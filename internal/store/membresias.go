package store

import (
	"context"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// transaccionMembresias ordena, para una persona y en todas las réplicas, las
// decisiones automáticas, concesiones y revocaciones. El cast a uuid antes de
// calcular la clave hace que las representaciones equivalentes tomen el mismo
// bloqueo. Read Committed obliga a que la lectura posterior a la espera vea lo
// que confirmó la transacción anterior.
func (s *Store) transaccionMembresias(ctx context.Context, userID string) (pgx.Tx, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1::uuid::text, 730017))`, userID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

type ejecutorSolicitud interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func crearSolicitud(ctx context.Context, q ejecutorSolicitud, userID, grupo, estado, por string) (bool, error) {
	var resuelta *time.Time
	var p *string
	if estado != "pendiente" {
		now := time.Now()
		resuelta = &now
		if por != "" {
			p = &por
		}
	}
	tag, err := q.Exec(ctx, `insert into account.solicitudes(user_id, grupo, estado, resuelta, por)
		values ($1,$2,$3,$4,$5)
		on conflict (user_id, grupo) where estado='pendiente' do nothing`, userID, grupo, estado, resuelta, p)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// SolicitarAcceso vuelve indivisible la autorización automática: toma el
// bloqueo antes de leer las membresías y lo conserva hasta registrar la
// decisión y, si corresponde, la nueva membresía. Repetir un acceso que ya se
// tiene se registra, pero no ejecuta otro INSERT que pueda resucitarlo.
func (s *Store) SolicitarAcceso(ctx context.Context, userID, grupo string) (*Grupo, policy.Decision, error) {
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return nil, policy.Rechazada, err
	}
	defer tx.Rollback(ctx)
	g, err := scanGrupo(tx.QueryRow(ctx, `select `+grupoCols+` from account.grupos where nombre=$1`, grupo))
	if err != nil {
		return nil, policy.Rechazada, err
	}
	rows, err := tx.Query(ctx, `select m.grupo, g.solicitable from account.membresias m
		join account.grupos g on g.nombre=m.grupo where m.user_id=$1`, userID)
	if err != nil {
		return nil, policy.Rechazada, err
	}
	var membresias []string
	herramientas := map[string]bool{}
	for rows.Next() {
		var nombre string
		var solicitable bool
		if err := rows.Scan(&nombre, &solicitable); err != nil {
			rows.Close()
			return nil, policy.Rechazada, err
		}
		membresias = append(membresias, nombre)
		herramientas[nombre] = solicitable
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, policy.Rechazada, err
	}

	decision := policy.Solicitar(g.Nombre, g.Solicitable, membresias, herramientas)
	por := ""
	if decision == policy.Automatica {
		if !policy.PuedeEntrar(g.Nombre, membresias) {
			if _, err := tx.Exec(ctx, `insert into account.membresias(user_id, grupo, por) values ($1,$2,'automática')
				on conflict (user_id, grupo) do nothing`, userID, g.Nombre); err != nil {
				return nil, policy.Rechazada, err
			}
		}
		por = "automática"
	}
	if decision != policy.Rechazada {
		if _, err := crearSolicitud(ctx, tx, userID, g.Nombre, decision.String(), por); err != nil {
			return nil, policy.Rechazada, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, policy.Rechazada, err
	}
	return g, decision, nil
}

// RevocarTodo toma el bloqueo antes de enumerar y lo conserva mientras borra
// todas las membresías y las dos clases de sesión. Los triggers de membresía
// revocan los grants OAuth dentro de esta misma transacción.
func (s *Store) RevocarTodo(ctx context.Context, userID string) ([]string, error) {
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `select grupo from account.membresias where user_id=$1 order by grupo`, userID)
	if err != nil {
		return nil, err
	}
	var grupos []string
	for rows.Next() {
		var grupo string
		if err := rows.Scan(&grupo); err != nil {
			rows.Close()
			return nil, err
		}
		grupos = append(grupos, grupo)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, q := range []string{
		`delete from account.membresias where user_id=$1`,
		`delete from auth.sessions where user_id=$1`,
		`delete from account.sesiones where user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return grupos, nil
}
