package store

import (
	"context"
	"errors"
	"fmt"
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
func (s *Store) SolicitarAcceso(ctx context.Context, userID, grupo, grupoAdmin string) (*Grupo, policy.Decision, error) {
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return nil, policy.Rechazada, err
	}
	defer tx.Rollback(ctx)
	// El bloqueo de la fila conserva la clasificación validada hasta que la
	// decisión y su posible membresía quedan confirmadas.
	g, err := scanGrupo(tx.QueryRow(ctx, `select `+grupoCols+` from account.grupos where nombre=$1 for share`, grupo))
	if err != nil {
		return nil, policy.Rechazada, err
	}
	// La defensa de aplicación no confía en `solicitable`: ni un rol corrupto
	// ni el nombre configurado para /admin entran jamás en autoservicio.
	if g.Tipo != TipoGrupoHerramienta || g.Nombre == grupoAdmin {
		return g, policy.Rechazada, nil
	}
	rows, err := tx.Query(ctx, `select m.grupo, g.tipo from account.membresias m
		join account.grupos g on g.nombre=m.grupo where m.user_id=$1`, userID)
	if err != nil {
		return nil, policy.Rechazada, err
	}
	var membresias []string
	herramientas := map[string]bool{}
	for rows.Next() {
		var nombre string
		var tipo TipoGrupo
		if err := rows.Scan(&nombre, &tipo); err != nil {
			rows.Close()
			return nil, policy.Rechazada, err
		}
		membresias = append(membresias, nombre)
		herramientas[nombre] = tipo == TipoGrupoHerramienta
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
// todas las membresías y aplica la misma frontera durable de sesiones que los
// cierres del panel. Los triggers revocan los grants OAuth en esta transacción.
func (s *Store) RevocarTodo(ctx context.Context, userID string) ([]string, error) {
	b, err := s.bloquearAutoridad(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer b.cerrar()
	errProveedor := s.CerrarSesionesGoTrue(ctx, userID)
	if errProveedor != nil {
		errProveedor = fmt.Errorf("cerrar sesiones del proveedor: %w", errProveedor)
	}
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return nil, errors.Join(errProveedor, err)
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
	espera, err := revocarSesionesLocalesTx(ctx, tx, userID)
	if err != nil {
		return nil, errors.Join(errProveedor, fmt.Errorf("cerrar sesiones locales: %w", err))
	}
	if err := avanzarAutoridadAdministrativa(ctx, tx, userID); err != nil {
		return nil, errors.Join(errProveedor, err)
	}
	if _, err := tx.Exec(ctx, `delete from account.membresias where user_id=$1`, userID); err != nil {
		return nil, errors.Join(errProveedor, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.Join(errProveedor, err)
	}
	if err := esperarEmisionPosterior(ctx, espera); err != nil {
		return nil, errors.Join(errProveedor, fmt.Errorf("esperar nueva emisión de sesión: %w", err))
	}
	return grupos, errProveedor
}
