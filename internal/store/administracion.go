package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const salAutoridadAdministrativa int64 = 730021

var (
	// ErrAdministradorRevocado indica que la persona ya no administra o que la
	// orden pertenece a una generación anterior a una revocación.
	ErrAdministradorRevocado = errors.New("autoridad administrativa revocada")
	// ErrObjetivoNoBloqueado impide ampliar una orden después de haber fijado
	// el orden canónico de sus bloqueos.
	ErrObjetivoNoBloqueado = errors.New("objetivo administrativo no bloqueado")
	// ErrAutoconcesionAdmin es defensa en profundidad contra conservar o
	// recuperar administración mediante una concesión propia.
	ErrAutoconcesionAdmin = errors.New("no se puede conceder administración a uno mismo")
)

// bloqueoAutoridad conserva bloqueos de sesión de PostgreSQL en una conexión
// exclusiva. Es deliberado que abarque llamadas remotas: o el efecto termina
// antes de una revocación, o la revocación gana y la orden relee ya sin poder.
type bloqueoAutoridad struct {
	conn      *pgxpool.Conn
	objetivos map[string]bool
	invalidos map[string]bool
	unaVez    sync.Once
}

func (s *Store) bloquearAutoridad(ctx context.Context, ids ...string) (*bloqueoAutoridad, error) {
	pool := s.autoridadPool
	if pool == nil {
		// Compatibilidad para stores mínimos construidos por pruebas unitarias.
		pool = s.pool
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	b := &bloqueoAutoridad{conn: conn, objetivos: map[string]bool{}, invalidos: map[string]bool{}}
	fallar := func(err error) (*bloqueoAutoridad, error) {
		b.cerrar()
		return nil, err
	}
	for _, id := range ids {
		var canonico string
		if err := conn.QueryRow(ctx, `select $1::uuid::text`, id).Scan(&canonico); err != nil {
			// Un objetivo inválido no representa una identidad que pueda correr
			// una carrera. Se conserva para que el sink produzca su error normal.
			b.invalidos[id] = true
			continue
		}
		b.objetivos[canonico] = true
	}
	orden := make([]string, 0, len(b.objetivos))
	for id := range b.objetivos {
		orden = append(orden, id)
	}
	sort.Strings(orden)
	for _, id := range orden {
		if _, err := conn.Exec(ctx, `select pg_advisory_lock(hashtextextended($1::uuid::text,$2))`, id, salAutoridadAdministrativa); err != nil {
			return fallar(err)
		}
	}
	return b, nil
}

func (b *bloqueoAutoridad) cubre(ctx context.Context, id string) bool {
	if b.invalidos[id] {
		return true
	}
	var canonico string
	if err := b.conn.QueryRow(ctx, `select $1::uuid::text`, id).Scan(&canonico); err != nil {
		return false
	}
	return b.objetivos[canonico]
}

func (b *bloqueoAutoridad) canonico(ctx context.Context, id string) (string, error) {
	var canonico string
	err := b.conn.QueryRow(ctx, `select $1::uuid::text`, id).Scan(&canonico)
	return canonico, err
}

func (b *bloqueoAutoridad) cerrar() {
	b.unaVez.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := b.conn.Exec(ctx, `select pg_advisory_unlock_all()`); err != nil {
			conn := b.conn.Hijack()
			_ = conn.Close(ctx)
			return
		}
		b.conn.Release()
	})
}

// AutoridadAdmin es una orden administrativa linealizable. Los objetivos se
// fijan al abrirla para que todas las operaciones tomen actor y destinos en el
// mismo orden y no puedan formar ciclos A→B/B→A.
type AutoridadAdmin struct {
	store       *Store
	bloqueo     *bloqueoAutoridad
	actorID     string
	grupoAdmin  string
	generacion  int64
	actualizada time.Time
}

// AutorizarAdmin abre una orden nueva y captura su generación actual.
func (s *Store) AutorizarAdmin(ctx context.Context, actorID, grupoAdmin string, objetivos ...string) (*AutoridadAdmin, error) {
	return s.autorizarAdmin(ctx, actorID, grupoAdmin, nil, objetivos...)
}

// AutorizarAdminEnGeneracion reanuda una segunda fase sin permitir que una
// revocación y concesión intermedias rejuvenezcan la orden original.
func (s *Store) AutorizarAdminEnGeneracion(ctx context.Context, actorID, grupoAdmin string, generacion int64, objetivos ...string) (*AutoridadAdmin, error) {
	return s.autorizarAdmin(ctx, actorID, grupoAdmin, &generacion, objetivos...)
}

func (s *Store) autorizarAdmin(ctx context.Context, actorID, grupoAdmin string, esperada *int64, objetivos ...string) (*AutoridadAdmin, error) {
	ids := append([]string{actorID}, objetivos...)
	b, err := s.bloquearAutoridad(ctx, ids...)
	if err != nil {
		return nil, err
	}
	actorCanonico, err := b.canonico(ctx, actorID)
	if err != nil {
		b.cerrar()
		return nil, err
	}
	a := &AutoridadAdmin{store: s, bloqueo: b, actorID: actorCanonico, grupoAdmin: grupoAdmin}
	var miembro bool
	if err := b.conn.QueryRow(ctx, `select
		exists(select 1 from account.membresias where user_id=$1 and grupo=$2),
		coalesce((select generacion from account.autoridad_administrativa where user_id=$1),0),
		coalesce((select actualizada from account.autoridad_administrativa where user_id=$1),'epoch')`,
		actorCanonico, grupoAdmin).Scan(&miembro, &a.generacion, &a.actualizada); err != nil {
		b.cerrar()
		return nil, err
	}
	if !miembro || (esperada != nil && a.generacion != *esperada) {
		b.cerrar()
		return nil, ErrAdministradorRevocado
	}
	return a, nil
}

// Cerrar abandona la orden y libera todos sus bloqueos. Es idempotente.
func (a *AutoridadAdmin) Cerrar() { a.bloqueo.cerrar() }

// Generacion liga una segunda fase a la autoridad con la que empezó.
func (a *AutoridadAdmin) Generacion() int64 { return a.generacion }

// Actualizada permite rechazar una sesión nacida antes de la última
// revocación incluso si una limpieza física falló y el rol se concedió otra vez.
func (a *AutoridadAdmin) Actualizada() time.Time { return a.actualizada }

// Verificar relee membresía y generación bajo el bloqueo inmediatamente
// antes de cada efecto local o remoto.
func (a *AutoridadAdmin) Verificar(ctx context.Context) error {
	var ok bool
	if err := a.bloqueo.conn.QueryRow(ctx, `select exists(
		select 1 from account.membresias m
		left join account.autoridad_administrativa aa on aa.user_id=m.user_id
		where m.user_id=$1 and m.grupo=$2 and coalesce(aa.generacion,0)=$3)`,
		a.actorID, a.grupoAdmin, a.generacion).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrAdministradorRevocado
	}
	return nil
}

func (a *AutoridadAdmin) verificarObjetivo(ctx context.Context, userID string) error {
	if !a.bloqueo.cubre(ctx, userID) {
		return ErrObjetivoNoBloqueado
	}
	return a.Verificar(ctx)
}

// VerificarEfecto exige la relectura final antes de una llamada remota cuyo
// objetivo ya forma parte de la orden.
func (a *AutoridadAdmin) VerificarEfecto(ctx context.Context, userID string) error {
	return a.verificarObjetivo(ctx, userID)
}

// EsActor compara identidades UUID normalizadas; las representaciones con
// llaves o mayúsculas no eluden las defensas de autoconcesión/autorrevocación.
func (a *AutoridadAdmin) EsActor(ctx context.Context, userID string) bool {
	canonico, err := a.bloqueo.canonico(ctx, userID)
	return err == nil && canonico == a.actorID
}

// Conceder aplica la escritura sólo tras reautorizar al actor. La prohibición
// de autoconcesión vive también aquí, no sólo en el formulario.
func (a *AutoridadAdmin) Conceder(ctx context.Context, userID, grupo, por string) error {
	if a.EsActor(ctx, userID) && grupo == a.grupoAdmin {
		return ErrAutoconcesionAdmin
	}
	if err := a.verificarObjetivo(ctx, userID); err != nil {
		return err
	}
	return a.store.Conceder(ctx, userID, grupo, por)
}

// Revocar conserva el bloqueo del objetivo hasta haber invalidado también sus
// sesiones cuando se retira la administración.
func (a *AutoridadAdmin) Revocar(ctx context.Context, userID, grupo string) error {
	if err := a.verificarObjetivo(ctx, userID); err != nil {
		return err
	}
	if err := a.store.revocarBajoAutoridad(ctx, userID, grupo, grupo == a.grupoAdmin); err != nil {
		return err
	}
	if grupo == a.grupoAdmin {
		return a.store.revocarSesionesBajoAutoridad(ctx, userID)
	}
	return nil
}

// RevocarAdministracion es la frontera explícita para la CLI de confianza:
// no tiene un actor web, pero conserva sin huecos el mismo bloqueo, generación
// y cierre de sesiones que la operación actor-aware.
func (s *Store) RevocarAdministracion(ctx context.Context, userID, grupoAdmin string) error {
	b, err := s.bloquearAutoridad(ctx, userID)
	if err != nil {
		return err
	}
	defer b.cerrar()
	if err := s.revocarBajoAutoridad(ctx, userID, grupoAdmin, true); err != nil {
		return err
	}
	return s.revocarSesionesBajoAutoridad(ctx, userID)
}

// ResolverSolicitud conserva actor y persona afectada bajo la misma orden.
func (a *AutoridadAdmin) ResolverSolicitud(ctx context.Context, userID, id, estado, por string) error {
	if err := a.verificarObjetivo(ctx, userID); err != nil {
		return err
	}
	return a.store.ResolverSolicitud(ctx, id, estado, por)
}

func (a *AutoridadAdmin) VincularCliente(ctx context.Context, grupo, clienteID string) error {
	if err := a.Verificar(ctx); err != nil {
		return err
	}
	return a.store.VincularCliente(ctx, grupo, clienteID)
}

func (a *AutoridadAdmin) RevocarSesiones(ctx context.Context, userID string) error {
	if err := a.verificarObjetivo(ctx, userID); err != nil {
		return err
	}
	// Cerrar o bloquear una cuenta también derrota una petición privilegiada
	// que ya hubiera cargado su sesión y estuviera esperando esta frontera.
	if err := avanzarAutoridadAdministrativa(ctx, a.bloqueo.conn, userID); err != nil {
		return err
	}
	return a.store.revocarSesionesBajoAutoridad(ctx, userID)
}

func avanzarAutoridadAdministrativa(ctx context.Context, q ejecutorSolicitud, userID string) error {
	_, err := q.Exec(ctx, `insert into account.autoridad_administrativa(user_id,generacion,actualizada)
		values ($1,1,now()) on conflict (user_id) do update
		set generacion=account.autoridad_administrativa.generacion+1, actualizada=now()`, userID)
	if err != nil {
		return fmt.Errorf("invalidar operaciones administrativas: %w", err)
	}
	return nil
}
