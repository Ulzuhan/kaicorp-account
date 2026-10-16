package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

const personaSoloRol = "00000000-0000-4000-8000-000000000003"

func esperarBloqueoMembresia(t *testing.T, db *pgxpool.Pool, fragmento string) {
	t.Helper()
	limite := time.Now().Add(5 * time.Second)
	for time.Now().Before(limite) {
		var bloqueada bool
		if err := db.QueryRow(t.Context(), `select exists(select 1 from pg_stat_activity
			where datname=current_database() and wait_event_type='Lock' and position($1 in query)>0)`, fragmento).Scan(&bloqueada); err != nil {
			t.Fatal(err)
		}
		if bloqueada {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no se observó el bloqueo de %q", fragmento)
}

func bloquearSolicitudAutomatica(t *testing.T, db *pgxpool.Pool) func() {
	t.Helper()
	conn, err := db.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), `select pg_advisory_lock(730018)`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `create function account.espera_solicitud_test() returns trigger language plpgsql as $$
begin
  if new.grupo='herramienta' then perform pg_advisory_xact_lock(730018); end if;
  return new;
end $$;
create trigger espera_solicitud_test before insert on account.solicitudes
  for each row execute function account.espera_solicitud_test()`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	var once sync.Once
	liberar := func() {
		once.Do(func() {
			_, _ = conn.Exec(context.Background(), `select pg_advisory_unlock(730018)`)
			conn.Release()
		})
	}
	t.Cleanup(liberar)
	return liberar
}

func bloquearNuevaMembresia(t *testing.T, db *pgxpool.Pool) func() {
	t.Helper()
	conn, err := db.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), `select pg_advisory_lock(730019)`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `create function account.espera_membresia_test() returns trigger language plpgsql as $$
begin
  if new.grupo='otra' then perform pg_advisory_xact_lock(730019); end if;
  return new;
end $$;
create trigger espera_membresia_test before insert on account.membresias
  for each row execute function account.espera_membresia_test()`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	var once sync.Once
	liberar := func() {
		once.Do(func() {
			_, _ = conn.Exec(context.Background(), `select pg_advisory_unlock(730019)`)
			conn.Release()
		})
	}
	t.Cleanup(liberar)
	return liberar
}

func TestSolicitarAccesoMantienePoliticaYAtomicidad(t *testing.T) {
	s, db := storeVinculos(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo,solicitable) values ('rol','Role',false);
create function account.prohibe_reinsertar_test() returns trigger language plpgsql as $$
begin
  if new.grupo='herramienta' then raise exception 'no debe reinsertar'; end if;
  return new;
end $$;
create trigger prohibe_reinsertar_test before insert on account.membresias
  for each row execute function account.prohibe_reinsertar_test()`); err != nil {
		t.Fatal(err)
	}

	if g, d, err := s.SolicitarAcceso(t.Context(), personaUno, "herramienta"); err != nil || g.Nombre != "herramienta" || d != policy.Automatica {
		t.Fatalf("repetir acceso existente: grupo=%v decisión=%v error=%v", g, d, err)
	}
	if _, d, err := s.SolicitarAcceso(t.Context(), personaUno, "otra"); err != nil || d != policy.Automatica {
		t.Fatalf("segunda herramienta: decisión=%v error=%v", d, err)
	}
	if ok, err := s.EsMiembro(t.Context(), personaUno, "otra"); err != nil || !ok {
		t.Fatalf("la segunda herramienta no quedó concedida: %v %v", ok, err)
	}
	if _, d, err := s.SolicitarAcceso(t.Context(), personaDos, "herramienta"); err != nil || d != policy.Pendiente {
		t.Fatalf("primera herramienta: decisión=%v error=%v", d, err)
	}
	if ok, err := s.EsMiembro(t.Context(), personaDos, "herramienta"); err != nil || ok {
		t.Fatalf("la primera herramienta se concedió sin aprobación: %v %v", ok, err)
	}
	if err := s.Conceder(t.Context(), personaSoloRol, "rol", "test"); err != nil {
		t.Fatal(err)
	}
	if _, d, err := s.SolicitarAcceso(t.Context(), personaSoloRol, "otra"); err != nil || d != policy.Pendiente {
		t.Fatalf("un rol contó como aprobación: decisión=%v error=%v", d, err)
	}
	if _, d, err := s.SolicitarAcceso(t.Context(), personaUno, "rol"); err != nil || d != policy.Rechazada {
		t.Fatalf("un rol no solicitable se pudo pedir: decisión=%v error=%v", d, err)
	}
	if _, _, err := s.SolicitarAcceso(t.Context(), personaUno, "inexistente"); !errors.Is(err, ErrNoExiste) {
		t.Fatalf("grupo inexistente: %v", err)
	}

	var automaticas, pendientes int
	if err := db.QueryRow(t.Context(), `select
		count(*) filter(where estado='automatica'), count(*) filter(where estado='pendiente')
		from account.solicitudes`).Scan(&automaticas, &pendientes); err != nil {
		t.Fatal(err)
	}
	if automaticas != 2 || pendientes != 2 {
		t.Fatalf("registro de decisiones: automáticas=%d pendientes=%d", automaticas, pendientes)
	}
}

func TestSolicitarAccesoRevierteMembresiaSiNoRegistraDecision(t *testing.T) {
	s, db := storeVinculos(t)
	if _, err := db.Exec(t.Context(), `create function account.falla_solicitud_test() returns trigger language plpgsql as $$
begin
  if new.grupo='otra' then raise exception 'fallo de registro'; end if;
  return new;
end $$;
create trigger falla_solicitud_test before insert on account.solicitudes
  for each row execute function account.falla_solicitud_test()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SolicitarAcceso(t.Context(), personaUno, "otra"); err == nil {
		t.Fatal("la solicitud debía fallar")
	}
	if ok, err := s.EsMiembro(t.Context(), personaUno, "otra"); err != nil || ok {
		t.Fatalf("la membresía sobrevivió al rollback: %v %v", ok, err)
	}
}

func TestSolicitudYRevocacionCompartenOrdenCanonico(t *testing.T) {
	t.Run("revocación primero", func(t *testing.T) {
		s, db := storeVinculos(t)
		tx, err := db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `select pg_advisory_xact_lock(hashtextextended($1::uuid::text,730017))`, "{"+strings.ToUpper(personaUno)+"}"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `delete from account.membresias where user_id=$1 and grupo='herramienta'`, personaUno); err != nil {
			t.Fatal(err)
		}
		type resultado struct {
			decision policy.Decision
			err      error
		}
		fin := make(chan resultado, 1)
		go func() {
			_, d, err := s.SolicitarAcceso(t.Context(), personaUno, "herramienta")
			fin <- resultado{d, err}
		}()
		select {
		case r := <-fin:
			t.Fatalf("la solicitud no esperó la revocación alias: %+v", r)
		case <-time.After(100 * time.Millisecond):
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		r := <-fin
		if r.err != nil || r.decision != policy.Pendiente {
			t.Fatalf("la solicitud no reevaluó después de revocar: %+v", r)
		}
		if ok, err := s.EsMiembro(t.Context(), personaUno, "herramienta"); err != nil || ok {
			t.Fatalf("la solicitud restauró la membresía: %v %v", ok, err)
		}
	})

	t.Run("solicitud primero", func(t *testing.T) {
		s, db := storeVinculos(t)
		liberar := bloquearSolicitudAutomatica(t, db)
		type resultado struct {
			decision policy.Decision
			err      error
		}
		solicitud := make(chan resultado, 1)
		go func() {
			_, d, err := s.SolicitarAcceso(t.Context(), personaUno, "herramienta")
			solicitud <- resultado{d, err}
		}()
		esperarBloqueoMembresia(t, db, "insert into account.solicitudes")
		revocacion := make(chan error, 1)
		go func() { revocacion <- s.Revocar(t.Context(), personaUno, "herramienta") }()
		select {
		case err := <-revocacion:
			t.Fatalf("la revocación adelantó a la solicitud en vuelo: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		liberar()
		r := <-solicitud
		if r.err != nil || r.decision != policy.Automatica {
			t.Fatalf("solicitud automática: %+v", r)
		}
		if err := <-revocacion; err != nil {
			t.Fatal(err)
		}
		if ok, err := s.EsMiembro(t.Context(), personaUno, "herramienta"); err != nil || ok {
			t.Fatalf("la membresía sobrevivió a la revocación posterior: %v %v", ok, err)
		}
	})
}

func TestRevocarTodoNoOmiteConcesionAutomaticaEnVuelo(t *testing.T) {
	s, db := storeVinculos(t)
	grantVinculo(t, db, personaUno, clienteViejo)
	if _, err := db.Exec(t.Context(), `insert into auth.sessions(user_id) values ($1)`, personaUno); err != nil {
		t.Fatal(err)
	}
	if err := s.CrearSesion(t.Context(), sesionParaCorte("membresia-revocar-todo", personaUno, time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	liberar := bloquearNuevaMembresia(t, db)
	type resultado struct {
		decision policy.Decision
		err      error
	}
	solicitud := make(chan resultado, 1)
	go func() {
		_, d, err := s.SolicitarAcceso(t.Context(), personaUno, "otra")
		solicitud <- resultado{d, err}
	}()
	esperarBloqueoMembresia(t, db, "insert into account.membresias")
	type revocacionResultado struct {
		grupos []string
		err    error
	}
	revocacion := make(chan revocacionResultado, 1)
	go func() {
		grupos, err := s.RevocarTodo(t.Context(), personaUno)
		revocacion <- revocacionResultado{grupos, err}
	}()
	select {
	case r := <-revocacion:
		t.Fatalf("revocar todo tomó una instantánea antes de la solicitud: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	liberar()
	if r := <-solicitud; r.err != nil || r.decision != policy.Automatica {
		t.Fatalf("solicitud en vuelo: %+v", r)
	}
	r := <-revocacion
	if r.err != nil || !reflect.DeepEqual(r.grupos, []string{"herramienta", "otra"}) {
		t.Fatalf("revocación: grupos=%v error=%v", r.grupos, r.err)
	}
	if ms, err := s.MembresiasDe(t.Context(), personaUno); err != nil || len(ms) != 0 {
		t.Fatalf("membresías supervivientes: %v %v", ms, err)
	}
	if sesiones, err := s.SesionesDe(t.Context(), personaUno); err != nil || len(sesiones) != 0 {
		t.Fatalf("sesiones de app supervivientes: %v %v", sesiones, err)
	}
	var sesionesProveedor int
	if err := db.QueryRow(t.Context(), `select count(*) from auth.sessions where user_id=$1`, personaUno).Scan(&sesionesProveedor); err != nil || sesionesProveedor != 0 {
		t.Fatalf("sesiones del proveedor supervivientes: %d %v", sesionesProveedor, err)
	}
	if vivos := vivosVinculo(t, db, clienteViejo); vivos != 0 {
		t.Fatalf("grants supervivientes: %d", vivos)
	}
}
