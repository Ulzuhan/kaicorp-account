package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const administradorCarrera = "00000000-0000-4000-8000-000000000090"

func prepararAutoridadAdministrativa(t *testing.T) (*Store, string) {
	t.Helper()
	s, db := storeVinculos(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo,tipo,solicitable)
		values ('account-admin','Administration','rol',false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into account.membresias(user_id,grupo,por)
		values ($1,'account-admin','test')`, administradorCarrera); err != nil {
		t.Fatal(err)
	}
	return s, administradorCarrera
}

func TestAutoridadAdminReleeDespuesDeQueRevocacionGane(t *testing.T) {
	s, actor := prepararAutoridadAdministrativa(t)
	if ok, err := s.EsMiembro(t.Context(), actor, "account-admin"); err != nil || !ok {
		t.Fatalf("precondición de la lectura temprana: %v %v", ok, err)
	}

	// La revocación ya posee la frontera del actor. La orden representa una
	// petición que había pasado la lectura temprana de requiereAdmin.
	b, err := s.bloquearAutoridad(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() {
		a, err := s.AutorizarAdmin(t.Context(), actor, "account-admin", personaDos)
		if err == nil {
			defer a.Cerrar()
			err = a.Conceder(t.Context(), personaDos, "otra", "stale-admin")
		}
		fin <- err
	}()
	select {
	case err := <-fin:
		t.Fatalf("la orden no esperó el bloqueo de revocación: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := s.revocarBajoAutoridad(t.Context(), actor, "account-admin", true); err != nil {
		t.Fatal(err)
	}
	b.cerrar()
	if err := <-fin; !errors.Is(err, ErrAdministradorRevocado) {
		t.Fatalf("la orden antigua no fue rechazada: %v", err)
	}
	if ok, err := s.EsMiembro(t.Context(), personaDos, "otra"); err != nil || ok {
		t.Fatalf("la orden revocada concedió la membresía: %v %v", ok, err)
	}
}

func TestRevocacionEsPosteriorAOpcionQueYaPoseeLaFrontera(t *testing.T) {
	s, actor := prepararAutoridadAdministrativa(t)
	a, err := s.AutorizarAdmin(t.Context(), actor, "account-admin", personaDos)
	if err != nil {
		t.Fatal(err)
	}
	revocada := make(chan error, 1)
	go func() { revocada <- s.Revocar(t.Context(), actor, "account-admin") }()
	select {
	case err := <-revocada:
		t.Fatalf("la revocación adelantó a la orden que ya tenía la frontera: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := a.Conceder(t.Context(), personaDos, "otra", "admin"); err != nil {
		t.Fatal(err)
	}
	a.Cerrar()
	if err := <-revocada; err != nil {
		t.Fatal(err)
	}
	if ok, err := s.EsMiembro(t.Context(), actor, "account-admin"); err != nil || ok {
		t.Fatalf("la administración sobrevivió: %v %v", ok, err)
	}
	if ok, err := s.EsMiembro(t.Context(), personaDos, "otra"); err != nil || !ok {
		t.Fatalf("la orden anterior a la revocación no se linealizó: %v %v", ok, err)
	}
}

func TestGeneracionImpideRevivirOrdenYAutoconcederse(t *testing.T) {
	s, actor := prepararAutoridadAdministrativa(t)
	a, err := s.AutorizarAdmin(t.Context(), actor, "account-admin", actor)
	if err != nil {
		t.Fatal(err)
	}
	generacion := a.Generacion()
	alias := "{" + strings.ToUpper(actor) + "}"
	if err := a.Conceder(t.Context(), alias, "account-admin", "admin"); !errors.Is(err, ErrAutoconcesionAdmin) {
		t.Fatalf("la autoconcesión con UUID equivalente no fue rechazada: %v", err)
	}
	a.Cerrar()

	if err := s.RevocarAdministracion(t.Context(), actor, "account-admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Conceder(t.Context(), actor, "account-admin", "system"); err != nil {
		t.Fatal(err)
	}
	if antigua, err := s.AutorizarAdminEnGeneracion(t.Context(), actor, "account-admin", generacion, personaDos); !errors.Is(err, ErrAdministradorRevocado) {
		if antigua != nil {
			antigua.Cerrar()
		}
		t.Fatalf("revocar y volver a conceder revivió la orden: %v", err)
	}
}

func TestFronteraAdministrativaNoAgotaPoolDeTrabajo(t *testing.T) {
	base, actor := prepararAutoridadAdministrativa(t)

	// Un pool ordinario de una conexión reproduce el ciclo mínimo: la orden
	// conserva su conexión de bloqueo y Conceder necesita otra. Con pools
	// separados la escritura termina; si vuelven a compartirse, el contexto de
	// la prueba vence en lugar de quedar colgado indefinidamente.
	trabajoCfg := base.pool.Config()
	trabajoCfg.MaxConns = 1
	trabajoCfg.MinConns = 0
	trabajo, err := pgxpool.NewWithConfig(t.Context(), trabajoCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trabajo.Close)

	autoridadCfg := base.pool.Config()
	autoridadCfg.MaxConns = 1
	autoridadCfg.MinConns = 0
	autoridad, err := pgxpool.NewWithConfig(t.Context(), autoridadCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(autoridad.Close)

	s := &Store{pool: trabajo, autoridadPool: autoridad}
	a, err := s.AutorizarAdmin(t.Context(), actor, "account-admin", personaDos)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Cerrar()
	if err := a.Conceder(t.Context(), personaDos, "otra", "admin"); err != nil {
		t.Fatal(err)
	}
}
