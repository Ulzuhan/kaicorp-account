package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	clienteViejo = "11111111-aaaa-4000-8000-000000000001"
	clienteNuevo = "22222222-bbbb-4000-8000-000000000002"
	personaUno   = "00000000-0000-4000-8000-000000000001"
	personaDos   = "00000000-0000-4000-8000-000000000002"
)

// Sólo una instancia PostgreSQL desechable: crea bases temporales propias y
// ejecuta el bootstrap real. No apunta a la instancia de despliegue.
func storeVinculos(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("ACCOUNT_BINDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCOUNT_BINDING_TEST_DATABASE_URL no configurada")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	nombre := fmt.Sprintf("account_binding_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "create database "+pgx.Identifier{nombre}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "drop database "+pgx.Identifier{nombre}.Sanitize()+" with (force)")
		_ = admin.Close(context.Background())
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = nombre
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	_, err = db.Exec(ctx, `do $$ begin
		if not exists(select 1 from pg_roles where rolname='supabase_auth_admin') then create role supabase_auth_admin; end if;
		if not exists(select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
		if not exists(select 1 from pg_roles where rolname='anon') then create role anon; end if;
	end $$;
	create schema auth;
	create table auth.users(id uuid primary key);
	create table auth.sessions(user_id uuid);
	create table auth.oauth_clients(id uuid primary key);
	create table auth.oauth_authorizations(client_id uuid);
	create table auth.oauth_consents(user_id uuid, client_id uuid, revoked_at timestamptz, primary key(user_id,client_id));
	grant usage on schema auth to supabase_auth_admin;
	grant select, insert, update on auth.oauth_consents to supabase_auth_admin;`)
	if err != nil {
		t.Fatal(err)
	}
	psqlDSN, err := url.Parse(dsn)
	if err != nil || (psqlDSN.Scheme != "postgres" && psqlDSN.Scheme != "postgresql") {
		t.Fatal("ACCOUNT_BINDING_TEST_DATABASE_URL debe ser una URL postgres")
	}
	psqlDSN.Path = "/" + nombre
	cmd := exec.CommandContext(ctx, "psql", "-X", "-q", "-d", psqlDSN.String(),
		"-v", "account_password=binding-test-only",
		"-v", "account_migration_password=binding-migrate-test-only",
		"-f", "../../db/bootstrap.sql")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v: %s", err, out)
	}
	migrationDSN := *psqlDSN
	migrationDSN.User = url.UserPassword("account_migrator", "binding-migrate-test-only")
	migrator, err := Open(ctx, migrationDSN.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(migrator.Close)
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	appDSN := *psqlDSN
	appDSN.User = url.UserPassword("account", "binding-test-only")
	s, err := Open(ctx, appDSN.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.CheckMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `insert into account.grupos(nombre,titulo,cliente_id) values ('herramienta','Tool',$1),('otra','Other',null)`, clienteViejo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `insert into account.membresias(user_id,grupo,por) values ($1,'herramienta','test')`, personaUno); err != nil {
		t.Fatal(err)
	}
	return s, db
}

func grantVinculo(t *testing.T, db *pgxpool.Pool, user, client string) {
	t.Helper()
	if _, err := db.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values ($1,$2)`, user, client); err != nil {
		t.Fatal(err)
	}
}

func vivosVinculo(t *testing.T, db *pgxpool.Pool, client string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), `select count(*) from auth.oauth_consents where client_id=$1 and revoked_at is null`, client).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestVincularRetiraGrants(t *testing.T) {
	for _, nuevo := range []string{"", clienteNuevo} {
		t.Run(nuevo, func(t *testing.T) {
			s, db := storeVinculos(t)
			grantVinculo(t, db, personaUno, clienteViejo)
			// Grant histórico de un exmiembro, anterior a instalar la guarda.
			if _, err := db.Exec(t.Context(), `alter table auth.oauth_consents disable trigger account_valida_consentimiento`); err != nil {
				t.Fatal(err)
			}
			grantVinculo(t, db, personaDos, clienteViejo) // también un exmiembro
			if _, err := db.Exec(t.Context(), `alter table auth.oauth_consents enable trigger account_valida_consentimiento`); err != nil {
				t.Fatal(err)
			}
			grantVinculo(t, db, personaUno, clienteNuevo)
			if err := s.VincularCliente(t.Context(), "herramienta", nuevo); err != nil {
				t.Fatal(err)
			}
			if err := s.Revocar(t.Context(), personaUno, "herramienta"); err != nil {
				t.Fatal(err)
			}
			nuevos := 1 // El cliente ajeno conserva su grant.
			if nuevo == clienteNuevo {
				nuevos = 0
			} // Revocar también quita el grant actual.
			if vivosVinculo(t, db, clienteViejo) != 0 || vivosVinculo(t, db, clienteNuevo) != nuevos {
				t.Fatal("retirar el vínculo y revocar deben quitar los grants correspondientes")
			}
		})
	}
}

func TestVincularMismaIdentidadYRollback(t *testing.T) {
	s, db := storeVinculos(t)
	grantVinculo(t, db, personaUno, clienteViejo)
	if err := s.VincularCliente(t.Context(), "herramienta", "{"+strings.ToUpper(clienteViejo)+"}"); err != nil {
		t.Fatal(err)
	}
	if vivosVinculo(t, db, clienteViejo) != 1 {
		t.Fatal("la misma identidad UUID conserva el grant")
	}
	if err := s.VincularCliente(t.Context(), "otra", strings.ReplaceAll(clienteViejo, "-", "")); err == nil {
		t.Fatal("una grafía alternativa no puede duplicar el vínculo")
	}
	if err := s.VincularCliente(t.Context(), "otra", clienteNuevo); err != nil {
		t.Fatal(err)
	}
	for _, caso := range []struct{ grupo, client string }{{"herramienta", clienteNuevo}, {"herramienta", "invalid"}, {"ausente", ""}} {
		if err := s.VincularCliente(t.Context(), caso.grupo, caso.client); err == nil {
			t.Fatal("tenía que fallar", caso)
		}
		g, err := s.Grupo(t.Context(), "herramienta")
		if err != nil || g.ClienteID != clienteViejo || vivosVinculo(t, db, clienteViejo) != 1 {
			t.Fatal("un error debe preservar vínculo y grants", g, err)
		}
	}
	if _, err := db.Exec(t.Context(), `revoke update(revoked_at) on auth.oauth_consents from account`); err != nil {
		t.Fatal(err)
	}
	if err := s.VincularCliente(t.Context(), "herramienta", ""); err == nil {
		t.Fatal("sin permiso de revocación no debe descartar la identidad")
	}
	g, err := s.Grupo(t.Context(), "herramienta")
	if err != nil || g.ClienteID != clienteViejo || vivosVinculo(t, db, clienteViejo) != 1 {
		t.Fatal("el fallo de revocación debe preservar el estado", g, err)
	}
	if _, err := db.Exec(t.Context(), `grant update(revoked_at) on auth.oauth_consents to account`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `alter table auth.oauth_consents disable trigger account_valida_grants`); err != nil {
		t.Fatal(err)
	}
	if err := s.VincularCliente(t.Context(), "herramienta", ""); err == nil || vivosVinculo(t, db, clienteViejo) != 1 {
		t.Fatal("sin bootstrap debe fallar sin cambios", err)
	}
}

func TestVincularRechazaGrantTardio(t *testing.T) {
	s, db := storeVinculos(t)
	grantVinculo(t, db, personaUno, clienteViejo)
	if err := s.VincularCliente(t.Context(), "herramienta", ""); err != nil {
		t.Fatal(err)
	}
	provider, err := db.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Release()
	if _, err := provider.Exec(t.Context(), "set role supabase_auth_admin"); err != nil {
		t.Fatal(err)
	}
	defer provider.Exec(context.Background(), "reset role")
	for _, sql := range []string{
		`insert into auth.oauth_consents(user_id,client_id) values ('` + personaDos + `','` + clienteViejo + `')`,
		`update auth.oauth_consents set revoked_at=null where client_id='` + clienteViejo + `'`,
		`insert into auth.oauth_consents(user_id,client_id) values ('` + personaUno + `','` + clienteViejo + `') on conflict(user_id,client_id) do update set revoked_at=null`,
	} {
		_, err := provider.Exec(t.Context(), sql)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("tenía que rechazar el grant tardío: %v", err)
		}
	}
	// Si C se mueve a otro grupo, no hereda los miembros del grupo antiguo.
	if err := s.VincularCliente(t.Context(), "otra", clienteViejo); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exec(t.Context(), `update auth.oauth_consents set revoked_at=null where client_id=$1`, clienteViejo); err == nil {
		t.Fatal("un miembro del grupo anterior no pertenece al nuevo")
	}
	if err := s.Conceder(t.Context(), personaUno, "otra", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exec(t.Context(), `update auth.oauth_consents set revoked_at=null where user_id=$1 and client_id=$2`, personaUno, clienteViejo); err != nil {
		t.Fatal("el miembro actual puede autorizar", err)
	}
	if err := s.RevocarGrants(t.Context(), personaUno, clienteViejo); err != nil {
		t.Fatal("la revocación sigue permitida", err)
	}
	grantVinculo(t, db, personaDos, clienteNuevo) // un cliente ajeno no se intercepta
}

func TestVincularEsperaEscrituraProveedor(t *testing.T) {
	s, db := storeVinculos(t)
	tx, err := db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values ($1,$2)`, personaUno, clienteViejo); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := s.VincularCliente(ctx, "herramienta", ""); err == nil {
		t.Fatal("no puede retirar el vínculo antes del commit del proveedor")
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.VincularCliente(t.Context(), "herramienta", ""); err != nil {
		t.Fatal(err)
	}
	if vivosVinculo(t, db, clienteViejo) != 0 {
		t.Fatal("la escritura en vuelo debe quedar revocada")
	}
}

func TestVincularSnapshotAntiguo(t *testing.T) {
	s, db := storeVinculos(t)
	tx, err := db.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var n int
	if err := tx.QueryRow(t.Context(), `select count(*) from account.grupos`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := s.VincularCliente(t.Context(), "herramienta", ""); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values ($1,$2)`, personaUno, clienteViejo)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "40001" {
		t.Fatalf("un snapshot anterior al cambio debe abortar: %v", err)
	}
}

func TestVincularMigracionUUID(t *testing.T) {
	for _, valor := range []string{"invalid", strings.ToUpper(clienteViejo)} {
		t.Run(valor, func(t *testing.T) {
			_, db := storeVinculos(t)
			if _, err := db.Exec(t.Context(), `alter table account.grupos alter column cliente_id type text using cliente_id::text;
				drop table account.clientes_anteriores, account.estado_vinculos;`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(t.Context(), `update account.grupos set cliente_id=$1 where nombre='otra'`, valor); err != nil {
				t.Fatal(err)
			}
			sql, err := migraciones.ReadFile("migrations/0003_vinculos_grants.sql")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), string(sql)); err == nil {
				t.Fatal("la migración no puede aceptar UUID inválidos ni duplicados")
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			var actual string
			if err := db.QueryRow(t.Context(), `select cliente_id from account.grupos where nombre='otra'`).Scan(&actual); err != nil || actual != valor {
				t.Fatal("el fallo de migración no debe reinterpretar el valor", actual, err)
			}
		})
	}
}
