package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const consentPersona = "00000000-0000-4000-8000-000000000041"
const consentCliente = "11111111-aaaa-4000-8000-000000000041"
const consentAutorizacion = "22222222-bbbb-4000-8000-000000000041"

func TestConsentimientoMigracionEsperaProveedor(t *testing.T) {
	st, migrator, db := baseConsentimientoConMigracion(t, false)
	p := proveedorConsentimiento(t, db)
	tx, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `update auth.oauth_authorizations set status='approved',authorization_code='before-upgrade' where authorization_id=$1`, consentAutorizacion); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() { fin <- migrator.Migrate(t.Context()) }()
	// La migración debe drenar las transacciones admitidas por el bootstrap.
	limite := time.Now().Add(5 * time.Second)
	bloqueada := false
	for time.Now().Before(limite) {
		select {
		case err := <-fin:
			t.Fatalf("la migración no esperó al proveedor: %v", err)
		default:
		}
		var n int
		if err := db.QueryRow(t.Context(), `select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and pid<>pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			bloqueada = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !bloqueada {
		t.Fatal("no se observó el bloqueo de migración")
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-fin; err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
		t.Fatal(err)
	}
	sinGrantsConsentimiento(t, db)
}

func TestConsentimientoRevocarSinMembresia(t *testing.T) {
	st, db := baseConsentimiento(t)
	p := proveedorConsentimiento(t, db)
	if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
		t.Fatal(err)
	}
	// Simula un grant histórico previo a instalar la remediación.
	if _, err := db.Exec(t.Context(), `alter table account.membresias disable trigger account_revoca_consentimiento;
 delete from account.membresias;
 alter table account.membresias enable trigger account_revoca_consentimiento;`); err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
		t.Fatal(err)
	}
	sinGrantsConsentimiento(t, db)
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
		t.Fatal("repetición", err)
	}
}

func TestConsentimientoDenegarSinMembresia(t *testing.T) {
	st, _ := baseConsentimiento(t)
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
		t.Fatal(err)
	}
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"redirect_url":"https://tool.example/callback?error=access_denied"}`)
	}))
	defer proveedor.Close()
	gt := gotrue.New(proveedor.URL, "anon-test", "")
	ses, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL}, st, gt, ses, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(url.Values{"authorization_id": {consentAutorizacion}, "action": {"deny"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{UserID: consentPersona}))
	w := httptest.NewRecorder()
	s.consentPOST(w, r)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=access_denied") {
		t.Fatal(w.Code, w.Body.String())
	}
}

// Sólo una instancia desechable con permiso para crear bases: cada prueba
// crea su propia base y aplica el bootstrap real, RLS y las migraciones.
func baseConsentimiento(t *testing.T) (*store.Store, *pgxpool.Pool) {
	st, _, db := baseConsentimientoConMigracion(t, true)
	return st, db
}

func baseConsentimientoConMigracion(t *testing.T, completa bool) (*store.Store, *store.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("ACCOUNT_CONSENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCOUNT_CONSENT_TEST_DATABASE_URL no configurada")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	nombre := fmt.Sprintf("account_consent_%d", time.Now().UnixNano())
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
 create table auth.oauth_authorizations(authorization_id uuid primary key, client_id uuid, user_id uuid,
   status text default 'pending', authorization_code text, expires_at timestamptz default now()+interval '1 hour');
 create table auth.oauth_consents(user_id uuid, client_id uuid, revoked_at timestamptz, primary key(user_id,client_id));
 alter table auth.oauth_consents enable row level security;
 alter table auth.oauth_authorizations enable row level security;
 grant usage on schema auth to supabase_auth_admin;
 grant select,insert,update on auth.oauth_consents,auth.oauth_authorizations to supabase_auth_admin;
 create policy provider_consents on auth.oauth_consents to supabase_auth_admin using(true) with check(true);
 create policy provider_authorizations on auth.oauth_authorizations to supabase_auth_admin using(true) with check(true);`)
	if err != nil {
		t.Fatal(err)
	}
	psqlURL, err := url.Parse(dsn)
	if err != nil || (psqlURL.Scheme != "postgres" && psqlURL.Scheme != "postgresql") {
		t.Fatal("se necesita una URL postgres")
	}
	psqlURL.Path = "/" + nombre
	cmd := exec.CommandContext(ctx, "psql", "-X", "-q", "-d", psqlURL.String(),
		"-v", "account_password=consent-test-only",
		"-v", "account_migration_password=consent-migrate-test-only",
		"-f", "../../db/bootstrap.sql")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v: %s", err, out)
	}
	migrationURL := *psqlURL
	migrationURL.User = url.UserPassword("account_migrator", "consent-migrate-test-only")
	migrator, err := store.Open(ctx, migrationURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(migrator.Close)
	appURL := *psqlURL
	appURL.User = url.UserPassword("account", "consent-test-only")
	st, err := store.Open(ctx, appURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if completa {
		if err := migrator.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	} else {
		app, err := pgx.Connect(ctx, migrationURL.String())
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(context.Background())
		if _, err := app.Exec(ctx, `create table account.schema_migrations(version text primary key, applied_at timestamptz default now())`); err != nil {
			t.Fatal(err)
		}
		anteriores, err := os.ReadDir("../store/migrations")
		if err != nil {
			t.Fatal(err)
		}
		for _, entrada := range anteriores {
			if !strings.HasSuffix(entrada.Name(), ".sql") || entrada.Name() >= "0004" {
				continue
			}
			sql, err := os.ReadFile("../store/migrations/" + entrada.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := app.Exec(ctx, string(sql)); err != nil {
				t.Fatal(err)
			}
			if _, err := app.Exec(ctx, `insert into account.schema_migrations(version) values($1)`, entrada.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(ctx, `insert into account.grupos(nombre,titulo,cliente_id) values ('herramienta','Tool',$1),('rol','Role',null);
 `, consentCliente); err != nil {
		t.Fatal(err)
	}
	if err := st.Conceder(ctx, consentPersona, "herramienta", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `insert into auth.oauth_authorizations(authorization_id,client_id,user_id) values($1,$2,$3)`,
		consentAutorizacion, consentCliente, consentPersona); err != nil {
		t.Fatal(err)
	}
	return st, migrator, db
}

func proveedorConsentimiento(t *testing.T, db *pgxpool.Pool) *pgx.Conn {
	t.Helper()
	c, err := pgx.ConnectConfig(t.Context(), db.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	if _, err := c.Exec(t.Context(), "set role supabase_auth_admin"); err != nil {
		t.Fatal(err)
	}
	return c
}

func errorConsentimiento(t *testing.T, err error, code string) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != code {
		t.Fatalf("quería SQLSTATE %s, recibió %v", code, err)
	}
}

func sinGrantsConsentimiento(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), `select count(*) from auth.oauth_consents where client_id=$1 and revoked_at is null`, consentCliente).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("quedan %d grants vivos", n)
	}
}

func esperaBloqueoConsentimiento(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	limite := time.Now().Add(5 * time.Second)
	for time.Now().Before(limite) {
		var n int
		if err := db.QueryRow(t.Context(), `select count(*) from pg_stat_activity
   where datname=current_database() and wait_event_type='Lock' and pid<>pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no se observó la espera del bloqueo")
}

// La consulta de membresía ya pasó; la escritura remota llega después de la
// revocación (también si terminó el contexto HTTP). No necesita grant previo.
func TestConsentimientoTardio(t *testing.T) {
	for _, previo := range []bool{false, true} {
		t.Run(fmt.Sprint(previo), func(t *testing.T) {
			st, db := baseConsentimiento(t)
			p := proveedorConsentimiento(t, db)
			if previo {
				if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
					t.Fatal(err)
				}
			}
			if ok, err := st.EsMiembro(t.Context(), consentPersona, "herramienta"); err != nil || !ok {
				t.Fatal("control previo", ok, err)
			}
			if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
				t.Fatal(err)
			}
			for _, sql := range []string{
				`insert into auth.oauth_consents(user_id,client_id) values($1,$2) on conflict(user_id,client_id) do update set revoked_at=null`,
				`insert into auth.oauth_consents(user_id,client_id) values($1,$2)`,
				`insert into auth.oauth_authorizations(authorization_id,client_id,user_id,status,authorization_code)
       values('33333333-cccc-4000-8000-000000000041',$2,$1,'approved','late-code')`,
			} {
				_, err := p.Exec(t.Context(), sql, consentPersona, consentCliente)
				errorConsentimiento(t, err, "42501")
			}
			if previo {
				_, err := p.Exec(t.Context(), `update auth.oauth_consents set revoked_at=null where user_id=$1 and client_id=$2`, consentPersona, consentCliente)
				errorConsentimiento(t, err, "42501")
			}
			// GET autoapprove sólo modifica la autorización, sin tocar el consentimiento.
			_, err := p.Exec(t.Context(), `update auth.oauth_authorizations set status='approved',authorization_code='late-code' where authorization_id=$1`, consentAutorizacion)
			errorConsentimiento(t, err, "42501")
			var estado string
			if err := db.QueryRow(t.Context(), `select status from auth.oauth_authorizations where authorization_id=$1`, consentAutorizacion).Scan(&estado); err != nil || estado != "pending" {
				t.Fatal("la aprobación rechazada debe conservar el estado pendiente", estado, err)
			}
			sinGrantsConsentimiento(t, db)
		})
	}
}

func TestConsentimientoAnteriorARevocacion(t *testing.T) {
	st, db := baseConsentimiento(t)
	p := proveedorConsentimiento(t, db)
	tx, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `update auth.oauth_authorizations set status='approved',authorization_code='early-code' where authorization_id=$1`, consentAutorizacion); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() { fin <- st.Revocar(t.Context(), consentPersona, "herramienta") }()
	esperaBloqueoConsentimiento(t, db)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-fin; err != nil {
		t.Fatal(err)
	}
	sinGrantsConsentimiento(t, db)
}

func TestConsentimientoEsperaRevocacion(t *testing.T) {
	st, db := baseConsentimiento(t)
	cfg := db.Config().ConnConfig.Copy()
	cfg.User = "account"
	app, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(context.Background())
	tx, err := app.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `delete from account.membresias where user_id=$1 and grupo='herramienta'`, consentPersona); err != nil {
		t.Fatal(err)
	}
	p := proveedorConsentimiento(t, db)
	fin := make(chan error, 1)
	go func() {
		_, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente)
		fin <- err
	}()
	esperaBloqueoConsentimiento(t, db)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	errorConsentimiento(t, <-fin, "42501")
	sinGrantsConsentimiento(t, db)
	if ok, err := st.EsMiembro(t.Context(), consentPersona, "herramienta"); err != nil || ok {
		t.Fatal(ok, err)
	}
}

func TestConsentimientoSnapshotAntiguo(t *testing.T) {
	for _, tabla := range []string{"consent", "authorization"} {
		t.Run(tabla, func(t *testing.T) {
			st, db := baseConsentimiento(t)
			p := proveedorConsentimiento(t, db)
			tx, err := p.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var n int
			if err := tx.QueryRow(t.Context(), `select count(*) from auth.oauth_authorizations`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
				t.Fatal(err)
			}
			if tabla == "consent" {
				_, err = tx.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente)
			} else {
				_, err = tx.Exec(t.Context(), `update auth.oauth_authorizations set status='approved',authorization_code='stale' where authorization_id=$1`, consentAutorizacion)
			}
			errorConsentimiento(t, err, "40001")
		})
	}
}

func TestConsentimientoRollbackYBorrado(t *testing.T) {
	st, db := baseConsentimiento(t)
	p := proveedorConsentimiento(t, db)
	if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `revoke update(revoked_at) on auth.oauth_consents from account`); err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err == nil {
		t.Fatal("revocación sin permiso")
	}
	if ok, err := st.EsMiembro(t.Context(), consentPersona, "herramienta"); err != nil || !ok {
		t.Fatal("debe conservar membresía", ok, err)
	}
	if _, err := db.Exec(t.Context(), `grant update(revoked_at) on auth.oauth_consents to account;
 alter table auth.oauth_authorizations disable trigger account_valida_consentimiento`); err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err == nil {
		t.Fatal("revocación sin bootstrap")
	}
	if _, err := db.Exec(t.Context(), `alter table auth.oauth_authorizations enable trigger account_valida_consentimiento`); err != nil {
		t.Fatal(err)
	}
	// BorrarRastro también borra membresías; la misma guarda cubre este caller.
	if err := st.BorrarRastro(t.Context(), consentPersona); err != nil {
		t.Fatal(err)
	}
	sinGrantsConsentimiento(t, db)
}

func TestConsentimientoLegitimo(t *testing.T) {
	st, db := baseConsentimiento(t)
	p := proveedorConsentimiento(t, db)
	if err := st.VincularCliente(t.Context(), "herramienta", "{"+strings.ToUpper(consentCliente)+"}"); err != nil {
		t.Fatal(err)
	}
	g, err := st.GrupoDeCliente(t.Context(), consentCliente)
	if err != nil || g.Nombre != "herramienta" {
		t.Fatal("identidad UUID", g, err)
	}
	if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2)`, consentPersona, consentCliente); err != nil {
		t.Fatal(err)
	}
	if err := st.Conceder(t.Context(), consentPersona, "rol", "test"); err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "rol"); err != nil {
		t.Fatal(err)
	}
	if err := st.Revocar(t.Context(), consentPersona, "herramienta"); err != nil {
		t.Fatal(err)
	}
	// Denegar y crear autorizaciones pendientes siguen permitidos sin membresía.
	if _, err := p.Exec(t.Context(), `update auth.oauth_authorizations set status='denied' where authorization_id=$1`, consentAutorizacion); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,'44444444-dddd-4000-8000-000000000041')`, consentPersona); err != nil {
		t.Fatal("cliente ajeno", err)
	}
	if err := st.Conceder(t.Context(), consentPersona, "herramienta", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `insert into auth.oauth_consents(user_id,client_id) values($1,$2) on conflict(user_id,client_id) do update set revoked_at=null`, consentPersona, consentCliente); err != nil {
		t.Fatal("concesión nueva", err)
	}
}

func TestConsentimientoRespuesta(t *testing.T) {
	for _, metodo := range []string{http.MethodGet, http.MethodPost} {
		for _, revocar := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", metodo, revocar), func(t *testing.T) {
				st, _ := baseConsentimiento(t)
				proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if revocar {
						if err := st.Revocar(r.Context(), consentPersona, "herramienta"); err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
					}
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"redirect_url":"https://tool.example/callback?code=issued-before-revocation"}`)
				}))
				defer proveedor.Close()
				gt := gotrue.New(proveedor.URL, "anon-test", "")
				ses, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
				if err != nil {
					t.Fatal(err)
				}
				publicURL, _ := url.Parse("https://account.example.com")
				s, err := New(&config.Config{PublicURL: publicURL}, st, gt, ses, nil)
				if err != nil {
					t.Fatal(err)
				}
				var r *http.Request
				if metodo == http.MethodGet {
					r = httptest.NewRequest(metodo, "/oauth/consent?authorization_id="+consentAutorizacion, nil)
				} else {
					r = httptest.NewRequest(metodo, "/oauth/consent", strings.NewReader(url.Values{"authorization_id": {consentAutorizacion}, "action": {"approve"}}.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{UserID: consentPersona}))
				w := httptest.NewRecorder()
				if metodo == http.MethodGet {
					s.consentGET(w, r)
				} else {
					s.consentPOST(w, r)
				}
				if revocar {
					if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
						t.Fatal("entregó código revocado", w.Code, w.Header())
					}
				} else if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "https://tool.example/") {
					t.Fatal("control legítimo", w.Code, w.Body.String())
				}
			})
		}
	}
}
