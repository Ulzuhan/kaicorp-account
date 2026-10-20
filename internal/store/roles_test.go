package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRolesRestringidosProtegenHook(t *testing.T) {
	s, db := storeVinculos(t)

	var hooksSeguros bool
	if err := db.QueryRow(t.Context(), `select count(*)=6 and bool_and(r.rolname='account_hook' and not r.rolsuper)
		from pg_proc p join pg_namespace n on n.oid=p.pronamespace join pg_roles r on r.oid=p.proowner
		where n.nspname='public' and p.proname in ('custom_access_token_hook','account_ordena_grants',
		'account_valida_grants','account_sincroniza_consentimiento','account_valida_consentimiento',
		'account_valida_sesiones_oauth')`).Scan(&hooksSeguros); err != nil {
		t.Fatal(err)
	}
	if !hooksSeguros {
		t.Fatal("las funciones privilegiadas no pertenecen exclusivamente a account_hook sin superusuario")
	}
	var cierreSeguro bool
	if err := db.QueryRow(t.Context(), `select r.rolname='account_hook_lock' and not r.rolsuper
		from pg_proc p join pg_namespace n on n.oid=p.pronamespace join pg_roles r on r.oid=p.proowner
		where n.nspname='public' and p.proname='account_lock_provider_state'`).Scan(&cierreSeguro); err != nil {
		t.Fatal(err)
	}
	if !cierreSeguro {
		t.Fatal("el cierre de coordinación no pertenece a su rol restringido")
	}

	var relacionesSeguras bool
	if err := db.QueryRow(t.Context(), `select coalesce(bool_and(r.rolname='account_migrator'),false)
		from pg_class c join pg_namespace n on n.oid=c.relnamespace join pg_roles r on r.oid=c.relowner
		where n.nspname='account' and c.relkind in ('r','p','v','m','S')`).Scan(&relacionesSeguras); err != nil {
		t.Fatal(err)
	}
	if !relacionesSeguras {
		t.Fatal("el runtime aún posee una relación del esquema account")
	}

	var creaSchema, hookLee, hookEscribe, hookLeeAjeno, lockLee, lockActualizaVersion, lockActualizaID, lockLeeNegocio bool
	var runtimeLee, runtimeInserta, runtimeActualiza, runtimeBorra, runtimeIntentos, runtimeMigra bool
	var runtimeActualizaSesiones, runtimeProcedimientosSesion bool
	if err := db.QueryRow(t.Context(), `select
		has_schema_privilege('account','account','CREATE'),
		(select count(*)=3 and bool_and(has_table_privilege('account_hook',format('account.%I',nombre),'SELECT'))
		 from unnest(array['membresias','grupos','clientes_anteriores']) nombre),
		has_table_privilege('account_hook','account.membresias','INSERT,UPDATE,DELETE'),
		(select bool_or(has_table_privilege('account_hook',format('account.%I',nombre),'SELECT'))
		 from unnest(array['estado_vinculos','estado_consentimiento','solicitudes','sesiones','cortes_credencial','intentos_password','schema_migrations']) nombre),
		(select bool_and(has_table_privilege('account_hook_lock',format('account.%I',nombre),'SELECT'))
		 from unnest(array['estado_vinculos','estado_consentimiento']) nombre),
		(select bool_and(has_column_privilege('account_hook_lock',format('account.%I',nombre),'version','UPDATE'))
		 from unnest(array['estado_vinculos','estado_consentimiento']) nombre),
		(select bool_or(has_column_privilege('account_hook_lock',format('account.%I',nombre),'id','UPDATE'))
		 from unnest(array['estado_vinculos','estado_consentimiento']) nombre),
		has_table_privilege('account_hook_lock','account.membresias','SELECT,INSERT,UPDATE,DELETE'),
		has_table_privilege('account','account.membresias','SELECT'),
		has_table_privilege('account','account.membresias','INSERT'),
		has_table_privilege('account','account.membresias','UPDATE'),
		has_table_privilege('account','account.membresias','DELETE'),
		has_table_privilege('account','account.intentos_password','SELECT,INSERT,UPDATE,DELETE'),
		has_table_privilege('account','account.schema_migrations','INSERT,UPDATE,DELETE'),
		has_table_privilege('account','account.sesiones','UPDATE'),
		(select count(*)=4 and bool_and(has_function_privilege('account',p.oid,'EXECUTE'))
		 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
		 where n.nspname='account' and p.proname in ('actualizar_tokens_sesion','rotar_sesion','tocar_sesion','actualizar_correo_sesiones'))`).
		Scan(&creaSchema, &hookLee, &hookEscribe, &hookLeeAjeno, &lockLee, &lockActualizaVersion, &lockActualizaID, &lockLeeNegocio,
			&runtimeLee, &runtimeInserta, &runtimeActualiza, &runtimeBorra, &runtimeIntentos, &runtimeMigra,
			&runtimeActualizaSesiones, &runtimeProcedimientosSesion); err != nil {
		t.Fatal(err)
	}
	if creaSchema || !hookLee || hookEscribe || hookLeeAjeno || !lockLee || !lockActualizaVersion || lockActualizaID || lockLeeNegocio ||
		!runtimeLee || !runtimeInserta || !runtimeActualiza || !runtimeBorra || !runtimeIntentos || runtimeMigra ||
		runtimeActualizaSesiones || !runtimeProcedimientosSesion {
		t.Fatalf("privilegios inseguros: create=%v hook=%v/%v/%v lock=%v/%v/%v/%v runtime=%v/%v/%v/%v intentos=%v migra=%v sesiones-update=%v sesiones-funciones=%v",
			creaSchema, hookLee, hookEscribe, hookLeeAjeno, lockLee, lockActualizaVersion, lockActualizaID, lockLeeNegocio,
			runtimeLee, runtimeInserta, runtimeActualiza, runtimeBorra, runtimeIntentos, runtimeMigra,
			runtimeActualizaSesiones, runtimeProcedimientosSesion)
	}
	var invalidaAutorizacion, cambiaCodigo bool
	if err := db.QueryRow(t.Context(), `select
		has_column_privilege('account','auth.oauth_authorizations','status','UPDATE'),
		has_column_privilege('account','auth.oauth_authorizations','authorization_code','UPDATE')`).
		Scan(&invalidaAutorizacion, &cambiaCodigo); err != nil {
		t.Fatal(err)
	}
	if !invalidaAutorizacion || cambiaCodigo {
		t.Fatalf("permiso OAuth demasiado amplio: status=%v code=%v", invalidaAutorizacion, cambiaCodigo)
	}

	for _, sql := range []string{
		`drop table account.membresias`,
		`alter table account.membresias rename to membresias_atacante`,
		`alter table account.membresias disable trigger account_revoca_consentimiento`,
		`truncate account.membresias`,
		`create function account.elevar() returns text language sql as 'select current_user'`,
		`alter function public.custom_access_token_hook(jsonb) rename to hook_atacante`,
		`set role account_migrator`,
		`set role account_hook`,
		`set role account_hook_lock`,
	} {
		tx, err := s.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), sql)
		_ = tx.Rollback(t.Context())
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("el runtime pudo cambiar la frontera con %q: %v", sql, err)
		}
	}
	if err := s.Migrate(t.Context()); err == nil {
		t.Fatal("el runtime pudo ejecutar migraciones")
	}

	if err := s.Conceder(t.Context(), personaDos, "otra", "test"); err != nil {
		t.Fatalf("DML legítimo del runtime: %v", err)
	}
	conn, err := db.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(t.Context(), `set role supabase_auth_admin`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(t.Context(), `reset role`)
	var resultado string
	if err := conn.QueryRow(t.Context(), `select public.custom_access_token_hook(
		jsonb_build_object('user_id',$1::text,'claims','{}'::jsonb))::text`, personaUno).Scan(&resultado); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resultado, `"groups": ["herramienta"]`) {
		t.Fatalf("el hook legítimo perdió las membresías: %s", resultado)
	}
}
