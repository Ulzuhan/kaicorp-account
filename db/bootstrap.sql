-- Preparación de la instancia de Supabase Auth para la app de cuenta.
-- Se ejecuta UNA vez como superusuario (postgres) en la base `postgres`:
--
--   docker exec -i <contenedor-db> psql -U supabase_admin -d postgres \
--     -v ON_ERROR_STOP=1 -v account_password="$ACCOUNT_DB_PASSWORD" \
--     -v account_migration_password="$ACCOUNT_MIGRATION_DB_PASSWORD" < db/bootstrap.sql
-- Sin comillas alrededor del valor: :'account_password' ya lo cita. Con ellas, la
-- contraseña guardada lleva las comillas dentro (pasó el 09-09).
-- Como supabase_admin y no como postgres: en la imagen de Supabase, postgres
-- no puede hacer SET ROLE a otros roles y el `authorization account` falla.
--
-- Qué hace y por qué:
--   1. Roles sin superusuario: `account` sólo hace DML en producción;
--      `account_migrator` posee el esquema y sólo se usa en despliegues;
--      `account_hook` no inicia sesión y posee las funciones con privilegios.
--      `account_hook_lock`, también sin login, sólo toma los dos bloqueos de
--      fila que coordinan snapshots antiguos del proveedor.
--   2. Permisos ACOTADOS sobre el esquema `auth` de GoTrue, que la política
--      necesita y la API no ofrece a un administrador: saber qué cliente pide
--      una autorización ANTES de aprobarla (GoTrue aprueba solo si hay grant
--      previo), revocar el grant de otra persona al quitarle una membresía, y
--      invalidar códigos OAuth, revocar grants y cerrar sesiones. Sólo lectura
--      salvo esas tres escrituras acotadas.
--   3. El hook de claims: mete en el access token los grupos de la persona,
--      leídos de account.membresias. Es lo que lee LinkUp. Su dueño dedicado
--      sólo puede leer las tres relaciones de negocio necesarias. Los dos
--      estados de coordinación quedan detrás del helper acotado de bloqueo.

\set ON_ERROR_STOP on

begin;

-- psql no sustituye variables dentro de bloques $$, así que el rol se crea o
-- se actualiza con \gexec, que ejecuta la orden que devuelve el select.
select format('create role account login password %L', :'account_password')
 where not exists (select 1 from pg_roles where rolname = 'account') \gexec
select format('alter role account with login password %L', :'account_password')
 where exists (select 1 from pg_roles where rolname = 'account') \gexec

select format('create role account_migrator login password %L', :'account_migration_password')
 where not exists (select 1 from pg_roles where rolname = 'account_migrator') \gexec
select format('alter role account_migrator with login password %L', :'account_migration_password')
 where exists (select 1 from pg_roles where rolname = 'account_migrator') \gexec
select 'create role account_hook nologin'
 where not exists (select 1 from pg_roles where rolname = 'account_hook') \gexec
select 'create role account_hook_lock nologin'
 where not exists (select 1 from pg_roles where rolname = 'account_hook_lock') \gexec

alter role account with nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
alter role account_migrator with nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
alter role account_hook with nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
alter role account_hook_lock with nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
select format('revoke %I from account', granted.rolname)
  from pg_auth_members m join pg_roles granted on granted.oid=m.roleid
  join pg_roles member on member.oid=m.member
 where member.rolname='account'
   and granted.rolname in ('account_migrator','account_hook','account_hook_lock') \gexec

create schema if not exists account authorization account_migrator;
-- Actualización: todo lo que las migraciones antiguas dejaron a `account`
-- pasa al dueño de despliegue antes de retirar CREATE y la propiedad implícita.
reassign owned by account to account_migrator;
alter schema account owner to account_migrator;
revoke all on schema account from public;
revoke create on schema account from account, account_hook, account_hook_lock;
grant usage on schema account to account, account_hook, account_hook_lock;
-- ALTER FUNCTION ... OWNER exige CREATE al nuevo dueño. Se concede sólo
-- durante esta transacción de bootstrap y se retira antes del commit.
grant usage, create on schema public to account_hook, account_hook_lock;

alter default privileges for role account_migrator in schema account revoke execute on functions from public;

-- Existe desde el bootstrap: las escrituras anteriores a la migración también
-- toman su bloqueo y la migración puede esperar a que todas hayan terminado.
set local role account_migrator;
create table if not exists account.estado_consentimiento (
  id boolean primary key default true check (id),
  version bigint not null default 0
);
insert into account.estado_consentimiento(id) values (true) on conflict do nothing;
reset role;

-- Restablece privilegios explícitos tras transferir instalaciones existentes.
-- Las relaciones que aún no existen en una instalación nueva reciben lo mismo
-- desde sus migraciones y la migración final de frontera.
revoke all privileges on all tables in schema account from public, account, account_hook, account_hook_lock;
revoke all privileges on all sequences in schema account from public, account, account_hook, account_hook_lock;
revoke all privileges on all functions in schema account from public, account, account_hook, account_hook_lock;
grant select, update on account.estado_consentimiento to account;
grant select, update(version) on account.estado_consentimiento to account_hook_lock;
do $$ begin
  if pg_catalog.to_regclass('account.grupos') is not null then
    grant select, update on account.grupos to account;
    grant select on account.grupos to account_hook;
  end if;
  if pg_catalog.to_regclass('account.membresias') is not null then
    grant select, insert, update, delete on account.membresias to account;
    grant select on account.membresias to account_hook;
  end if;
  if pg_catalog.to_regclass('account.solicitudes') is not null then
    grant select, insert, update, delete on account.solicitudes to account;
  end if;
  if pg_catalog.to_regclass('account.sesiones') is not null then
    grant select, insert, delete on account.sesiones to account;
  end if;
  if pg_catalog.to_regclass('account.intentos_password') is not null then
    grant select, insert, update, delete on account.intentos_password to account;
  end if;
  if pg_catalog.to_regclass('account.clientes_anteriores') is not null then
    grant select, insert on account.clientes_anteriores to account;
    grant select on account.clientes_anteriores to account_hook;
  end if;
  if pg_catalog.to_regclass('account.estado_vinculos') is not null then
    grant select, update on account.estado_vinculos to account;
    grant select, update(version) on account.estado_vinculos to account_hook_lock;
  end if;
  if pg_catalog.to_regclass('account.cortes_credencial') is not null then
    grant select, insert, update on account.cortes_credencial to account;
  end if;
  if pg_catalog.to_regclass('account.schema_migrations') is not null then
    grant select on account.schema_migrations to account;
  end if;
end $$;

do $$ begin
  if pg_catalog.to_regprocedure('account.actualizar_tokens_sesion(text,bytea,bytea,timestamptz)') is not null then
    execute 'grant execute on function account.actualizar_tokens_sesion(text,bytea,bytea,timestamptz) to account';
  end if;
  if pg_catalog.to_regprocedure('account.rotar_sesion(text,text,bytea,bytea,timestamptz,text)') is not null then
    execute 'grant execute on function account.rotar_sesion(text,text,bytea,bytea,timestamptz,text) to account';
  end if;
  if pg_catalog.to_regprocedure('account.tocar_sesion(text)') is not null then
    execute 'grant execute on function account.tocar_sesion(text) to account';
  end if;
  if pg_catalog.to_regprocedure('account.actualizar_correo_sesiones(uuid,text)') is not null then
    execute 'grant execute on function account.actualizar_correo_sesiones(uuid,text) to account';
  end if;
end $$;

-- Lecturas sobre auth: quién es quién, qué cliente pide qué y qué identidad,
-- propósito y buzón están ligados a un hash de correo antes de canjearlo.
grant usage on schema auth to account;
grant select on auth.users to account;
grant select on auth.one_time_tokens to account;
grant select on auth.oauth_clients to account;
grant select on auth.oauth_authorizations to account;
grant select on auth.oauth_consents to account;
-- Las tres escrituras: invalidar un código aprobado, revocar un grant y
-- cerrar sesiones del proveedor.
grant update (status) on auth.oauth_authorizations to account;
grant update (revoked_at) on auth.oauth_consents to account;
grant delete on auth.sessions to account;
grant select on auth.sessions to account;

-- Las tablas de auth llevan seguridad por filas en la imagen de Supabase: un
-- GRANT deja consultar pero no deja ver ninguna fila. Cada permiso de arriba
-- necesita su política, acotada al rol `account` y a lo que hace la app.
-- (Sin BYPASSRLS, que sería abrir todo: políticas explícitas con nombre.)
drop policy if exists account_lee_users on auth.users;
create policy account_lee_users on auth.users for select to account using (true);
drop policy if exists account_lee_tokens_correo on auth.one_time_tokens;
create policy account_lee_tokens_correo on auth.one_time_tokens for select to account using (true);
drop policy if exists account_lee_clientes on auth.oauth_clients;
create policy account_lee_clientes on auth.oauth_clients for select to account using (true);
drop policy if exists account_lee_autorizaciones on auth.oauth_authorizations;
create policy account_lee_autorizaciones on auth.oauth_authorizations for select to account using (true);
drop policy if exists account_invalida_autorizaciones on auth.oauth_authorizations;
create policy account_invalida_autorizaciones on auth.oauth_authorizations for update to account
  using (status='approved' and expires_at>now()) with check (status='denied');
drop policy if exists account_lee_grants on auth.oauth_consents;
create policy account_lee_grants on auth.oauth_consents for select to account using (true);
drop policy if exists account_revoca_grants on auth.oauth_consents;
create policy account_revoca_grants on auth.oauth_consents for update to account using (true) with check (true);
drop policy if exists account_lee_sesiones on auth.sessions;
create policy account_lee_sesiones on auth.sessions for select to account using (true);
drop policy if exists account_cierra_sesiones on auth.sessions;
create policy account_cierra_sesiones on auth.sessions for delete to account using (true);

-- El hook: groups = membresías de la persona. Sustituye al de prueba de la fase 0.
-- FOR SHARE exige UPDATE aunque no escriba. Esta función encierra esa facultad
-- en dos columnas de coordinación; el dueño de los hooks conserva sólo SELECT.
create or replace function public.account_lock_provider_state()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if pg_catalog.to_regclass('account.estado_vinculos') is not null then
    perform version from account.estado_vinculos where id for share;
    if not found then raise exception 'missing account binding state'; end if;
  end if;
  perform version from account.estado_consentimiento where id for share;
  if not found then raise exception 'missing account consent state'; end if;
end;
$$;
alter function public.account_lock_provider_state() owner to account_hook_lock;
revoke execute on function public.account_lock_provider_state() from public, anon, authenticated, supabase_auth_admin, account;
grant execute on function public.account_lock_provider_state() to account_hook;

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  claims jsonb := event->'claims';
  grupos jsonb;
begin
  select coalesce(jsonb_agg(m.grupo order by m.grupo), '[]'::jsonb)
    into grupos
    from account.membresias m
   where m.user_id = (event->>'user_id')::uuid;
  claims := jsonb_set(claims, '{groups}', grupos, true);
  return jsonb_set(event, '{claims}', claims, true);
end;
$$;
alter function public.custom_access_token_hook(jsonb) owner to account_hook;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook(jsonb) from authenticated, anon, public;

-- Ordena INSERT y UPDATE del proveedor antes de que bloqueen filas de grants.
-- SECURITY DEFINER permite leer el estado privado de account sin conceder a
-- GoTrue acceso al esquema. Antes de migrar no hay vínculos nuevos que guardar.
create or replace function public.account_ordena_grants()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.account_lock_provider_state();
  return null;
end;
$$;
alter function public.account_ordena_grants() owner to account_hook;
revoke execute on function public.account_ordena_grants() from public, anon, authenticated;

-- Un grant tardío de un cliente retirado sólo vuelve a estar vivo si el
-- vínculo ACTUAL y la membresía lo permiten; cubre INSERT y reactivación.
create or replace function public.account_valida_grants()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.revoked_at is null
     and pg_catalog.to_regclass('account.clientes_anteriores') is not null then
    if exists (select 1 from account.clientes_anteriores where cliente_id=new.client_id)
       and not exists (
         select 1 from account.grupos g
         join account.membresias m on m.grupo=g.nombre
         where g.cliente_id=new.client_id and m.user_id=new.user_id
       ) then
      raise exception 'client binding no longer authorizes this consent' using errcode='42501';
    end if;
  end if;
  return new;
end;
$$;
alter function public.account_valida_grants() owner to account_hook;
revoke execute on function public.account_valida_grants() from public, anon, authenticated;

drop trigger if exists account_ordena_grants on auth.oauth_consents;
create trigger account_ordena_grants before insert or update on auth.oauth_consents
  for each statement execute function public.account_ordena_grants();
drop trigger if exists account_valida_grants on auth.oauth_consents;
create trigger account_valida_grants before insert or update on auth.oauth_consents
  for each row execute function public.account_valida_grants();

-- Las guardas corren también para trabajos de GoTrue que terminan después de
-- un timeout HTTP. Se instalan antes de arrancar la app con la migración 0004.
-- SECURITY DEFINER sólo permite estas lecturas del esquema privado; no da al
-- proveedor permisos nuevos sobre account ni escrituras nuevas sobre auth.
create or replace function public.account_sincroniza_consentimiento()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform public.account_lock_provider_state();
  return null;
end;
$$;
alter function public.account_sincroniza_consentimiento() owner to account_hook;

create or replace function public.account_valida_consentimiento()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if tg_table_name='oauth_authorizations' then
    if new.status <> 'approved' then return new; end if;
  else
    if new.revoked_at is not null then return new; end if;
  end if;
  -- Los clientes ajenos a esta app conservan su política. Para uno vinculado,
  -- ni el primer INSERT, ni UPDATE/UPSERT, ni GET autoapprove pueden revivir
  -- autoridad después de que termine la revocación.
  if (
    exists (select 1 from account.grupos where cliente_id::uuid=new.client_id)
    and not exists (
      select 1 from account.grupos g join account.membresias m on m.grupo=g.nombre
      where g.cliente_id::uuid=new.client_id and m.user_id=new.user_id
    )
  ) or (
    exists (select 1 from account.clientes_anteriores where cliente_id=new.client_id)
    and not exists (
      select 1 from account.grupos g join account.membresias m on m.grupo=g.nombre
      where g.cliente_id::uuid=new.client_id and m.user_id=new.user_id
    )
  ) then
    raise exception 'membership no longer authorizes this consent' using errcode='42501';
  end if;
  return new;
end;
$$;
alter function public.account_valida_consentimiento() owner to account_hook;

-- Una revocación de consent no elimina por sí sola el refresh token: GoTrue
-- lo liga a auth.sessions.oauth_client_id. Esta guarda aplica la misma frontera
-- al crear o refrescar una sesión y ordena el intercambio de un código que ya
-- estaba en vuelo con el cambio de vínculo.
create or replace function public.account_valida_sesiones_oauth()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.oauth_client_id is null then return new; end if;
  if (
    exists (select 1 from account.grupos where cliente_id::uuid=new.oauth_client_id)
    and not exists (
      select 1 from account.grupos g join account.membresias m on m.grupo=g.nombre
      where g.cliente_id::uuid=new.oauth_client_id and m.user_id=new.user_id
    )
  ) or (
    exists (select 1 from account.clientes_anteriores where cliente_id=new.oauth_client_id)
    and not exists (
      select 1 from account.grupos g join account.membresias m on m.grupo=g.nombre
      where g.cliente_id::uuid=new.oauth_client_id and m.user_id=new.user_id
    )
  ) then
    raise exception 'membership no longer authorizes this OAuth session' using errcode='42501';
  end if;
  return new;
end;
$$;
alter function public.account_valida_sesiones_oauth() owner to account_hook;
revoke execute on function public.account_sincroniza_consentimiento() from public, anon, authenticated;
revoke execute on function public.account_valida_consentimiento() from public, anon, authenticated;
revoke execute on function public.account_valida_sesiones_oauth() from public, anon, authenticated;

drop trigger if exists account_sincroniza_consentimiento on auth.oauth_authorizations;
create trigger account_sincroniza_consentimiento before insert or update on auth.oauth_authorizations
  for each statement execute function public.account_sincroniza_consentimiento();
drop trigger if exists account_valida_consentimiento on auth.oauth_authorizations;
create trigger account_valida_consentimiento before insert or update on auth.oauth_authorizations
  for each row execute function public.account_valida_consentimiento();
drop trigger if exists account_sincroniza_consentimiento on auth.oauth_consents;
create trigger account_sincroniza_consentimiento before insert or update on auth.oauth_consents
  for each statement execute function public.account_sincroniza_consentimiento();
drop trigger if exists account_valida_consentimiento on auth.oauth_consents;
create trigger account_valida_consentimiento before insert or update on auth.oauth_consents
  for each row execute function public.account_valida_consentimiento();
drop trigger if exists account_sincroniza_sesiones_oauth on auth.sessions;
create trigger account_sincroniza_sesiones_oauth before insert or update on auth.sessions
  for each statement execute function public.account_sincroniza_consentimiento();
drop trigger if exists account_valida_sesiones_oauth on auth.sessions;
create trigger account_valida_sesiones_oauth before insert or update on auth.sessions
  for each row execute function public.account_valida_sesiones_oauth();

revoke create on schema public from account_hook, account_hook_lock;

commit;
select 'bootstrap de account aplicado' as resultado;
