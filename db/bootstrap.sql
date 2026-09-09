-- Preparación de la instancia de Supabase Auth para la app de cuenta.
-- Se ejecuta UNA vez como superusuario (postgres) en la base `postgres`:
--
--   docker exec -i <contenedor-db> psql -U supabase_admin -d postgres \
--     -v ON_ERROR_STOP=1 -v account_password="$ACCOUNT_DB_PASSWORD" < db/bootstrap.sql
-- Sin comillas alrededor del valor: :'account_password' ya lo cita. Con ellas, la
-- contraseña guardada lleva las comillas dentro (pasó el 09-09).
-- Como supabase_admin y no como postgres: en la imagen de Supabase, postgres
-- no puede hacer SET ROLE a otros roles y el `authorization account` falla.
--
-- Qué hace y por qué:
--   1. El rol `account`, dueño del esquema `account`: la app corre con él y
--      sus migraciones crean ahí sus tablas. No es superusuario.
--   2. Permisos ACOTADOS sobre el esquema `auth` de GoTrue, que la política
--      necesita y la API no ofrece a un administrador: saber qué cliente pide
--      una autorización ANTES de aprobarla (GoTrue aprueba solo si hay grant
--      previo), revocar el grant de otra persona al quitarle una membresía, y
--      cerrar sus sesiones. Sólo lectura salvo esas dos escrituras.
--   3. El hook de claims: mete en el access token los grupos de la persona,
--      leídos de account.membresias. Es lo que lee LinkUp. Va como SECURITY
--      DEFINER del superusuario para que supabase_auth_admin no necesite
--      permisos sobre el esquema account.

\set ON_ERROR_STOP on

-- psql no sustituye variables dentro de bloques $$, así que el rol se crea o
-- se actualiza con \gexec, que ejecuta la orden que devuelve el select.
select format('create role account login password %L', :'account_password')
 where not exists (select 1 from pg_roles where rolname = 'account') \gexec
select format('alter role account with login password %L', :'account_password')
 where exists (select 1 from pg_roles where rolname = 'account') \gexec

create schema if not exists account authorization account;
grant usage on schema account to account;

-- Lecturas sobre auth: quién es quién y qué cliente pide qué.
grant usage on schema auth to account;
grant select on auth.users to account;
grant select on auth.oauth_clients to account;
grant select on auth.oauth_authorizations to account;
grant select on auth.oauth_consents to account;
-- Las dos escrituras: revocar un grant y cerrar sesiones del proveedor.
grant update (revoked_at) on auth.oauth_consents to account;
grant delete on auth.sessions to account;
grant select on auth.sessions to account;

-- Las tablas de auth llevan seguridad por filas en la imagen de Supabase: un
-- GRANT deja consultar pero no deja ver ninguna fila. Cada permiso de arriba
-- necesita su política, acotada al rol `account` y a lo que hace la app.
-- (Sin BYPASSRLS, que sería abrir todo: mejor cinco políticas con nombre.)
drop policy if exists account_lee_users on auth.users;
create policy account_lee_users on auth.users for select to account using (true);
drop policy if exists account_lee_clientes on auth.oauth_clients;
create policy account_lee_clientes on auth.oauth_clients for select to account using (true);
drop policy if exists account_lee_autorizaciones on auth.oauth_authorizations;
create policy account_lee_autorizaciones on auth.oauth_authorizations for select to account using (true);
drop policy if exists account_lee_grants on auth.oauth_consents;
create policy account_lee_grants on auth.oauth_consents for select to account using (true);
drop policy if exists account_revoca_grants on auth.oauth_consents;
create policy account_revoca_grants on auth.oauth_consents for update to account using (true) with check (true);
drop policy if exists account_lee_sesiones on auth.sessions;
create policy account_lee_sesiones on auth.sessions for select to account using (true);
drop policy if exists account_cierra_sesiones on auth.sessions;
create policy account_cierra_sesiones on auth.sessions for delete to account using (true);

-- El hook: groups = membresías de la persona. Sustituye al de prueba de la fase 0.
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
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook(jsonb) from authenticated, anon, public;

select 'bootstrap de account aplicado' as resultado;
