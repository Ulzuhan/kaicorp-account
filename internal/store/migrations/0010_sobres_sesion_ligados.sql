-- Los tokens sellados por versiones anteriores no llevaban AAD de fila. No se
-- pueden distinguir de un sobre trasplantado: el despliegue cierra esas
-- sesiones una vez y sólo acepta sobres creados por el binario nuevo.
delete from account.sesiones;

-- El runtime puede crear, leer y cerrar filas, pero las mutaciones de tokens y
-- metadata pasan por operaciones de ciclo de vida estrechas. Sus transacciones
-- y bloqueos siguen en la aplicación; SECURITY DEFINER aporta sólo el UPDATE
-- exacto que cada operación necesita.
create or replace function account.actualizar_tokens_sesion(
  p_id text, p_access bytea, p_refresh bytea, p_access_expira timestamptz
) returns bigint
language sql
security definer
set search_path = pg_catalog
as $$
  with actualizada as (
    update account.sesiones
       set access_token=p_access, refresh_token=p_refresh,
           access_expira=p_access_expira, ultima=pg_catalog.now()
     where id=p_id and expira>pg_catalog.now()
     returning 1
  )
  select count(*) from actualizada
$$;

create or replace function account.rotar_sesion(
  p_id text, p_nuevo_id text, p_access bytea, p_refresh bytea,
  p_access_expira timestamptz, p_aal text
) returns table(expira timestamptz, user_id text, referencia text)
language sql
security definer
set search_path = pg_catalog
as $$
  update account.sesiones
     set id=p_nuevo_id, access_token=p_access, refresh_token=p_refresh,
         access_expira=p_access_expira,
         aal=coalesce(nullif(p_aal, ''), account.sesiones.aal),
         ultima=pg_catalog.now()
   where account.sesiones.id=p_id
     and account.sesiones.expira>pg_catalog.now()
   returning account.sesiones.expira, account.sesiones.user_id::text,
             account.sesiones.referencia::text
$$;

create or replace function account.tocar_sesion(p_id text) returns bigint
language sql
security definer
set search_path = pg_catalog
as $$
  with actualizada as (
    update account.sesiones set ultima=pg_catalog.now() where id=p_id
    returning 1
  )
  select count(*) from actualizada
$$;

create or replace function account.actualizar_correo_sesiones(p_user_id uuid, p_email text) returns bigint
language sql
security definer
set search_path = pg_catalog
as $$
  with actualizadas as (
    update account.sesiones set email=p_email where user_id=p_user_id
    returning 1
  )
  select count(*) from actualizadas
$$;

revoke all on function account.actualizar_tokens_sesion(text,bytea,bytea,timestamptz) from public;
revoke all on function account.rotar_sesion(text,text,bytea,bytea,timestamptz,text) from public;
revoke all on function account.tocar_sesion(text) from public;
revoke all on function account.actualizar_correo_sesiones(uuid,text) from public;
grant execute on function account.actualizar_tokens_sesion(text,bytea,bytea,timestamptz) to account;
grant execute on function account.rotar_sesion(text,text,bytea,bytea,timestamptz,text) to account;
grant execute on function account.tocar_sesion(text) to account;
grant execute on function account.actualizar_correo_sesiones(uuid,text) to account;

revoke update on account.sesiones from account;
grant select, insert, delete on account.sesiones to account;
