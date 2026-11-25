-- Consolida la frontera entre despliegue, runtime y funciones privilegiadas.
-- El bootstrap debe ejecutarse primero: reescribe las seis funciones públicas,
-- transfiere instalaciones antiguas y crea los tres roles sin superusuario.
do $$
declare
  inseguro text;
begin
  if current_user <> 'account_migrator' then
    raise exception 'migrations require account_migrator';
  end if;
  if (select r.rolname from pg_catalog.pg_namespace n
      join pg_catalog.pg_roles r on r.oid=n.nspowner
      where n.nspname='account') <> 'account_migrator' then
    raise exception 'reapply db/bootstrap.sql: account schema has an unsafe owner';
  end if;
  select c.relname into inseguro
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    join pg_catalog.pg_roles r on r.oid=c.relowner
   where n.nspname='account' and c.relkind in ('r','p','v','m','S')
     and r.rolname <> 'account_migrator'
   limit 1;
  if inseguro is not null then
    raise exception 'reapply db/bootstrap.sql: unsafe owner for account.%', inseguro;
  end if;
  if exists (
    select 1 from (values
      ('custom_access_token_hook','jsonb'::pg_catalog.regtype),
      ('account_ordena_grants',null::pg_catalog.regtype),
      ('account_valida_grants',null::pg_catalog.regtype),
      ('account_sincroniza_consentimiento',null::pg_catalog.regtype),
      ('account_valida_consentimiento',null::pg_catalog.regtype),
      ('account_valida_sesiones_oauth',null::pg_catalog.regtype)
    ) expected(name,arg)
    where not exists (
      select 1 from pg_catalog.pg_proc p
      join pg_catalog.pg_namespace n on n.oid=p.pronamespace
      join pg_catalog.pg_roles r on r.oid=p.proowner
      where n.nspname='public' and p.proname=expected.name
        and r.rolname='account_hook'
        and (expected.arg is null or p.proargtypes[0]=expected.arg::oid)
    )
  ) then
    raise exception 'reapply db/bootstrap.sql: privileged hooks have an unsafe owner';
  end if;
  if not exists (
    select 1 from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid=p.pronamespace
    join pg_catalog.pg_roles r on r.oid=p.proowner
    where n.nspname='public' and p.proname='account_lock_provider_state'
      and r.rolname='account_hook_lock'
  ) then
    raise exception 'reapply db/bootstrap.sql: provider lock helper has an unsafe owner';
  end if;
  if exists (select 1 from pg_catalog.pg_roles
      where rolname in ('account','account_migrator','account_hook','account_hook_lock')
      and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls)) then
    raise exception 'reapply db/bootstrap.sql: account roles are overprivileged';
  end if;
end $$;

revoke all privileges on schema account from public;
revoke create on schema account from account, account_hook, account_hook_lock;
grant usage on schema account to account, account_hook, account_hook_lock;

revoke all privileges on all tables in schema account from public, account, account_hook, account_hook_lock;
revoke all privileges on all sequences in schema account from public, account, account_hook, account_hook_lock;
revoke all privileges on all functions in schema account from public, account, account_hook, account_hook_lock;

grant select, update on account.estado_consentimiento to account;
grant select, update(version) on account.estado_consentimiento to account_hook_lock;
grant select, update on account.grupos to account;
grant select on account.grupos to account_hook;
grant select, insert, update, delete on account.membresias to account;
grant select on account.membresias to account_hook;
grant select, insert, update, delete on account.solicitudes to account;
grant select, insert, update, delete on account.sesiones to account;
grant select, insert on account.clientes_anteriores to account;
grant select on account.clientes_anteriores to account_hook;
grant select, update on account.estado_vinculos to account;
grant select, update(version) on account.estado_vinculos to account_hook_lock;
grant select, insert, update on account.cortes_credencial to account;
grant select on account.schema_migrations to account;

alter default privileges for role account_migrator in schema account
  revoke execute on functions from public;
