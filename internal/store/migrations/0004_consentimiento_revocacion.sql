-- El bootstrap creó el estado ANTES de admitir nuevas escrituras del
-- proveedor. Drena sus transacciones antes de cambiar grupos o membresías.
do $$ begin
  if pg_catalog.to_regclass('account.estado_vinculos') is not null then
    perform version from account.estado_vinculos where id for share;
    if not found then raise exception 'missing account binding state'; end if;
  end if;
  update account.estado_consentimiento set version=version+1 where id;
  if not found then raise exception 'reapply db/bootstrap.sql before migrating'; end if;
end $$;

create function account.ordena_revocacion()
returns trigger language plpgsql set search_path = '' as $$
begin
  -- Si está instalada la guarda de vínculos, siempre va primero.
  if pg_catalog.to_regclass('account.estado_vinculos') is not null then
    perform version from account.estado_vinculos where id for share;
    if not found then raise exception 'missing account binding state'; end if;
  end if;
  if (select count(*) from pg_catalog.pg_trigger
      where not tgisinternal and tgenabled in ('O','A')
      and tgname in ('account_sincroniza_consentimiento','account_valida_consentimiento')
      and tgrelid in ('auth.oauth_authorizations'::regclass,'auth.oauth_consents'::regclass)) <> 4 then
    raise exception 'reapply db/bootstrap.sql before revoking memberships';
  end if;
  update account.estado_consentimiento set version=version+1 where id;
  if not found then raise exception 'missing account consent state'; end if;
  return null;
end;
$$;

create function account.revoca_consentimiento()
returns trigger language plpgsql set search_path = '' as $$
begin
  -- En la misma transacción que el DELETE: un error conserva la membresía.
  update auth.oauth_consents set revoked_at=pg_catalog.now()
    where user_id=old.user_id and revoked_at is null
    and client_id in (select cliente_id from account.grupos where nombre=old.grupo);
  return old;
end;
$$;
revoke execute on function account.ordena_revocacion() from public;
revoke execute on function account.revoca_consentimiento() from public;

create trigger account_ordena_revocacion before delete on account.membresias
  for each statement execute function account.ordena_revocacion();
create trigger account_revoca_consentimiento after delete on account.membresias
  for each row execute function account.revoca_consentimiento();
