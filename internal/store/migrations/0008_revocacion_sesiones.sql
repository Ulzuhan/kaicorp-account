-- Un cierre administrativo no depende de que los DELETE físicos sean la única
-- memoria del evento. La generación invalida filas supervivientes y el corte
-- impide publicar después un token del proveedor obtenido antes del cierre.
alter table account.cortes_credencial
  add column if not exists sesiones_no_antes bigint not null default 0,
  add column if not exists sesiones_generacion bigint not null default 0;

alter table account.sesiones
  add column if not exists revocacion_generacion bigint not null default 0;

grant select, insert, update on account.cortes_credencial to account;
grant select, insert, update, delete on account.sesiones to account;
