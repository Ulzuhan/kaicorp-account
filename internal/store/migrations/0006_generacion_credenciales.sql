-- La generación liga una mutación de contraseña con la única sesión que esa
-- mutación puede publicar. El corte temporal sigue invalidando tokens del
-- proveedor; la generación cierra la carrera entre el PUT remoto y la sesión.
alter table account.cortes_credencial
  add column if not exists generacion bigint not null default 0;

grant select, insert, update on account.cortes_credencial to account;
