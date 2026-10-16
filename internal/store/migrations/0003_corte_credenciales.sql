-- El corte persiste aunque ya no quede ninguna sesión. Impide que una ficha
-- emitida antes de un cambio de contraseña se inserte después de la limpieza.
create table if not exists account.cortes_credencial (
  user_id   uuid primary key,
  no_antes  bigint not null
);
