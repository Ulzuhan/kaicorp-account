-- Una orden administrativa conserva la generación que tenía quien la
-- inició. Revocar cualquier membresía de esa persona la adelanta: una orden
-- que estuviera esperando, o que vuelva de un efecto remoto, no revive aunque
-- la administración se conceda otra vez.
create table if not exists account.autoridad_administrativa (
  user_id     uuid primary key,
  generacion bigint not null default 0 check (generacion >= 0),
  actualizada timestamptz not null default now()
);

grant select, insert, update on account.autoridad_administrativa to account;
