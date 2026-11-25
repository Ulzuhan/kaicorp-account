-- Las verificaciones de contraseña comparten presupuesto entre procesos y
-- réplicas. Dos filas por sujeto mantienen a la vez el agregado de cuenta y
-- la dimensión de cliente confiable sin convertir una NAT en un bloqueo
-- global para todas las cuentas.
create table if not exists account.intentos_password (
  tipo        text not null check (tipo in ('usuario','correo')),
  sujeto      text not null check (length(sujeto) between 1 and 128),
  cliente     text not null default '' check (length(cliente) <= 64),
  intentos    integer not null default 0 check (intentos >= 0),
  no_antes    timestamptz not null default 'epoch',
  actualizado timestamptz not null default now(),
  primary key (tipo, sujeto, cliente)
);
create index if not exists intentos_password_actualizado on account.intentos_password (actualizado);

grant select, insert, update, delete on account.intentos_password to account;
