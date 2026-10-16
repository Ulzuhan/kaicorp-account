-- La referencia identifica la fila durante toda su vida, incluso cuando se
-- sustituye la cookie al verificar un factor. No sirve para autenticar.
alter table account.sesiones
  add column if not exists referencia uuid not null default gen_random_uuid();
create unique index if not exists sesiones_referencia on account.sesiones (referencia);
