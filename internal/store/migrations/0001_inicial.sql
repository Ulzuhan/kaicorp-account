-- Esquema `account`: lo que la app de cuenta guarda además de lo que guarda
-- GoTrue. Las cuentas, contraseñas, factores y sesiones del proveedor viven en
-- el esquema `auth`; aquí viven las MEMBRESÍAS (quién puede entrar a qué), las
-- SOLICITUDES (la lista de trabajo de quien aprueba) y las SESIONES de esta
-- app, que envuelven a las de GoTrue.
--
-- El esquema lo crea db/bootstrap.sql como superusuario, con el rol `account`
-- de dueño; estas migraciones corren con ese rol.

create table if not exists account.grupos (
  nombre      text primary key check (nombre ~ '^[a-z0-9-]+$'),
  titulo      text not null,
  descripcion text not null default '',
  url         text not null default '',
  -- El cliente OAuth (auth.oauth_clients.id) al que este grupo abre la puerta.
  -- Un cliente exige exactamente un grupo; los grupos sin cliente son roles
  -- dentro de una app (linkup-admins) o de esta (account-admin).
  cliente_id  text unique,
  -- ¿Se puede pedir desde /solicitar? Chorus y los roles, no.
  solicitable boolean not null default true,
  orden       int not null default 100
);

create table if not exists account.membresias (
  user_id uuid not null,
  grupo   text not null references account.grupos(nombre) on delete cascade,
  desde   timestamptz not null default now(),
  -- Quién la concedió: un correo de administrador, o 'automática' cuando una
  -- cuenta ya activa pidió otra herramienta.
  por     text not null,
  primary key (user_id, grupo)
);
create index if not exists membresias_grupo on account.membresias (grupo);

create table if not exists account.solicitudes (
  id       uuid primary key default gen_random_uuid(),
  user_id  uuid not null,
  grupo    text not null references account.grupos(nombre) on delete cascade,
  estado   text not null check (estado in ('pendiente', 'aprobada', 'rechazada', 'automatica')),
  creada   timestamptz not null default now(),
  resuelta timestamptz,
  por      text
);
-- Una sola pendiente por persona y grupo: repetir la petición no crea ruido.
create unique index if not exists solicitudes_pendiente_unica
  on account.solicitudes (user_id, grupo) where estado = 'pendiente';
create index if not exists solicitudes_user on account.solicitudes (user_id);

create table if not exists account.sesiones (
  id            text primary key,
  user_id       uuid not null,
  email         text not null,
  nombre        text not null default '',
  aal           text not null default 'aal1',
  -- Los tokens de GoTrue, cifrados con la clave de la app (AES-GCM). La base
  -- no los puede leer; quien tenga la base y no la clave tampoco.
  access_token  bytea not null,
  refresh_token bytea not null,
  access_expira timestamptz not null,
  creada        timestamptz not null default now(),
  ultima        timestamptz not null default now(),
  expira        timestamptz not null,
  agente        text not null default ''
);
create index if not exists sesiones_user on account.sesiones (user_id);
create index if not exists sesiones_expira on account.sesiones (expira);

-- Los grupos (herramientas y roles) no van aquí: son de cada instalación y se
-- cargan con SQL (db/grupos.example.sql) o se vinculan desde /admin.
