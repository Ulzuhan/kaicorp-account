-- Esquema `account`: lo que la app de cuenta guarda además de lo que guarda
-- GoTrue. Las cuentas, contraseñas, factores y sesiones del proveedor viven en
-- el esquema `auth`; aquí viven las MEMBRESÍAS (quién puede entrar a qué), las
-- SOLICITUDES (la lista de trabajo de quien aprueba) y las SESIONES de esta
-- app, que envuelven a las de GoTrue.
--
-- El esquema lo crea db/bootstrap.sql para `account_migrator`; sólo esa
-- identidad de despliegue ejecuta migraciones. `account` recibe DML explícito.

create table if not exists account.grupos (
  nombre      text primary key check (nombre ~ '^[a-z0-9-]+$'),
  titulo      text not null,
  descripcion text not null default '',
  url         text not null default '',
  -- La clase es autoridad: no se infiere de la URL ni del cliente.
  tipo        text not null default 'rol'
              constraint grupos_tipo_valido check (tipo in ('herramienta','rol')),
  -- El cliente OAuth (auth.oauth_clients.id) al que este grupo abre la puerta.
  -- Un cliente exige exactamente un grupo de tipo herramienta.
  cliente_id  text unique,
  -- El alta es cerrada: una herramienta debe optar explícitamente por admitir
  -- peticiones; un rol no puede hacerlo ni por error de datos.
  solicitable boolean not null default false,
  orden       int not null default 100,
  constraint grupos_rol_no_solicitable check (tipo <> 'rol' or not solicitable)
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

-- Generación de las operaciones administrativas iniciadas por una persona.
-- Sobrevive a una revocación y a una concesión posterior para que una orden
-- antigua nunca recupere autoridad.
create table if not exists account.autoridad_administrativa (
  user_id     uuid primary key,
  generacion bigint not null default 0 check (generacion >= 0),
  actualizada timestamptz not null default now()
);

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
  agente        text not null default '',
  -- Instantánea de la generación de revocación al publicar la fila. Una fila
  -- de una generación anterior nunca vuelve a ser autoridad aunque sobreviva
  -- físicamente a una limpieza.
  revocacion_generacion bigint not null default 0
);
create index if not exists sesiones_user on account.sesiones (user_id);
create index if not exists sesiones_expira on account.sesiones (expira);

-- Presupuesto compartido de verificaciones de contraseña. La fila sin cliente
-- impide reiniciar el límite cambiando de IP; la fila con cliente añade la
-- identidad de red obtenida sólo de la frontera de proxy de confianza.
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

-- El runtime y los hooks reciben capacidades explícitas; la propiedad se
-- conserva siempre en account_migrator.
grant select, update on account.grupos to account;
grant select on account.grupos to account_hook;
grant select, insert, update, delete on account.membresias to account;
grant select on account.membresias to account_hook;
grant select, insert, update on account.autoridad_administrativa to account;
grant select, insert, update, delete on account.solicitudes to account;
grant select, insert, delete on account.sesiones to account;
grant select, insert, update, delete on account.intentos_password to account;

-- Los grupos (herramientas y roles) no van aquí: son de cada instalación y se
-- cargan con SQL (db/grupos.example.sql) o se vinculan desde /admin.
