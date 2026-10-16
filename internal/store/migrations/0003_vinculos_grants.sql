-- Una identidad de cliente, también cuando llega como UUID con otra grafía.
-- Los valores inválidos o duplicados abortan la migración: no se reinterpretan.
alter table account.grupos alter column cliente_id type uuid using cliente_id::uuid;

-- Conserva los clientes retirados para reconocer escrituras tardías de GoTrue.
create table account.clientes_anteriores (
  cliente_id uuid primary key
);

-- Las guardas de db/bootstrap.sql toman FOR SHARE antes de escribir grants;
-- VincularCliente actualiza esta fila antes de retirar el vínculo antiguo.
create table account.estado_vinculos (
  id boolean primary key default true check (id),
  version bigint not null default 0
);
insert into account.estado_vinculos(id) values (true);
