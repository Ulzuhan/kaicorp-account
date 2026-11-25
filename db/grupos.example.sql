-- Los grupos de una instalación: una fila por herramienta o rol. Ejemplo; la
-- instalación real carga el suyo con sus URL. `cliente_id` se vincula después
-- desde /admin o con `account vincular`, cuando exista el cliente OAuth.
--
--   docker exec -i <contenedor-db> psql -U account_migrator -d postgres < grupos.sql
insert into account.grupos (nombre, titulo, descripcion, url, tipo, solicitable, orden) values
  ('files',   'Files',   'Share files with links that expire.', 'https://files.example.com', 'herramienta', true, 10),
  ('notes',   'Notes',   'Notes for the team.',                 'https://notes.example.com', 'herramienta', true, 20),
  ('account-admin', 'Account administration', 'Approve requests and manage memberships.', '', 'rol', false, 90)
on conflict (nombre) do update set titulo = excluded.titulo, descripcion = excluded.descripcion,
  url = excluded.url, tipo = excluded.tipo, solicitable = excluded.solicitable, orden = excluded.orden;
