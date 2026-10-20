-- Separa la clase de grupo de sus datos de presentación. Una URL no distingue
-- con seguridad: históricamente también hubo roles con URL. Por eso toda fila
-- antigua sin clasificación se cierra como rol; la configuración de cada
-- instalación debe volver a optar explícitamente por sus herramientas.
alter table account.grupos add column if not exists tipo text;

update account.grupos
   set tipo = 'rol'
 where tipo is null;

alter table account.grupos alter column tipo set default 'rol';
alter table account.grupos alter column tipo set not null;
alter table account.grupos alter column solicitable set default false;

-- Repara antes de cerrar la frontera cualquier fila heredada: hasta que la
-- instalación declare que es herramienta, no entra en autoservicio.
update account.grupos set solicitable=false where tipo='rol' and solicitable;

do $$
begin
  if not exists (select 1 from pg_constraint where conrelid='account.grupos'::regclass and conname='grupos_tipo_valido') then
    alter table account.grupos add constraint grupos_tipo_valido check (tipo in ('herramienta','rol'));
  end if;
  if not exists (select 1 from pg_constraint where conrelid='account.grupos'::regclass and conname='grupos_rol_no_solicitable') then
    alter table account.grupos add constraint grupos_rol_no_solicitable check (tipo <> 'rol' or not solicitable);
  end if;
end $$;
