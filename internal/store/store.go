// Package store es la capa de datos de la app de cuenta: el esquema `account`
// (grupos, membresías, solicitudes, sesiones) y las pocas lecturas y
// escrituras sobre el esquema `auth` de GoTrue que la política necesita y que
// la API no ofrece a un administrador: saber qué cliente pide una
// autorización antes de aprobarla, revocar un grant ajeno y cerrar las
// sesiones de otra persona. Los permisos exactos están en db/bootstrap.sql.
//
// Todo el SQL vive aquí. Es lo que permite, si algún día hace falta, mover el
// esquema sin tocar handlers.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migraciones embed.FS

// ErrNoExiste es «no hay fila».
var ErrNoExiste = errors.New("no existe")

// ErrCredencialAnterior impide publicar una sesión del proveedor emitida antes
// del último cambio de contraseña conocido por la app.
var ErrCredencialAnterior = errors.New("credencial anterior al último cambio")

// Store es el acceso a la base.
type Store struct {
	pool          *pgxpool.Pool
	autoridadPool *pgxpool.Pool
}

// Open abre el pool y comprueba la conexión.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("ACCOUNT_DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}

	// Las fronteras administrativas conservan una conexión mientras mantienen
	// bloqueos de sesión. Si compartieran este pool con las consultas que la
	// operación ejecuta bajo el bloqueo, suficientes peticiones concurrentes
	// podrían ocupar todas las conexiones y esperar indefinidamente por sí
	// mismas. Un pool pequeño y separado limita esas órdenes sin privar al pool
	// ordinario que necesitan para completar sus efectos.
	autoridadCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("ACCOUNT_DATABASE_URL (autoridad): %w", err)
	}
	autoridadCfg.MaxConns = 4
	autoridadCfg.MinConns = 0
	autoridadCfg.MaxConnIdleTime = 5 * time.Minute
	autoridadPool, err := pgxpool.NewWithConfig(ctx, autoridadCfg)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err := autoridadPool.Ping(ctx); err != nil {
		autoridadPool.Close()
		pool.Close()
		return nil, fmt.Errorf("postgres (autoridad): %w", err)
	}
	return &Store{pool: pool, autoridadPool: autoridadPool}, nil
}

// Close cierra ambos pools.
func (s *Store) Close() {
	if s.autoridadPool != nil {
		s.autoridadPool.Close()
	}
	s.pool.Close()
}

// Ping comprueba la base; lo usa la sonda de salud.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func nombresMigraciones() ([]string, error) {
	entries, err := fs.ReadDir(migraciones, "migrations")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// CheckMigrations sólo lee el registro de migraciones. El proceso de larga
// vida usa este método con el rol DML y nunca recibe autoridad de esquema.
func (s *Store) CheckMigrations(ctx context.Context) error {
	want, err := nombresMigraciones()
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `select version from account.schema_migrations`)
	if err != nil {
		return fmt.Errorf("migraciones no disponibles; ejecuta `account migrar` con ACCOUNT_MIGRATION_DATABASE_URL: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]bool, len(want))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		applied[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var missing []string
	for _, name := range want {
		if !applied[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("faltan migraciones %s; ejecuta `account migrar` con ACCOUNT_MIGRATION_DATABASE_URL", strings.Join(missing, ", "))
	}
	return nil
}

// Migrate aplica las migraciones embebidas que falten, en orden y cada una en
// su transacción, anotándolas en account.schema_migrations.
func (s *Store) Migrate(ctx context.Context) error {
	var current, session, owner string
	if err := s.pool.QueryRow(ctx, `select current_user, session_user, r.rolname
		from pg_namespace n join pg_roles r on r.oid=n.nspowner
		where n.nspname='account'`).Scan(&current, &session, &owner); err != nil {
		return fmt.Errorf("comprobar dueño de migraciones: %w", err)
	}
	if current != "account_migrator" || session != current || owner != "account_migrator" {
		return fmt.Errorf("migraciones requieren una sesión directa de account_migrator (actual %s, sesión %s, dueño %s)", current, session, owner)
	}
	if _, err := s.pool.Exec(ctx, `create table if not exists account.schema_migrations (
		version text primary key, applied_at timestamptz not null default now())`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	names, err := nombresMigraciones()
	if err != nil {
		return err
	}
	for _, name := range names {
		var ya bool
		if err := s.pool.QueryRow(ctx, `select exists(select 1 from account.schema_migrations where version=$1)`, name).Scan(&ya); err != nil {
			return err
		}
		if ya {
			continue
		}
		sql, err := migraciones.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migración %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `insert into account.schema_migrations(version) values ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ── Grupos ─────────────────────────────────────────────────────────────────

// TipoGrupo hace explícita la frontera entre herramientas que pueden pedirse y
// roles que sólo se conceden por una persona administradora.
type TipoGrupo string

const (
	TipoGrupoHerramienta TipoGrupo = "herramienta"
	TipoGrupoRol         TipoGrupo = "rol"
)

// Grupo es una herramienta o un rol al que se puede pertenecer.
type Grupo struct {
	Nombre      string
	Titulo      string
	Descripcion string
	URL         string
	Tipo        TipoGrupo
	ClienteID   string
	Solicitable bool
	Orden       int
}

// Host es el dominio de una herramienta, para enseñarlo como hace la web en
// sus tarjetas (secret.kaicorplabs.com); vacío cuando no hay URL.
func (g Grupo) Host() string {
	u, err := url.Parse(g.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

const grupoCols = `nombre, titulo, descripcion, url, tipo, coalesce(cliente_id::text,''), solicitable, orden`

func scanGrupo(row pgx.Row) (*Grupo, error) {
	var g Grupo
	if err := row.Scan(&g.Nombre, &g.Titulo, &g.Descripcion, &g.URL, &g.Tipo, &g.ClienteID, &g.Solicitable, &g.Orden); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoExiste
		}
		return nil, err
	}
	return &g, nil
}

// Grupos lista todos, por orden.
func (s *Store) Grupos(ctx context.Context) ([]Grupo, error) {
	rows, err := s.pool.Query(ctx, `select `+grupoCols+` from account.grupos order by orden, nombre`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grupo
	for rows.Next() {
		g, err := scanGrupo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// Grupo devuelve uno por nombre.
func (s *Store) Grupo(ctx context.Context, nombre string) (*Grupo, error) {
	return scanGrupo(s.pool.QueryRow(ctx, `select `+grupoCols+` from account.grupos where nombre=$1`, nombre))
}

// GrupoDeCliente devuelve el grupo que exige un cliente OAuth.
func (s *Store) GrupoDeCliente(ctx context.Context, clienteID string) (*Grupo, error) {
	return scanGrupo(s.pool.QueryRow(ctx, `select `+grupoCols+` from account.grupos where cliente_id=$1`, clienteID))
}

// ValidarGrupoAdministrador cierra el arranque si la membresía que abre /admin
// no es un rol existente y no solicitable. La denegación en SolicitarAcceso es
// independiente: esta comprobación detecta además una instalación insegura.
func (s *Store) ValidarGrupoAdministrador(ctx context.Context, nombre string) error {
	if nombre == "" {
		return errors.New("el grupo administrador no está configurado")
	}
	g, err := s.Grupo(ctx, nombre)
	if err != nil {
		if errors.Is(err, ErrNoExiste) {
			return fmt.Errorf("falta el grupo administrador %q", nombre)
		}
		return err
	}
	if g.Tipo != TipoGrupoRol {
		return fmt.Errorf("el grupo administrador %q debe ser de tipo rol", nombre)
	}
	if g.Solicitable {
		return fmt.Errorf("el grupo administrador %q no puede ser solicitable", nombre)
	}
	return nil
}

// VincularCliente ata un cliente OAuth a su grupo (o lo desata con "").
func (s *Store) VincularCliente(ctx context.Context, grupo, clienteID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// El bootstrap instala las guardas en auth, donde también escriben las
	// peticiones de GoTrue que terminan después de un timeout de HTTP.
	var guardas bool
	if err := tx.QueryRow(ctx, `select count(*)=8 from pg_trigger
		where not tgisinternal and tgenabled in ('O','A') and (
			(tgrelid='auth.oauth_consents'::regclass and tgname in
				('account_ordena_grants','account_valida_grants',
				 'account_sincroniza_consentimiento','account_valida_consentimiento'))
			or (tgrelid='auth.oauth_authorizations'::regclass and tgname in
				('account_sincroniza_consentimiento','account_valida_consentimiento'))
			or (tgrelid='auth.sessions'::regclass and tgname in
				('account_sincroniza_sesiones_oauth','account_valida_sesiones_oauth'))
		)`).Scan(&guardas); err != nil {
		return err
	}
	if !guardas {
		return errors.New("vincular: vuelve a aplicar db/bootstrap.sql antes de cambiar clientes")
	}
	// La fila común ordena cambios de vínculo y escrituras del proveedor.
	// Cambiar su versión también invalida snapshots Repeatable Read antiguos.
	tag, err := tx.Exec(ctx, `update account.estado_vinculos set version=version+1 where id`)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("vincular: falta el estado de vínculos")
	}
	var anterior string
	var tipo TipoGrupo
	if err := tx.QueryRow(ctx, `select coalesce(cliente_id::text,''), tipo from account.grupos where nombre=$1 for update`, grupo).Scan(&anterior, &tipo); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoExiste
		}
		return err
	}
	if tipo != TipoGrupoHerramienta {
		return errors.New("vincular: los roles no admiten clientes OAuth")
	}
	var cid *string
	if clienteID != "" {
		if err := tx.QueryRow(ctx, `select $1::uuid::text`, clienteID).Scan(&clienteID); err != nil {
			return err
		}
		cid = &clienteID
	}
	if anterior != clienteID && anterior != "" {
		if _, err := tx.Exec(ctx, `insert into account.clientes_anteriores(cliente_id) values ($1) on conflict do nothing`, anterior); err != nil {
			return err
		}
		// Todos los grants del cliente antiguo, incluso los de exmiembros.
		if _, err := tx.Exec(ctx, `update auth.oauth_consents set revoked_at=now() where client_id=$1 and revoked_at is null`, anterior); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update auth.oauth_authorizations set status='denied'
			where client_id=$1 and status='approved' and expires_at>now()`, anterior); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `delete from auth.sessions where oauth_client_id=$1`, anterior); err != nil {
			return err
		}
	}
	if anterior != clienteID {
		if _, err := tx.Exec(ctx, `update account.grupos set cliente_id=$2 where nombre=$1`, grupo, cid); err != nil {
			return err
		}
	}
	if clienteID != "" {
		// El vínculo sólo se publica al confirmar la transacción. Antes se
		// reconcilian códigos, grants y refresh tokens que el cliente ya tenía.
		if _, err := tx.Exec(ctx, `update auth.oauth_authorizations a set status='denied'
			where a.client_id=$1 and a.status='approved' and a.expires_at>now()
			and not exists (select 1 from account.membresias m
				where m.grupo=$2 and m.user_id=a.user_id)`, clienteID, grupo); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update auth.oauth_consents c set revoked_at=now()
			where c.client_id=$1 and c.revoked_at is null
			and not exists (select 1 from account.membresias m
				where m.grupo=$2 and m.user_id=c.user_id)`, clienteID, grupo); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `delete from auth.sessions s where s.oauth_client_id=$1
			and not exists (select 1 from account.membresias m
				where m.grupo=$2 and m.user_id=s.user_id)`, clienteID, grupo); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ── Membresías ─────────────────────────────────────────────────────────────

// Membresia es «esta persona pertenece a este grupo».
type Membresia struct {
	UserID string
	Grupo  string
	Desde  time.Time
	Por    string
}

// MembresiasDe lista los grupos de una persona.
func (s *Store) MembresiasDe(ctx context.Context, userID string) ([]Membresia, error) {
	rows, err := s.pool.Query(ctx, `select user_id::text, grupo, desde, por from account.membresias where user_id=$1 order by grupo`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membresia
	for rows.Next() {
		var m Membresia
		if err := rows.Scan(&m.UserID, &m.Grupo, &m.Desde, &m.Por); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// EsMiembro dice si la persona está en el grupo.
func (s *Store) EsMiembro(ctx context.Context, userID, grupo string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `select exists(select 1 from account.membresias where user_id=$1 and grupo=$2)`, userID, grupo).Scan(&ok)
	return ok, err
}

// Conceder da la membresía (idempotente).
func (s *Store) Conceder(ctx context.Context, userID, grupo, por string) error {
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `insert into account.membresias(user_id, grupo, por) values ($1,$2,$3)
		on conflict (user_id, grupo) do nothing`, userID, grupo, por); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Revocar quita la membresía y sus grants en una sola transacción; las guardas
// de la base ordenan también las aprobaciones del proveedor que sigan en vuelo.
func (s *Store) Revocar(ctx context.Context, userID, grupo string) error {
	b, err := s.bloquearAutoridad(ctx, userID)
	if err != nil {
		return err
	}
	defer b.cerrar()
	return s.revocarBajoAutoridad(ctx, userID, grupo, false)
}

// revocarBajoAutoridad se usa cuando el llamador ya conserva el bloqueo de
// autoridad del objetivo. Al retirar administración, avanza la generación en
// la misma transacción para invalidar cualquier orden que estuviera parada.
func (s *Store) revocarBajoAutoridad(ctx context.Context, userID, grupo string, invalidarAdmin bool) error {
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if invalidarAdmin {
		if err := avanzarAutoridadAdministrativa(ctx, tx, userID); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `delete from account.membresias where user_id=$1 and grupo=$2`, userID, grupo)
	if err != nil {
		return err
	}
	// El trigger por fila revoca al borrar. Si ya no había membresía, limpia
	// también grants históricos: repetir «revocar» sigue siendo idempotente.
	if tag.RowsAffected() == 0 {
		if _, err := tx.Exec(ctx, `update auth.oauth_consents set revoked_at=now()
			where user_id=$1 and revoked_at is null
			and client_id in (select cliente_id from account.grupos where nombre=$2)`, userID, grupo); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Miembro es una fila de membresía con el correo de auth.users.
type Miembro struct {
	UserID string
	Email  string
	Grupo  string
	Desde  time.Time
	Por    string
}

// MiembrosDe lista quién está en un grupo, con su correo.
func (s *Store) MiembrosDe(ctx context.Context, grupo string) ([]Miembro, error) {
	rows, err := s.pool.Query(ctx, `select m.user_id::text, coalesce(u.email,''), m.grupo, m.desde, m.por
		from account.membresias m left join auth.users u on u.id = m.user_id
		where m.grupo=$1 order by m.desde`, grupo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Miembro
	for rows.Next() {
		var m Miembro
		if err := rows.Scan(&m.UserID, &m.Email, &m.Grupo, &m.Desde, &m.Por); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ── Solicitudes ────────────────────────────────────────────────────────────

// Solicitud es una petición de acceso.
type Solicitud struct {
	ID       string
	UserID   string
	Email    string
	Grupo    string
	Estado   string
	Creada   time.Time
	Resuelta *time.Time
	Por      string
}

const solicitudCols = `s.id::text, s.user_id::text, coalesce(u.email,''), s.grupo, s.estado, s.creada, s.resuelta, coalesce(s.por,'')`

func scanSolicitudes(rows pgx.Rows) ([]Solicitud, error) {
	defer rows.Close()
	var out []Solicitud
	for rows.Next() {
		var x Solicitud
		if err := rows.Scan(&x.ID, &x.UserID, &x.Email, &x.Grupo, &x.Estado, &x.Creada, &x.Resuelta, &x.Por); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// CrearSolicitud registra una petición. Si ya había una pendiente para el
// mismo grupo, no crea otra y devuelve false: repetir no es ruido para nadie.
func (s *Store) CrearSolicitud(ctx context.Context, userID, grupo, estado, por string) (bool, error) {
	return crearSolicitud(ctx, s.pool, userID, grupo, estado, por)
}

// SolicitudesPendientes es la lista de trabajo de quien aprueba.
func (s *Store) SolicitudesPendientes(ctx context.Context) ([]Solicitud, error) {
	rows, err := s.pool.Query(ctx, `select `+solicitudCols+` from account.solicitudes s
		left join auth.users u on u.id = s.user_id where s.estado='pendiente' order by s.creada`)
	if err != nil {
		return nil, err
	}
	return scanSolicitudes(rows)
}

// SolicitudesDe lista las peticiones de una persona, recientes primero.
func (s *Store) SolicitudesDe(ctx context.Context, userID string) ([]Solicitud, error) {
	rows, err := s.pool.Query(ctx, `select `+solicitudCols+` from account.solicitudes s
		left join auth.users u on u.id = s.user_id where s.user_id=$1 order by s.creada desc limit 50`, userID)
	if err != nil {
		return nil, err
	}
	return scanSolicitudes(rows)
}

// Solicitud devuelve una por id.
func (s *Store) Solicitud(ctx context.Context, id string) (*Solicitud, error) {
	rows, err := s.pool.Query(ctx, `select `+solicitudCols+` from account.solicitudes s
		left join auth.users u on u.id = s.user_id where s.id=$1`, id)
	if err != nil {
		return nil, err
	}
	xs, err := scanSolicitudes(rows)
	if err != nil {
		return nil, err
	}
	if len(xs) == 0 {
		return nil, ErrNoExiste
	}
	return &xs[0], nil
}

// ResolverSolicitud la marca aprobada o rechazada.
func (s *Store) ResolverSolicitud(ctx context.Context, id, estado, por string) error {
	tag, err := s.pool.Exec(ctx, `update account.solicitudes set estado=$2, resuelta=now(), por=$3
		where id=$1 and estado='pendiente'`, id, estado, por)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoExiste
	}
	return nil
}

// ── Sesiones de esta app ───────────────────────────────────────────────────

// Sesion es una sesión de la app: envuelve los tokens de GoTrue, cifrados.
type Sesion struct {
	ID           string
	Referencia   string // Identidad estable de la fila, nunca un portador.
	UserID       string
	Email        string
	Nombre       string
	AAL          string
	AccessToken  []byte
	RefreshToken []byte
	AccessExpira time.Time
	Creada       time.Time
	Ultima       time.Time
	Expira       time.Time
	Agente       string
	Emitido      int64 // iat del access token; sólo se usa al insertar.
	Revocacion   int64 // Generación durable de cierre; la base la fija al insertar.
}

const sesionCols = `s.id, s.user_id::text, s.email, s.nombre, s.aal, s.access_token, s.refresh_token, s.access_expira, s.creada, s.ultima, s.expira, s.agente, s.referencia::text, s.revocacion_generacion`

func scanSesion(row pgx.Row) (*Sesion, error) {
	var x Sesion
	err := row.Scan(&x.ID, &x.UserID, &x.Email, &x.Nombre, &x.AAL, &x.AccessToken, &x.RefreshToken, &x.AccessExpira, &x.Creada, &x.Ultima, &x.Expira, &x.Agente, &x.Referencia, &x.Revocacion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoExiste
		}
		return nil, err
	}
	return &x, nil
}

const salBloqueoSesiones int64 = 0x4b414943 // "KAIC"

func bloquearSesionesPersona(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1::uuid::text,$2))`, userID, salBloqueoSesiones)
	return err
}

func corteCredencial(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	var corte int64
	err := tx.QueryRow(ctx, `select coalesce((select no_antes from account.cortes_credencial where user_id=$1),0)`, userID).Scan(&corte)
	return corte, err
}

func estadoCredencial(ctx context.Context, tx pgx.Tx, userID string) (int64, int64, error) {
	var corte, generacion int64
	err := tx.QueryRow(ctx, `select coalesce((select no_antes from account.cortes_credencial where user_id=$1),0),
		coalesce((select generacion from account.cortes_credencial where user_id=$1),0)`, userID).Scan(&corte, &generacion)
	return corte, generacion, err
}

func estadoRevocacionSesiones(ctx context.Context, tx pgx.Tx, userID string) (int64, int64, error) {
	var corte, generacion int64
	err := tx.QueryRow(ctx, `select
		coalesce((select sesiones_no_antes from account.cortes_credencial where user_id=$1),0),
		coalesce((select sesiones_generacion from account.cortes_credencial where user_id=$1),0)`, userID).
		Scan(&corte, &generacion)
	return corte, generacion, err
}

func generacionRevocacionParaSesion(ctx context.Context, tx pgx.Tx, userID string, emitido int64) (int64, error) {
	corte, generacion, err := estadoRevocacionSesiones(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if corte > 0 && !credencialVigente(corte, emitido) {
		return 0, ErrCredencialAnterior
	}
	return generacion, nil
}

// revocarSesionesLocalesTx establece primero la frontera durable y borra las
// filas bajo el mismo bloqueo por persona. Es idempotente: cada reintento crea
// una generación posterior y vuelve a intentar la limpieza física. La espera
// devuelta separa el último segundo revocado del primer iat que el llamador
// puede aceptar después de anunciar el cierre.
func revocarSesionesLocalesTx(ctx context.Context, tx pgx.Tx, userID string) (time.Duration, error) {
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return 0, err
	}
	var corte int64
	if err := tx.QueryRow(ctx, `insert into account.cortes_credencial
			(user_id,no_antes,sesiones_no_antes,sesiones_generacion)
		values ($1,0,extract(epoch from clock_timestamp())::bigint,1)
		on conflict (user_id) do update set
			sesiones_no_antes=greatest(account.cortes_credencial.sesiones_no_antes,excluded.sesiones_no_antes),
				sesiones_generacion=account.cortes_credencial.sesiones_generacion+1
			returning sesiones_no_antes`, userID).Scan(&corte); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `delete from account.sesiones where user_id=$1`, userID); err != nil {
		return 0, err
	}
	var reloj time.Time
	if err := tx.QueryRow(ctx, `select clock_timestamp()`).Scan(&reloj); err != nil {
		return 0, err
	}
	return time.Unix(corte+1, 0).Sub(reloj), nil
}

func esperarEmisionPosterior(ctx context.Context, espera time.Duration) error {
	if espera <= 0 {
		return nil
	}
	t := time.NewTimer(espera)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func avanzarCorteCredencial(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `insert into account.cortes_credencial(user_id,no_antes)
		values ($1,extract(epoch from clock_timestamp())::bigint)
		on conflict (user_id) do update set no_antes=greatest(account.cortes_credencial.no_antes,excluded.no_antes)`, userID)
	return err
}

func avanzarGeneracionCredencial(ctx context.Context, tx pgx.Tx, userID string, emitido int64) (int64, error) {
	var generacion int64
	err := tx.QueryRow(ctx, `insert into account.cortes_credencial(user_id,no_antes,generacion)
		values ($1,greatest(extract(epoch from clock_timestamp())::bigint,$2),1)
		on conflict (user_id) do update set
			no_antes=greatest(account.cortes_credencial.no_antes,excluded.no_antes),
			generacion=account.cortes_credencial.generacion+1
		returning generacion`, userID, emitido).Scan(&generacion)
	return generacion, err
}

func credencialVigente(corte, emitido int64) bool {
	return emitido > 0 && emitido > corte
}

func autoridadCredencialVigente(corte, generacionActual, emitido int64, generacionEsperada *int64) bool {
	if generacionEsperada != nil {
		return generacionActual == *generacionEsperada
	}
	return credencialVigente(corte, emitido)
}

// GeneracionCredencial toma una instantánea serializada de la autoridad de
// contraseña. Las intenciones de recuperación guardan este valor antes de
// mandar el correo, de modo que un cambio posterior invalida incluso un enlace
// cuyo canje haga que el proveedor emita un JWT nuevo.
func (s *Store) GeneracionCredencial(ctx context.Context, userID string) (int64, error) {
	if userID == "" {
		return 0, errors.New("identidad de credencial vacía")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return 0, err
	}
	_, generacion, err := estadoCredencial(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return generacion, nil
}

// ComprobarCredencial serializa la validación de una capacidad MFA con los
// cambios de contraseña. La capacidad conserva su iat original: verificar el
// factor no puede rejuvenecer autoridad emitida antes del último cambio.
func (s *Store) ComprobarCredencial(ctx context.Context, userID string, emitido int64, generacionEsperada *int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return err
	}
	corte, generacion, err := estadoCredencial(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !autoridadCredencialVigente(corte, generacion, emitido, generacionEsperada) {
		return ErrCredencialAnterior
	}
	return tx.Commit(ctx)
}

// CambiarCredencial conserva el bloqueo por persona desde la comprobación del
// iat hasta que termina el PUT remoto. El callback indica si un error es
// ambiguo y debe invalidar igualmente; los 4xx conocidos pueden dejar la misma
// capacidad disponible para corregir la contraseña y reintentar.
func (s *Store) CambiarCredencial(ctx context.Context, userID string, emitido int64, generacionEsperada *int64, cambiar func() (invalidar bool, err error)) (int64, error) {
	if userID == "" || cambiar == nil {
		return 0, errors.New("cambio de credencial incompleto")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return 0, err
	}
	corte, generacionActual, err := estadoCredencial(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if !autoridadCredencialVigente(corte, generacionActual, emitido, generacionEsperada) {
		return 0, ErrCredencialAnterior
	}
	invalidar, cambioErr := cambiar()
	if cambioErr != nil && !invalidar {
		return 0, cambioErr
	}
	// El proveedor puede haber aceptado el PUT justo cuando el navegador
	// canceló la petición. Desde ese punto el corte local debe sobrevivir al
	// contexto del cliente; de lo contrario la credencial antigua reaparecería.
	ctxSeguridad, cancelar := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelar()
	generacion, err := avanzarGeneracionCredencial(ctxSeguridad, tx, userID, emitido)
	if err != nil {
		return 0, errors.Join(cambioErr, err)
	}
	if err := tx.Commit(ctxSeguridad); err != nil {
		return 0, errors.Join(cambioErr, err)
	}
	return generacion, cambioErr
}

// CambiarCredencialAdministrativa aplica el mismo bloqueo a las rotaciones que
// usa la preparación de altas e invitaciones. No hay una autoridad previa que
// comprobar: la llamada administrativa existe precisamente para sustituir una
// contraseña pendiente que ninguna persona debe conocer.
func (s *Store) CambiarCredencialAdministrativa(ctx context.Context, userID string, cambiar func() error) (int64, error) {
	if userID == "" || cambiar == nil {
		return 0, errors.New("cambio administrativo de credencial incompleto")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return 0, err
	}
	cambioErr := cambiar()
	ctxSeguridad, cancelar := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelar()
	generacion, err := avanzarGeneracionCredencial(ctxSeguridad, tx, userID, time.Now().Unix())
	if err != nil {
		return 0, errors.Join(cambioErr, err)
	}
	if err := tx.Commit(ctxSeguridad); err != nil {
		return 0, errors.Join(cambioErr, err)
	}
	return generacion, cambioErr
}

func comprobarGeneracionCredencial(ctx context.Context, tx pgx.Tx, userID string, generacion int64) error {
	if generacion <= 0 {
		return ErrCredencialAnterior
	}
	_, actual, err := estadoCredencial(ctx, tx, userID)
	if err != nil {
		return err
	}
	if actual != generacion {
		return ErrCredencialAnterior
	}
	return nil
}

// CrearSesion guarda una sesión nueva bajo el mismo bloqueo por persona que
// usan los cambios de contraseña. Una ficha anterior al último corte no puede
// aparecer después de que la limpieza haya terminado.
func (s *Store) CrearSesion(ctx context.Context, x *Sesion) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := bloquearSesionesPersona(ctx, tx, x.UserID); err != nil {
		return err
	}
	corte, err := corteCredencial(ctx, tx, x.UserID)
	if err != nil {
		return err
	}
	if corte > 0 && (x.Emitido == 0 || x.Emitido <= corte) {
		return ErrCredencialAnterior
	}
	x.Revocacion, err = generacionRevocacionParaSesion(ctx, tx, x.UserID, x.Emitido)
	if err != nil {
		return err
	}
	if err := insertarSesion(ctx, tx, x); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CrearSesionUnica guarda la sesión nueva y elimina las demás filas de la
// persona en una sola transacción. Si la limpieza falla, la sesión nueva no se
// publica.
func (s *Store) CrearSesionUnica(ctx context.Context, x *Sesion) error {
	return s.crearSesionUnica(ctx, x, 0)
}

// CrearSesionUnicaEnGeneracion sólo publica la sesión producida por la última
// mutación de contraseña confirmada.
func (s *Store) CrearSesionUnicaEnGeneracion(ctx context.Context, x *Sesion, generacion int64) error {
	return s.crearSesionUnica(ctx, x, generacion)
}

func (s *Store) crearSesionUnica(ctx context.Context, x *Sesion, generacion int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := bloquearSesionesPersona(ctx, tx, x.UserID); err != nil {
		return err
	}
	if generacion > 0 {
		if err := comprobarGeneracionCredencial(ctx, tx, x.UserID, generacion); err != nil {
			return err
		}
	}
	x.Revocacion, err = generacionRevocacionParaSesion(ctx, tx, x.UserID, x.Emitido)
	if err != nil {
		return err
	}
	if err := insertarSesion(ctx, tx, x); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `delete from account.sesiones where user_id=$1 and referencia::text<>$2`, x.UserID, x.Referencia); err != nil {
		return err
	}
	if err := avanzarCorteCredencial(ctx, tx, x.UserID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertarSesion(ctx context.Context, tx pgx.Tx, x *Sesion) error {
	if x.Referencia == "" {
		return tx.QueryRow(ctx, `insert into account.sesiones(id, user_id, email, nombre, aal, access_token, refresh_token, access_expira, expira, agente, revocacion_generacion)
			values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning referencia::text`,
			x.ID, x.UserID, x.Email, x.Nombre, x.AAL, x.AccessToken, x.RefreshToken, x.AccessExpira, x.Expira, x.Agente, x.Revocacion).Scan(&x.Referencia)
	}
	return tx.QueryRow(ctx, `insert into account.sesiones(id, referencia, user_id, email, nombre, aal, access_token, refresh_token, access_expira, expira, agente, revocacion_generacion)
		values ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) returning referencia::text`,
		x.ID, x.Referencia, x.UserID, x.Email, x.Nombre, x.AAL, x.AccessToken, x.RefreshToken, x.AccessExpira, x.Expira, x.Agente, x.Revocacion).Scan(&x.Referencia)
}

// Sesion lee una por id.
func (s *Store) Sesion(ctx context.Context, id string) (*Sesion, error) {
	return scanSesion(s.pool.QueryRow(ctx, `select `+sesionCols+` from account.sesiones s
		left join account.cortes_credencial c on c.user_id=s.user_id
		where s.id=$1 and s.revocacion_generacion=coalesce(c.sesiones_generacion,0)`, id))
}

// ActualizarTokens renueva tokens sin cambiar el portador ni su nivel.
func (s *Store) ActualizarTokens(ctx context.Context, id string, access, refresh []byte, accessExpira time.Time) error {
	var actualizadas int64
	if err := s.pool.QueryRow(ctx, `select account.actualizar_tokens_sesion($1,$2,$3,$4)`,
		id, access, refresh, accessExpira).Scan(&actualizadas); err != nil {
		return err
	}
	if actualizadas == 0 {
		return ErrNoExiste
	}
	return nil
}

// ReautenticarSesion rota el portador, instala los tokens de una prueba de
// identidad reciente y elimina las demás sesiones en una transacción.
func (s *Store) ReautenticarSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time) (time.Time, error) {
	return s.reautenticarSesion(ctx, id, nuevoID, access, refresh, accessExpira, 0, "")
}

// ReautenticarSesionComo cambia también el AAL después de una mutación de los
// factores y elimina las demás sesiones dentro de la misma transacción.
func (s *Store) ReautenticarSesionComo(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time, aal string) (time.Time, error) {
	if aal != "aal1" && aal != "aal2" {
		return time.Time{}, errors.New("AAL de reautenticación inválido")
	}
	return s.reautenticarSesion(ctx, id, nuevoID, access, refresh, accessExpira, 0, aal)
}

// ReautenticarSesionEnGeneracion liga la sesión resultante al último cambio.
func (s *Store) ReautenticarSesionEnGeneracion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time, generacion int64) (time.Time, error) {
	return s.reautenticarSesion(ctx, id, nuevoID, access, refresh, accessExpira, generacion, "")
}

func (s *Store) reautenticarSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time, generacion int64, aal string) (time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var userID string
	if err := tx.QueryRow(ctx, `select user_id::text from account.sesiones where id=$1 and expira>now()`, id).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	} else if err != nil {
		return time.Time{}, err
	}
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return time.Time{}, err
	}
	if generacion > 0 {
		if err := comprobarGeneracionCredencial(ctx, tx, userID, generacion); err != nil {
			return time.Time{}, err
		}
	}
	var expira time.Time
	var referencia string
	err = tx.QueryRow(ctx, `select expira,user_id,referencia from account.rotar_sesion($1,$2,$3,$4,$5,$6)`,
		id, nuevoID, access, refresh, accessExpira, aal).
		Scan(&expira, &userID, &referencia)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	}
	if err != nil {
		return time.Time{}, err
	}
	if _, err := tx.Exec(ctx, `delete from account.sesiones where user_id=$1 and referencia::text<>$2`, userID, referencia); err != nil {
		return time.Time{}, err
	}
	if err := avanzarCorteCredencial(ctx, tx, userID); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return expira, nil
}

// RotarPortadorSesion invalida copias de la cookie y elimina las demás sesiones
// de la persona dentro de la misma transacción.
func (s *Store) RotarPortadorSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time) (time.Time, error) {
	return s.rotarPortadorSesion(ctx, id, nuevoID, access, refresh, accessExpira, 0)
}

// RotarPortadorSesionEnGeneracion liga la rotación a la última contraseña.
func (s *Store) RotarPortadorSesionEnGeneracion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time, generacion int64) (time.Time, error) {
	return s.rotarPortadorSesion(ctx, id, nuevoID, access, refresh, accessExpira, generacion)
}

func (s *Store) rotarPortadorSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time, generacion int64) (time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var userID string
	if err := tx.QueryRow(ctx, `select user_id::text from account.sesiones where id=$1 and expira>now()`, id).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	} else if err != nil {
		return time.Time{}, err
	}
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return time.Time{}, err
	}
	if generacion > 0 {
		if err := comprobarGeneracionCredencial(ctx, tx, userID, generacion); err != nil {
			return time.Time{}, err
		}
	}
	var expira time.Time
	var referencia string
	err = tx.QueryRow(ctx, `select expira,user_id,referencia from account.rotar_sesion($1,$2,$3,$4,$5,'')`,
		id, nuevoID, access, refresh, accessExpira).
		Scan(&expira, &userID, &referencia)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	}
	if err != nil {
		return time.Time{}, err
	}
	if _, err := tx.Exec(ctx, `delete from account.sesiones where user_id=$1 and referencia::text<>$2`, userID, referencia); err != nil {
		return time.Time{}, err
	}
	if err := avanzarCorteCredencial(ctx, tx, userID); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return expira, nil
}

// PromoverSesion sustituye el portador y sus tokens y cierra las demás sesiones
// sin factor de la cuenta en la misma transacción.
// Una petición con el id anterior no puede leer los tokens aal2 ni recrear la
// fila. Se conservan la caducidad absoluta y el resto de datos de la sesión.
func (s *Store) PromoverSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time) (time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var userID string
	if err := tx.QueryRow(ctx, `select user_id::text from account.sesiones where id=$1 and expira>now()`, id).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	} else if err != nil {
		return time.Time{}, err
	}
	if err := bloquearSesionesPersona(ctx, tx, userID); err != nil {
		return time.Time{}, err
	}
	var expira time.Time
	err = tx.QueryRow(ctx, `select expira,user_id from account.rotar_sesion($1,$2,$3,$4,$5,'aal2')`,
		id, nuevoID, access, refresh, accessExpira).Scan(&expira, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoExiste
	}
	if err != nil {
		return time.Time{}, err
	}
	if _, err := tx.Exec(ctx, `delete from account.sesiones where user_id=$1 and id<>$2 and aal<>'aal2'`, userID, nuevoID); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return expira, nil
}

// TocarSesion anota actividad.
func (s *Store) TocarSesion(ctx context.Context, id string) error {
	var actualizadas int64
	return s.pool.QueryRow(ctx, `select account.tocar_sesion($1)`, id).Scan(&actualizadas)
}

// BorrarSesion elimina una.
func (s *Store) BorrarSesion(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `delete from account.sesiones where id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoExiste
	}
	return nil
}

// BorrarSesionPorReferencia cierra también una sesión cuyo portador haya rotado
// desde que la petición de cierre la cargó.
func (s *Store) BorrarSesionPorReferencia(ctx context.Context, referencia string) error {
	_, err := s.pool.Exec(ctx, `delete from account.sesiones where referencia=$1::uuid`, referencia)
	return err
}

// BorrarSesionesDe elimina todas las de una persona, salvo la referencia estable
// dada, si se pasa. El id de cookie no identifica la misma fila tras promoverla.
func (s *Store) BorrarSesionesDe(ctx context.Context, userID, salvoReferencia string) error {
	_, err := s.pool.Exec(ctx, `delete from account.sesiones where user_id=$1 and referencia::text<>$2`, userID, salvoReferencia)
	return err
}

// SesionesDe lista las sesiones de la app de una persona.
func (s *Store) SesionesDe(ctx context.Context, userID string) ([]Sesion, error) {
	rows, err := s.pool.Query(ctx, `select `+sesionCols+` from account.sesiones s
		left join account.cortes_credencial c on c.user_id=s.user_id
		where s.user_id=$1 and s.expira>now()
		and s.revocacion_generacion=coalesce(c.sesiones_generacion,0)
		order by s.ultima desc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sesion
	for rows.Next() {
		x, err := scanSesion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// ActualizarCorreoSesiones pone el correo nuevo en todas las sesiones vivas de
// una persona: la barra lo enseña, y sin esto seguiría el viejo hasta re-entrar.
func (s *Store) ActualizarCorreoSesiones(ctx context.Context, userID, email string) error {
	var actualizadas int64
	return s.pool.QueryRow(ctx, `select account.actualizar_correo_sesiones($1,$2)`, userID, email).Scan(&actualizadas)
}

// PurgarSesiones borra las caducadas.
func (s *Store) PurgarSesiones(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `delete from account.sesiones where expira<now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ── Lecturas y escrituras acotadas sobre el esquema auth ───────────────────

// ClienteDeAutorizacion dice qué cliente OAuth pide una autorización. Hace
// falta ANTES de pedirle a GoTrue los detalles, porque esa llamada aprueba
// sola si la persona ya tiene grant y aquí la política va primero.
func (s *Store) ClienteDeAutorizacion(ctx context.Context, authorizationID string) (string, error) {
	var cid string
	err := s.pool.QueryRow(ctx, `select client_id::text from auth.oauth_authorizations
		where authorization_id=$1 and status='pending' and expires_at>now()`, authorizationID).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoExiste
	}
	return cid, err
}

// Cliente es un cliente OAuth registrado en GoTrue.
type Cliente struct {
	ID     string
	Nombre string
	URI    string
}

// Clientes lista los clientes OAuth vivos, para vincularlos a grupos.
func (s *Store) Clientes(ctx context.Context) ([]Cliente, error) {
	rows, err := s.pool.Query(ctx, `select id::text, coalesce(client_name,''), coalesce(client_uri,'') from auth.oauth_clients where deleted_at is null order by client_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cliente
	for rows.Next() {
		var c Cliente
		if err := rows.Scan(&c.ID, &c.Nombre, &c.URI); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevocarGrants deja sin efecto las autorizaciones de una persona a un
// cliente: GoTrue deja de aprobar solo, y sus refresh tokens dejan de valer.
func (s *Store) RevocarGrants(ctx context.Context, userID, clienteID string) error {
	_, err := s.pool.Exec(ctx, `update auth.oauth_consents set revoked_at=now()
		where user_id=$1 and client_id=$2 and revoked_at is null`, userID, clienteID)
	return err
}

// CerrarSesionesGoTrue mata todas las sesiones del proveedor de una persona:
// ningún refresh token vuelve a valer, para ninguna app.
func (s *Store) CerrarSesionesGoTrue(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `delete from auth.sessions where user_id=$1`, userID)
	return err
}

// RevocarSesiones es la única frontera para un cierre administrativo global.
// Intenta primero retirar las sesiones del proveedor y, aunque eso falle,
// confirma después el corte durable y la limpieza local bajo el bloqueo por
// persona. Repetir la operación es seguro y vuelve a intentar ambos borrados.
func (s *Store) RevocarSesiones(ctx context.Context, userID string) error {
	b, err := s.bloquearAutoridad(ctx, userID)
	if err != nil {
		return err
	}
	defer b.cerrar()
	if err := avanzarAutoridadAdministrativa(ctx, b.conn, userID); err != nil {
		return err
	}
	return s.revocarSesionesBajoAutoridad(ctx, userID)
}

func (s *Store) revocarSesionesBajoAutoridad(ctx context.Context, userID string) error {
	errProveedor := s.CerrarSesionesGoTrue(ctx, userID)
	if errProveedor != nil {
		errProveedor = fmt.Errorf("cerrar sesiones del proveedor: %w", errProveedor)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return errors.Join(errProveedor, fmt.Errorf("iniciar revocación de sesiones locales: %w", err))
	}
	defer tx.Rollback(context.Background())
	espera, errLocal := revocarSesionesLocalesTx(ctx, tx, userID)
	if errLocal == nil {
		errLocal = tx.Commit(ctx)
	}
	if errLocal == nil {
		errLocal = esperarEmisionPosterior(ctx, espera)
	}
	if errLocal != nil {
		errLocal = fmt.Errorf("cerrar sesiones locales: %w", errLocal)
	}
	return errors.Join(errProveedor, errLocal)
}

// Usuario es lo que /admin enseña de una cuenta.
type Usuario struct {
	ID         string
	Email      string
	Creada     time.Time
	UltimaEntr *time.Time
	Confirmada bool
	Bloqueada  bool
	Nombre     string
	// Invitada es cuándo se le mandó la invitación, si llegó por ahí. Se enseña
	// en /admin para que quien administra sepa de cuándo es el enlace que esa
	// persona tiene en el correo: sin ese dato, «sin confirmar» no dice si hace
	// falta reenviar o si acaba de invitarse. Nil = se registró por su cuenta.
	Invitada *time.Time
}

// UsuarioPorCorreo busca una cuenta por correo (exacto, sin distinguir mayúsculas).
func (s *Store) UsuarioPorCorreo(ctx context.Context, email string) (*Usuario, error) {
	return scanUsuario(s.pool.QueryRow(ctx, usuarioSelect+` where lower(u.email)=lower($1) and u.deleted_at is null`, email))
}

// UsuarioPorID busca una cuenta por id.
func (s *Store) UsuarioPorID(ctx context.Context, id string) (*Usuario, error) {
	return scanUsuario(s.pool.QueryRow(ctx, usuarioSelect+` where u.id=$1 and u.deleted_at is null`, id))
}

const usuarioSelect = `select u.id::text, coalesce(u.email,''), u.created_at, u.last_sign_in_at,
	u.email_confirmed_at is not null, coalesce(u.banned_until > now(), false),
	coalesce(u.raw_user_meta_data->>'name',''), u.invited_at from auth.users u`

func scanUsuario(row pgx.Row) (*Usuario, error) {
	var u Usuario
	if err := row.Scan(&u.ID, &u.Email, &u.Creada, &u.UltimaEntr, &u.Confirmada, &u.Bloqueada, &u.Nombre, &u.Invitada); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoExiste
		}
		return nil, err
	}
	return &u, nil
}

// Usuarios lista cuentas, con filtro opcional por correo.
func (s *Store) Usuarios(ctx context.Context, filtro string, limite int) ([]Usuario, error) {
	if limite <= 0 || limite > 200 {
		limite = 100
	}
	rows, err := s.pool.Query(ctx, usuarioSelect+` where u.deleted_at is null and ($1='' or u.email ilike '%'||$1||'%')
		order by u.created_at desc limit $2`, filtro, limite)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usuario
	for rows.Next() {
		u, err := scanUsuario(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// ── Purga y borrado ────────────────────────────────────────────────────────

// SinConfirmar lista las cuentas que se registraron solas, nunca confirmaron
// el correo y son anteriores a `antes`. Las invitadas quedan fuera: la
// invitación la decidió una persona, y si caduca se reenvía, no se purga.
func (s *Store) SinConfirmar(ctx context.Context, antes time.Time) ([]Usuario, error) {
	rows, err := s.pool.Query(ctx, usuarioSelect+` where u.deleted_at is null and u.email_confirmed_at is null
		and u.invited_at is null and u.created_at < $1 order by u.created_at`, antes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usuario
	for rows.Next() {
		u, err := scanUsuario(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// Rastro es lo que hay de una persona, contado antes de borrarlo: lo de esta
// app y, aparte, lo del proveedor que el borrado de la cuenta se lleva.
type Rastro struct {
	Membresias, Solicitudes, Sesiones, IntentosPassword int64
	Grants, SesionesProveedor                           int64
}

// RastroDe cuenta el rastro de una persona.
func (s *Store) RastroDe(ctx context.Context, userID string) (Rastro, error) {
	var r Rastro
	err := s.pool.QueryRow(ctx, `select
		(select count(*) from account.membresias where user_id=$1::uuid),
		(select count(*) from account.solicitudes where user_id=$1::uuid),
		(select count(*) from account.sesiones where user_id=$1::uuid),
		(select count(*) from account.intentos_password where tipo='usuario' and sujeto=$1::text),
		(select count(*) from auth.oauth_consents where user_id=$1::uuid and revoked_at is null),
		(select count(*) from auth.sessions where user_id=$1::uuid)`, userID).
		Scan(&r.Membresias, &r.Solicitudes, &r.Sesiones, &r.IntentosPassword, &r.Grants, &r.SesionesProveedor)
	return r, err
}

// BorrarRastro borra lo que esta app guarda de una persona, en una transacción.
// La cuenta en el proveedor es aparte (gotrue.AdminDeleteUser) y va después:
// primero lo que apunta a ella, luego ella.
func (s *Store) BorrarRastro(ctx context.Context, userID string) error {
	b, err := s.bloquearAutoridad(ctx, userID)
	if err != nil {
		return err
	}
	defer b.cerrar()
	tx, err := s.transaccionMembresias(ctx, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := avanzarAutoridadAdministrativa(ctx, tx, userID); err != nil {
		return err
	}
	for _, q := range []string{
		`delete from account.intentos_password where tipo='usuario' and sujeto=$1`,
		`delete from account.sesiones where user_id=$1`,
		`delete from account.solicitudes where user_id=$1`,
		`delete from account.membresias where user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// PurgarHuerfanos quita las filas de la app cuya cuenta ya no existe en el
// proveedor (borrada con la API de administración sin pasar por aquí).
func (s *Store) PurgarHuerfanos(ctx context.Context) (int64, error) {
	var total int64
	ct, err := s.pool.Exec(ctx, `delete from account.intentos_password i
		where i.tipo='usuario' and not exists(select 1 from auth.users u where u.id::text=i.sujeto)`)
	if err != nil {
		return total, err
	}
	total += ct.RowsAffected()
	for _, t := range []string{"account.sesiones", "account.solicitudes", "account.membresias"} {
		ct, err := s.pool.Exec(ctx, `delete from `+t+` where user_id not in (select id from auth.users)`)
		if err != nil {
			return total, err
		}
		total += ct.RowsAffected()
	}
	return total, nil
}
