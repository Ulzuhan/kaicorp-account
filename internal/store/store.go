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
	pool *pgxpool.Pool
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
	return &Store{pool: pool}, nil
}

// Close cierra el pool.
func (s *Store) Close() { s.pool.Close() }

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

// Grupo es una herramienta o un rol al que se puede pertenecer.
type Grupo struct {
	Nombre      string
	Titulo      string
	Descripcion string
	URL         string
	ClienteID   string
	Solicitable bool
	Orden       int
}

// Host es el dominio de la herramienta, para enseñarlo como hace la web en
// sus tarjetas (secret.kaicorplabs.com); vacío para los roles sin URL.
func (g Grupo) Host() string {
	u, err := url.Parse(g.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

const grupoCols = `nombre, titulo, descripcion, url, coalesce(cliente_id::text,''), solicitable, orden`

func scanGrupo(row pgx.Row) (*Grupo, error) {
	var g Grupo
	if err := row.Scan(&g.Nombre, &g.Titulo, &g.Descripcion, &g.URL, &g.ClienteID, &g.Solicitable, &g.Orden); err != nil {
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
	if err := tx.QueryRow(ctx, `select count(*)=2 from pg_trigger
		where tgrelid='auth.oauth_consents'::regclass and not tgisinternal
		and tgname in ('account_ordena_grants','account_valida_grants')
		and tgenabled in ('O','A')`).Scan(&guardas); err != nil {
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
	if err := tx.QueryRow(ctx, `select coalesce(cliente_id::text,'') from account.grupos where nombre=$1 for update`, grupo).Scan(&anterior); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoExiste
		}
		return err
	}
	var cid *string
	if clienteID != "" {
		if err := tx.QueryRow(ctx, `select $1::uuid::text`, clienteID).Scan(&clienteID); err != nil {
			return err
		}
		cid = &clienteID
	}
	if anterior == clienteID {
		return tx.Commit(ctx)
	}
	if anterior != "" {
		if _, err := tx.Exec(ctx, `insert into account.clientes_anteriores(cliente_id) values ($1) on conflict do nothing`, anterior); err != nil {
			return err
		}
		// Todos los grants del cliente antiguo, incluso los de exmiembros.
		if _, err := tx.Exec(ctx, `update auth.oauth_consents set revoked_at=now() where client_id=$1 and revoked_at is null`, anterior); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `update account.grupos set cliente_id=$2 where nombre=$1`, grupo, cid); err != nil {
		return err
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
	_, err := s.pool.Exec(ctx, `insert into account.membresias(user_id, grupo, por) values ($1,$2,$3)
		on conflict (user_id, grupo) do nothing`, userID, grupo, por)
	return err
}

// Revocar quita la membresía y sus grants en una sola transacción; las guardas
// de la base ordenan también las aprobaciones del proveedor que sigan en vuelo.
func (s *Store) Revocar(ctx context.Context, userID, grupo string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
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
	var resuelta *time.Time
	var p *string
	if estado != "pendiente" {
		now := time.Now()
		resuelta = &now
		if por != "" {
			p = &por
		}
	}
	tag, err := s.pool.Exec(ctx, `insert into account.solicitudes(user_id, grupo, estado, resuelta, por)
		values ($1,$2,$3,$4,$5)
		on conflict (user_id, grupo) where estado='pendiente' do nothing`, userID, grupo, estado, resuelta, p)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
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
}

const sesionCols = `id, user_id::text, email, nombre, aal, access_token, refresh_token, access_expira, creada, ultima, expira, agente, referencia::text`

func scanSesion(row pgx.Row) (*Sesion, error) {
	var x Sesion
	err := row.Scan(&x.ID, &x.UserID, &x.Email, &x.Nombre, &x.AAL, &x.AccessToken, &x.RefreshToken, &x.AccessExpira, &x.Creada, &x.Ultima, &x.Expira, &x.Agente, &x.Referencia)
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
	_, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,$2))`, userID, salBloqueoSesiones)
	return err
}

func corteCredencial(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	var corte int64
	err := tx.QueryRow(ctx, `select coalesce((select no_antes from account.cortes_credencial where user_id=$1),0)`, userID).Scan(&corte)
	return corte, err
}

func avanzarCorteCredencial(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `insert into account.cortes_credencial(user_id,no_antes)
		values ($1,extract(epoch from clock_timestamp())::bigint)
		on conflict (user_id) do update set no_antes=greatest(account.cortes_credencial.no_antes,excluded.no_antes)`, userID)
	return err
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
	if err := tx.QueryRow(ctx, `insert into account.sesiones(id, user_id, email, nombre, aal, access_token, refresh_token, access_expira, expira, agente)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning referencia::text`,
		x.ID, x.UserID, x.Email, x.Nombre, x.AAL, x.AccessToken, x.RefreshToken, x.AccessExpira, x.Expira, x.Agente).Scan(&x.Referencia); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CrearSesionUnica guarda la sesión nueva y elimina las demás filas de la
// persona en una sola transacción. Si la limpieza falla, la sesión nueva no se
// publica.
func (s *Store) CrearSesionUnica(ctx context.Context, x *Sesion) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := bloquearSesionesPersona(ctx, tx, x.UserID); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `insert into account.sesiones(id, user_id, email, nombre, aal, access_token, refresh_token, access_expira, expira, agente)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning referencia::text`,
		x.ID, x.UserID, x.Email, x.Nombre, x.AAL, x.AccessToken, x.RefreshToken, x.AccessExpira, x.Expira, x.Agente).Scan(&x.Referencia); err != nil {
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

// Sesion lee una por id.
func (s *Store) Sesion(ctx context.Context, id string) (*Sesion, error) {
	return scanSesion(s.pool.QueryRow(ctx, `select `+sesionCols+` from account.sesiones where id=$1`, id))
}

// ActualizarTokens renueva tokens sin cambiar el portador ni su nivel.
func (s *Store) ActualizarTokens(ctx context.Context, id string, access, refresh []byte, accessExpira time.Time) error {
	tag, err := s.pool.Exec(ctx, `update account.sesiones set access_token=$2, refresh_token=$3, access_expira=$4, ultima=now() where id=$1 and expira>now()`,
		id, access, refresh, accessExpira)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoExiste
	}
	return nil
}

// ReautenticarSesion rota el portador, instala los tokens de una prueba de
// identidad reciente y elimina las demás sesiones en una transacción.
func (s *Store) ReautenticarSesion(ctx context.Context, id, nuevoID string, access, refresh []byte, accessExpira time.Time) (time.Time, error) {
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
	var referencia string
	err = tx.QueryRow(ctx, `update account.sesiones set id=$2, access_token=$3, refresh_token=$4, access_expira=$5, ultima=now()
		where id=$1 and expira>now() returning expira, user_id::text, referencia::text`, id, nuevoID, access, refresh, accessExpira).
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
func (s *Store) RotarPortadorSesion(ctx context.Context, id, nuevoID string) (time.Time, error) {
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
	var referencia string
	err = tx.QueryRow(ctx, `update account.sesiones set id=$2, ultima=now()
		where id=$1 and expira>now() returning expira, user_id::text, referencia::text`, id, nuevoID).
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
	err = tx.QueryRow(ctx, `update account.sesiones set id=$2, access_token=$3, refresh_token=$4, access_expira=$5, aal='aal2', ultima=now()
		where id=$1 and expira>now() returning expira, user_id::text`, id, nuevoID, access, refresh, accessExpira).Scan(&expira, &userID)
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
	_, err := s.pool.Exec(ctx, `update account.sesiones set ultima=now() where id=$1`, id)
	return err
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
	rows, err := s.pool.Query(ctx, `select `+sesionCols+` from account.sesiones where user_id=$1 and expira>now() order by ultima desc`, userID)
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
	_, err := s.pool.Exec(ctx, `update account.sesiones set email=$2 where user_id=$1`, userID, email)
	return err
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
	Membresias, Solicitudes, Sesiones int64
	Grants, SesionesProveedor         int64
}

// RastroDe cuenta el rastro de una persona.
func (s *Store) RastroDe(ctx context.Context, userID string) (Rastro, error) {
	var r Rastro
	err := s.pool.QueryRow(ctx, `select
		(select count(*) from account.membresias where user_id=$1),
		(select count(*) from account.solicitudes where user_id=$1),
		(select count(*) from account.sesiones where user_id=$1),
		(select count(*) from auth.oauth_consents where user_id=$1 and revoked_at is null),
		(select count(*) from auth.sessions where user_id=$1)`, userID).
		Scan(&r.Membresias, &r.Solicitudes, &r.Sesiones, &r.Grants, &r.SesionesProveedor)
	return r, err
}

// BorrarRastro borra lo que esta app guarda de una persona, en una transacción.
// La cuenta en el proveedor es aparte (gotrue.AdminDeleteUser) y va después:
// primero lo que apunta a ella, luego ella.
func (s *Store) BorrarRastro(ctx context.Context, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`delete from account.sesiones where user_id=$1`,
		`delete from account.solicitudes where user_id=$1`,
		`delete from account.membresias where user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
	}
	return tx.Commit(ctx)
}

// PurgarHuerfanos quita las filas de la app cuya cuenta ya no existe en el
// proveedor (borrada con la API de administración sin pasar por aquí).
func (s *Store) PurgarHuerfanos(ctx context.Context) (int64, error) {
	var total int64
	for _, t := range []string{"account.sesiones", "account.solicitudes", "account.membresias"} {
		ct, err := s.pool.Exec(ctx, `delete from `+t+` where user_id not in (select id from auth.users)`)
		if err != nil {
			return total, err
		}
		total += ct.RowsAffected()
	}
	return total, nil
}
