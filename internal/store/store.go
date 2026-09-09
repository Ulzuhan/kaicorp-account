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

// Migrate aplica las migraciones embebidas que falten, en orden y cada una en
// su transacción, anotándolas en account.schema_migrations.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `create table if not exists account.schema_migrations (
		version text primary key, applied_at timestamptz not null default now())`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(migraciones, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
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

const grupoCols = `nombre, titulo, descripcion, url, coalesce(cliente_id,''), solicitable, orden`

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
	var cid *string
	if clienteID != "" {
		cid = &clienteID
	}
	tag, err := s.pool.Exec(ctx, `update account.grupos set cliente_id=$2 where nombre=$1`, grupo, cid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoExiste
	}
	return nil
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

// Revocar quita la membresía. No toca los grants de GoTrue: eso es RevocarGrants.
func (s *Store) Revocar(ctx context.Context, userID, grupo string) error {
	_, err := s.pool.Exec(ctx, `delete from account.membresias where user_id=$1 and grupo=$2`, userID, grupo)
	return err
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
}

const sesionCols = `id, user_id::text, email, nombre, aal, access_token, refresh_token, access_expira, creada, ultima, expira, agente`

func scanSesion(row pgx.Row) (*Sesion, error) {
	var x Sesion
	err := row.Scan(&x.ID, &x.UserID, &x.Email, &x.Nombre, &x.AAL, &x.AccessToken, &x.RefreshToken, &x.AccessExpira, &x.Creada, &x.Ultima, &x.Expira, &x.Agente)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoExiste
		}
		return nil, err
	}
	return &x, nil
}

// CrearSesion guarda una sesión nueva.
func (s *Store) CrearSesion(ctx context.Context, x *Sesion) error {
	_, err := s.pool.Exec(ctx, `insert into account.sesiones(id, user_id, email, nombre, aal, access_token, refresh_token, access_expira, expira, agente)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		x.ID, x.UserID, x.Email, x.Nombre, x.AAL, x.AccessToken, x.RefreshToken, x.AccessExpira, x.Expira, x.Agente)
	return err
}

// Sesion lee una por id.
func (s *Store) Sesion(ctx context.Context, id string) (*Sesion, error) {
	return scanSesion(s.pool.QueryRow(ctx, `select `+sesionCols+` from account.sesiones where id=$1`, id))
}

// ActualizarTokens guarda tokens nuevos (tras renovar o tras el segundo factor).
func (s *Store) ActualizarTokens(ctx context.Context, id string, access, refresh []byte, accessExpira time.Time, aal string) error {
	_, err := s.pool.Exec(ctx, `update account.sesiones set access_token=$2, refresh_token=$3, access_expira=$4, aal=$5, ultima=now() where id=$1`,
		id, access, refresh, accessExpira, aal)
	return err
}

// TocarSesion anota actividad.
func (s *Store) TocarSesion(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `update account.sesiones set ultima=now() where id=$1`, id)
	return err
}

// BorrarSesion elimina una.
func (s *Store) BorrarSesion(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `delete from account.sesiones where id=$1`, id)
	return err
}

// BorrarSesionesDe elimina todas las de una persona (menos la dada, si se pasa).
func (s *Store) BorrarSesionesDe(ctx context.Context, userID, salvo string) error {
	_, err := s.pool.Exec(ctx, `delete from account.sesiones where user_id=$1 and id<>$2`, userID, salvo)
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
	coalesce(u.raw_user_meta_data->>'name','') from auth.users u`

func scanUsuario(row pgx.Row) (*Usuario, error) {
	var u Usuario
	if err := row.Scan(&u.ID, &u.Email, &u.Creada, &u.UltimaEntr, &u.Confirmada, &u.Bloqueada, &u.Nombre); err != nil {
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
