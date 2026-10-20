// Package session son las sesiones de la app de cuenta y su CSRF.
//
// La sesión de verdad es la de GoTrue (access token de una hora, refresh token
// rotativo). Esta app la ENVUELVE: guarda los dos tokens cifrados en
// account.sesiones y le da al navegador una cookie con el id firmado. Así la
// persona puede ver y cerrar sus sesiones, un administrador puede echar a
// alguien, y ningún token de GoTrue viaja en ninguna cookie.
//
// CSRF: estado aleatorio sellado, también antes del login, y un campo firmado
// ligado a la sesión cargada. En HTTPS la cookie usa el prefijo __Host- para
// impedir que un subdominio hermano imponga estado mediante una cookie Domain.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

const (
	// CookieName es la cookie de sesión HTTPS. El prefijo obliga al navegador a
	// mantenerla en el host exacto, con Secure y Path=/.
	CookieName = "__Host-account_session"
	// DevelopmentCookieName sólo se usa cuando el servidor permite HTTP local.
	DevelopmentCookieName = "account_session"
	// CSRFCookie es la cookie del doble envío.
	CSRFCookie = "__Host-account_csrf"
	// CSRFField es el nombre del campo oculto de los formularios.
	CSRFField = "_csrf"
)

// rutasCookieSesionLegada cubre el nombre histórico en su Path=/ original y
// las rutas de autoridad donde un despliegue anterior o un hermano pudo haber
// dejado una variante más específica. Nunca se acepta ni se migra su valor.
var rutasCookieSesionLegada = []string{"/", "/oauth", "/oauth/consent", "/cuenta", "/admin", "/factor", "/salir", "/api/session"}

var errSujetoProveedor = errors.New("sesión: el token del proveedor pertenece a otra persona")

// Manager gestiona sesiones.
type Manager struct {
	aead   cipher.AEAD
	key    []byte
	secure bool
	ttl    time.Duration
	// recordarTTL es la vida de una sesión marcada «keep me signed in».
	recordarTTL time.Duration
	store       *store.Store
	gotrue      *gotrue.Client
}

// New crea el gestor. key son 32 bytes.
func New(key []byte, secure bool, ttl, recordarTTL time.Duration, st *store.Store, gt *gotrue.Client) (*Manager, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if recordarTTL < ttl {
		recordarTTL = ttl
	}
	return &Manager{aead: aead, key: key, secure: secure, ttl: ttl, recordarTTL: recordarTTL, store: st, gotrue: gt}, nil
}

// Actual es la sesión cargada para una petición.
type Actual struct {
	ID     string
	UserID string
	Email  string
	Nombre string
	AAL    string
	Creada time.Time
	Expira time.Time
	token  string
	// refresh y accessExpira se conservan sólo para volver a sellar los tokens
	// cuando rota el portador sin pedir credenciales nuevas al proveedor.
	refresh      string
	accessExpira time.Time
	// referencia permanece estable al rotar la cookie; sólo sirve para cerrar.
	referencia string
}

// Token es el access token de GoTrue vigente, para llamar en nombre de la persona.
func (a *Actual) Token() string { return a.token }

// EsAAL2 dice si la sesión pasó el segundo factor.
func (a *Actual) EsAAL2() bool { return a != nil && a.AAL == "aal2" }

func (m *Manager) cifrar(texto string) ([]byte, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, m.aead.Seal(nil, nonce, []byte(texto), nil)...), nil
}

func (m *Manager) descifrar(b []byte) (string, error) {
	n := m.aead.NonceSize()
	if len(b) < n {
		return "", errors.New("sesión: token cifrado demasiado corto")
	}
	out, err := m.aead.Open(nil, b[:n], b[n:], nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

const versionContextoToken = 1

type contextoToken struct {
	Version    int    `json:"v"`
	ID         string `json:"id"`
	Referencia string `json:"ref"`
	UserID     string `json:"sub"`
	AAL        string `json:"aal"`
	Clase      string `json:"kind"`
}

func datosAsociadosToken(id, referencia, userID, aal, clase string) ([]byte, error) {
	if id == "" || referencia == "" || userID == "" || (aal != "aal1" && aal != "aal2") || (clase != "access" && clase != "refresh") {
		return nil, errors.New("sesión: contexto de token incompleto")
	}
	return json.Marshal(contextoToken{
		Version: versionContextoToken, ID: id, Referencia: referencia,
		UserID: userID, AAL: aal, Clase: clase,
	})
}

func (m *Manager) cifrarToken(texto, id, referencia, userID, aal, clase string) ([]byte, error) {
	aad, err := datosAsociadosToken(id, referencia, userID, aal, clase)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, m.aead.Seal(nil, nonce, []byte(texto), aad)...), nil
}

func (m *Manager) descifrarToken(b []byte, id, referencia, userID, aal, clase string) (string, error) {
	aad, err := datosAsociadosToken(id, referencia, userID, aal, clase)
	if err != nil {
		return "", err
	}
	n := m.aead.NonceSize()
	if len(b) < n {
		return "", errors.New("sesión: token cifrado demasiado corto")
	}
	out, err := m.aead.Open(nil, b[:n], b[n:], aad)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func aleatorio(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func referenciaAleatoria() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// UUID v4 canónico para la columna uuid y para un AAD estable antes del INSERT.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// aalDe deduce el nivel de la sesión de GoTrue: el access token lleva `aal`,
// pero para no parsear JWTs aquí se deriva de si hubo verificación de factor.
func expiraDe(s *gotrue.Session) time.Time {
	if s.ExpiresAt > 0 {
		return time.Unix(s.ExpiresAt, 0)
	}
	return time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)
}

// EmitidoDe devuelve el iat de un access token del proveedor. No valida la
// firma: los únicos tokens que llegan aquí ya fueron emitidos o aceptados por
// GoTrue; el valor sólo los liga al corte de credenciales compartido.
func EmitidoDe(token string) int64 {
	partes := strings.Split(token, ".")
	if len(partes) != 3 {
		return 0
	}
	b, err := base64.RawURLEncoding.DecodeString(partes[1])
	if err != nil {
		return 0
	}
	var claims struct {
		IAT int64 `json:"iat"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.IAT <= 0 {
		return 0
	}
	return claims.IAT
}

// Crear abre una sesión de la app a partir de una sesión de GoTrue y pone la
// cookie. Con `recordar` la sesión vive el TTL largo («keep me signed in»);
// sin él, el corto. La cookie caduca con la sesión.
func (m *Manager) Crear(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool) (*Actual, error) {
	return m.crear(ctx, w, r, gs, aal, recordar, false, EmitidoDe(gs.AccessToken))
}

// CrearUnica abre una sesión sólo si puede eliminar atómicamente todas las
// demás sesiones locales de la misma persona.
func (m *Manager) CrearUnica(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool) (*Actual, error) {
	return m.crear(ctx, w, r, gs, aal, recordar, true, EmitidoDe(gs.AccessToken))
}

// CrearUnicaEnEmision conserva el iat de la autoridad que inició un flujo de
// recuperación o invitación. Un refresh posterior no puede rejuvenecer una
// capacidad que nació antes de un cierre administrativo.
func (m *Manager) CrearUnicaEnEmision(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool, emitido int64) (*Actual, error) {
	return m.crear(ctx, w, r, gs, aal, recordar, true, emitido)
}

// CrearEnEmision conserva el iat anterior a MFA. Los tokens aal2 recién
// devueltos no pueden rejuvenecer un login iniciado antes de cambiar password.
func (m *Manager) CrearEnEmision(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool, emitido int64) (*Actual, error) {
	return m.crear(ctx, w, r, gs, aal, recordar, false, emitido)
}

func (m *Manager) crear(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar, unica bool, emitido int64) (*Actual, error) {
	if aal == "" {
		aal = "aal1"
	}
	id, err := aleatorio(32)
	if err != nil {
		return nil, err
	}
	referencia, err := referenciaAleatoria()
	if err != nil {
		return nil, err
	}
	access, err := m.cifrarToken(gs.AccessToken, id, referencia, gs.User.ID, aal, "access")
	if err != nil {
		return nil, err
	}
	refresh, err := m.cifrarToken(gs.RefreshToken, id, referencia, gs.User.ID, aal, "refresh")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	vida := m.ttl
	if recordar {
		vida = m.recordarTTL
	}
	x := &store.Sesion{
		ID: id, Referencia: referencia, UserID: gs.User.ID, Email: gs.User.Email, Nombre: gs.User.Name(), AAL: aal,
		AccessToken: access, RefreshToken: refresh, AccessExpira: expiraDe(gs),
		Creada: now, Ultima: now, Expira: now.Add(vida), Agente: recortar(r.UserAgent(), 200), Emitido: emitido,
	}
	if unica {
		err = m.store.CrearSesionUnica(ctx, x)
	} else {
		err = m.store.CrearSesion(ctx, x)
	}
	if err != nil {
		return nil, err
	}
	m.ponerCookie(w, id, x.Expira)
	return &Actual{ID: id, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: aal, Creada: now, Expira: x.Expira,
		token: gs.AccessToken, refresh: gs.RefreshToken, accessExpira: x.AccessExpira, referencia: x.Referencia}, nil
}

// CrearUnicaEnGeneracion publica la sesión de una mutación de contraseña sólo
// si ninguna mutación posterior ganó antes de que terminara el proveedor.
func (m *Manager) CrearUnicaEnGeneracion(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool, generacion int64) (*Actual, error) {
	return m.crearEnGeneracion(ctx, w, r, gs, aal, recordar, generacion, EmitidoDe(gs.AccessToken))
}

// CrearUnicaEnGeneracionYEmision liga a la vez la mutación de contraseña y la
// autoridad original del flujo a sus dos fronteras durables.
func (m *Manager) CrearUnicaEnGeneracionYEmision(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool, generacion, emitido int64) (*Actual, error) {
	return m.crearEnGeneracion(ctx, w, r, gs, aal, recordar, generacion, emitido)
}

func (m *Manager) crearEnGeneracion(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool, generacion, emitido int64) (*Actual, error) {
	if aal == "" {
		aal = "aal1"
	}
	id, err := aleatorio(32)
	if err != nil {
		return nil, err
	}
	referencia, err := referenciaAleatoria()
	if err != nil {
		return nil, err
	}
	access, err := m.cifrarToken(gs.AccessToken, id, referencia, gs.User.ID, aal, "access")
	if err != nil {
		return nil, err
	}
	refresh, err := m.cifrarToken(gs.RefreshToken, id, referencia, gs.User.ID, aal, "refresh")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	vida := m.ttl
	if recordar {
		vida = m.recordarTTL
	}
	x := &store.Sesion{
		ID: id, Referencia: referencia, UserID: gs.User.ID, Email: gs.User.Email, Nombre: gs.User.Name(), AAL: aal,
		AccessToken: access, RefreshToken: refresh, AccessExpira: expiraDe(gs),
		Creada: now, Ultima: now, Expira: now.Add(vida), Agente: recortar(r.UserAgent(), 200), Emitido: emitido,
	}
	if err := m.store.CrearSesionUnicaEnGeneracion(ctx, x, generacion); err != nil {
		return nil, err
	}
	m.ponerCookie(w, id, x.Expira)
	return &Actual{ID: id, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: aal, Creada: now, Expira: x.Expira,
		token: gs.AccessToken, refresh: gs.RefreshToken, accessExpira: x.AccessExpira, referencia: x.Referencia}, nil
}

// Actualizar renueva tokens sin elevar el nivel ni cambiar el portador.
func (m *Manager) Actualizar(ctx context.Context, a *Actual, gs *gotrue.Session) error {
	if gs == nil || gs.User.ID == "" || gs.User.ID != a.UserID {
		return errSujetoProveedor
	}
	accessExpira := expiraDe(gs)
	access, err := m.cifrarToken(gs.AccessToken, a.ID, a.referencia, a.UserID, a.AAL, "access")
	if err != nil {
		return err
	}
	refresh, err := m.cifrarToken(gs.RefreshToken, a.ID, a.referencia, a.UserID, a.AAL, "refresh")
	if err != nil {
		return err
	}
	if err := m.store.ActualizarTokens(ctx, a.ID, access, refresh, accessExpira); err != nil {
		return err
	}
	a.token, a.refresh, a.accessExpira = gs.AccessToken, gs.RefreshToken, accessExpira
	return nil
}

// Reautenticar instala una sesión reciente del proveedor bajo un portador
// nuevo y elimina atómicamente las demás sesiones locales. La referencia
// estable, el AAL y la caducidad absoluta se conservan.
func (m *Manager) Reautenticar(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session) error {
	return m.reautenticar(ctx, w, a, gs, 0, "")
}

// ReautenticarComo rota el portador, instala una prueba reciente y fija el AAL
// resultante. Se usa al retirar un factor: el último baja a aal1; si aún queda
// otro factor, la afirmación fresca conserva aal2.
func (m *Manager) ReautenticarComo(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session, aal string) error {
	if aal != "aal1" && aal != "aal2" {
		return errors.New("sesión: AAL de reautenticación inválido")
	}
	return m.reautenticar(ctx, w, a, gs, 0, aal)
}

// ReautenticarEnGeneracion impide que una mutación anterior publique sus
// tokens después de que otra contraseña ya haya ganado.
func (m *Manager) ReautenticarEnGeneracion(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session, generacion int64) error {
	return m.reautenticar(ctx, w, a, gs, generacion, "")
}

func (m *Manager) reautenticar(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session, generacion int64, aal string) error {
	if gs == nil || gs.User.ID == "" || gs.User.ID != a.UserID {
		return errSujetoProveedor
	}
	aalDestino := a.AAL
	if aal != "" {
		aalDestino = aal
	}
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	accessExpira := expiraDe(gs)
	access, err := m.cifrarToken(gs.AccessToken, id, a.referencia, a.UserID, aalDestino, "access")
	if err != nil {
		return err
	}
	refresh, err := m.cifrarToken(gs.RefreshToken, id, a.referencia, a.UserID, aalDestino, "refresh")
	if err != nil {
		return err
	}
	var expira time.Time
	if generacion > 0 {
		expira, err = m.store.ReautenticarSesionEnGeneracion(ctx, a.ID, id, access, refresh, accessExpira, generacion)
	} else if aal != "" {
		expira, err = m.store.ReautenticarSesionComo(ctx, a.ID, id, access, refresh, accessExpira, aal)
	} else {
		expira, err = m.store.ReautenticarSesion(ctx, a.ID, id, access, refresh, accessExpira)
	}
	if err != nil {
		return err
	}
	a.ID, a.Expira, a.token, a.refresh, a.accessExpira = id, expira, gs.AccessToken, gs.RefreshToken, accessExpira
	if aal != "" {
		a.AAL = aal
	}
	m.ponerCookie(w, id, expira)
	return nil
}

// RotarPortador invalida copias de la cookie, conserva los tokens actuales y
// elimina atómicamente las demás sesiones locales.
func (m *Manager) RotarPortador(ctx context.Context, w http.ResponseWriter, a *Actual) error {
	return m.rotarPortador(ctx, w, a, 0)
}

// RotarPortadorEnGeneracion liga la rotación local a la contraseña que acaba
// de instalarse en el proveedor.
func (m *Manager) RotarPortadorEnGeneracion(ctx context.Context, w http.ResponseWriter, a *Actual, generacion int64) error {
	return m.rotarPortador(ctx, w, a, generacion)
}

func (m *Manager) rotarPortador(ctx context.Context, w http.ResponseWriter, a *Actual, generacion int64) error {
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	access, err := m.cifrarToken(a.token, id, a.referencia, a.UserID, a.AAL, "access")
	if err != nil {
		return err
	}
	refresh, err := m.cifrarToken(a.refresh, id, a.referencia, a.UserID, a.AAL, "refresh")
	if err != nil {
		return err
	}
	var expira time.Time
	if generacion > 0 {
		expira, err = m.store.RotarPortadorSesionEnGeneracion(ctx, a.ID, id, access, refresh, a.accessExpira, generacion)
	} else {
		expira, err = m.store.RotarPortadorSesion(ctx, a.ID, id, access, refresh, a.accessExpira)
	}
	if err != nil {
		return err
	}
	a.ID, a.Expira = id, expira
	m.ponerCookie(w, id, expira)
	return nil
}

// Promover instala los tokens obtenidos al verificar un factor bajo un portador
// nuevo. La cookie sólo se entrega después de invalidar atómicamente el anterior.
func (m *Manager) Promover(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session) error {
	if gs == nil || gs.User.ID == "" || gs.User.ID != a.UserID {
		return errSujetoProveedor
	}
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	accessExpira := expiraDe(gs)
	access, err := m.cifrarToken(gs.AccessToken, id, a.referencia, a.UserID, "aal2", "access")
	if err != nil {
		return err
	}
	refresh, err := m.cifrarToken(gs.RefreshToken, id, a.referencia, a.UserID, "aal2", "refresh")
	if err != nil {
		return err
	}
	expira, err := m.store.PromoverSesion(ctx, a.ID, id, access, refresh, accessExpira)
	if err != nil {
		return err
	}
	a.ID, a.AAL, a.Expira, a.token, a.refresh, a.accessExpira = id, "aal2", expira, gs.AccessToken, gs.RefreshToken, accessExpira
	m.ponerCookie(w, id, expira)
	return nil
}

// Cargar lee la sesión de la cookie. Devuelve (nil, nil) si no hay. Renueva el
// access token si está a punto de caducar; si GoTrue rechaza el refresh (la
// sesión fue revocada o cerrada desde otro sitio), la sesión de la app muere.
func (m *Manager) Cargar(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Actual, error) {
	if m.secure && len(r.CookiesNamed(DevelopmentCookieName)) > 0 {
		m.expirarCookieSesionLegada(w)
	}
	cookies := r.CookiesNamed(m.nombreCookieSesion())
	if len(cookies) != 1 {
		return nil, nil
	}
	c := cookies[0]
	id, ok := m.idDeCookie(c.Value)
	if !ok {
		return nil, nil
	}
	x, err := m.store.Sesion(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNoExiste) {
			// No borrar una cookie nueva que otra respuesta pudo entregar ya.
			return nil, nil
		}
		return nil, err
	}
	if time.Now().After(x.Expira) {
		m.invalidar(ctx, w, x.ID)
		return nil, nil
	}
	access, err := m.descifrarToken(x.AccessToken, x.ID, x.Referencia, x.UserID, x.AAL, "access")
	if err != nil {
		m.invalidar(ctx, w, x.ID)
		return nil, nil
	}
	// Se autentican los dos sobres en cada carga. Así tampoco puede quedar un
	// refresh trasplantado latente hasta que caduque el access token.
	refresh, err := m.descifrarToken(x.RefreshToken, x.ID, x.Referencia, x.UserID, x.AAL, "refresh")
	if err != nil {
		m.invalidar(ctx, w, x.ID)
		return nil, nil
	}
	a := &Actual{ID: x.ID, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: x.AAL, Creada: x.Creada, Expira: x.Expira,
		token: access, refresh: refresh, accessExpira: x.AccessExpira, referencia: x.Referencia}
	var usuario *gotrue.User
	if time.Until(x.AccessExpira) < 90*time.Second {
		gs, err := m.gotrue.Refresh(ctx, refresh)
		if err != nil {
			var ge *gotrue.Error
			if errors.As(err, &ge) && ge.Status < 500 {
				// Revocada, caducada o rotada por otro: fuera.
				m.invalidar(ctx, w, x.ID)
				return nil, nil
			}
			return nil, err
		}
		if gs == nil || gs.User.ID == "" || gs.User.ID != x.UserID {
			m.invalidar(ctx, w, x.ID)
			return nil, nil
		}
		usuario, err = m.usuarioVigente(ctx, w, a, gs.AccessToken)
		if err != nil || usuario == nil {
			return nil, err
		}
		if err := m.Actualizar(ctx, a, gs); err != nil {
			if errors.Is(err, errSujetoProveedor) {
				m.invalidar(ctx, w, x.ID)
				return nil, nil
			}
			if errors.Is(err, store.ErrNoExiste) {
				// Otro request la cerró o promovió mientras se renovaba en GoTrue.
				// No sobrescribir la cookie que entregó esa promoción.
				return nil, nil
			}
			return nil, err
		}
	} else {
		_ = m.store.TocarSesion(ctx, x.ID)
		usuario, err = m.usuarioVigente(ctx, w, a, access)
		if err != nil || usuario == nil {
			return nil, err
		}
	}
	if !a.EsAAL2() {
		// La ficha del login y el token cacheado pueden ser anteriores al alta.
		// usuario se obtuvo después del refresh y ya fue ligado al UserID local.
		if usuario.HasVerifiedFactor() {
			m.invalidar(ctx, w, a.ID)
			return nil, nil
		}
	}
	// También para aal2: un cierre administrativo puede confirmar después de
	// la primera lectura. No devolver autoridad cacheada si la fila desapareció
	// o pertenece ya a una generación revocada.
	if _, err := m.store.Sesion(ctx, a.ID); err != nil {
		if errors.Is(err, store.ErrNoExiste) {
			return nil, nil
		}
		return nil, err
	}
	return a, nil
}

// usuarioVigente comprueba en el proveedor el sujeto de todo access token,
// incluido AAL2. Una discrepancia sólo invalida la fila local: nunca cierra la
// sesión del token extraño, pues ese token puede pertenecer a una víctima.
func (m *Manager) usuarioVigente(ctx context.Context, w http.ResponseWriter, a *Actual, token string) (*gotrue.User, error) {
	u, err := m.gotrue.Me(ctx, token)
	if err != nil {
		if errors.Is(err, gotrue.ErrUnauthorized) || errors.Is(err, gotrue.ErrForbidden) {
			m.invalidar(ctx, w, a.ID)
			return nil, nil
		}
		return nil, err
	}
	if u == nil || u.ID == "" || u.ID != a.UserID {
		m.invalidar(ctx, w, a.ID)
		return nil, nil
	}
	return u, nil
}

// Cerrar termina la sesión: la de GoTrue (scope local) y la de la app.
func (m *Manager) Cerrar(ctx context.Context, w http.ResponseWriter, a *Actual) {
	if a != nil {
		_ = m.gotrue.Logout(ctx, a.token, "local")
		_ = m.store.BorrarSesionPorReferencia(ctx, a.referencia)
	}
	m.borrarCookie(w)
}

// CerrarOtras conserva esta fila aunque una verificación concurrente haya
// sustituido su portador mientras se cerraban las demás sesiones.
func (m *Manager) CerrarOtras(ctx context.Context, a *Actual) error {
	errProveedor := m.CerrarOtrasProveedor(ctx, a)
	errStore := m.store.BorrarSesionesDe(ctx, a.UserID, a.referencia)
	return errors.Join(errProveedor, errStore)
}

// CerrarOtrasProveedor completa en GoTrue una limpieza local que ya se hizo
// atómicamente durante un cambio de credenciales.
func (m *Manager) CerrarOtrasProveedor(ctx context.Context, a *Actual) error {
	return m.gotrue.Logout(ctx, a.token, "others")
}

func (m *Manager) invalidar(ctx context.Context, w http.ResponseWriter, id string) {
	if err := m.store.BorrarSesion(ctx, id); !errors.Is(err, store.ErrNoExiste) {
		m.borrarCookie(w)
	}
}

// El id guardado en la base sólo identifica la fila. La firma, que nunca se
// guarda allí, es necesaria para autenticar y usa un contexto distinto de CSRF.
func (m *Manager) firmaSesion(id string) string {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte("session:v1:" + id))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) idDeCookie(valor string) (string, bool) {
	// No se aceptan cookies antiguas sin firma, ni siquiera con una fila viva.
	if len(valor) != 132 {
		return "", false
	}
	partes := strings.Split(valor, ".")
	if len(partes) != 3 || partes[0] != "v1" || len(partes[1]) != 64 || len(partes[2]) != 64 {
		return "", false
	}
	id := partes[1]
	if _, err := hex.DecodeString(id); err != nil {
		return "", false
	}
	if !hmac.Equal([]byte(partes[2]), []byte(m.firmaSesion(id))) {
		return "", false
	}
	return id, true
}

func (m *Manager) ponerCookie(w http.ResponseWriter, id string, expira time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: m.nombreCookieSesion(), Value: "v1." + id + "." + m.firmaSesion(id), Path: "/", Expires: expira,
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode,
	})
	if m.secure {
		m.expirarCookieSesionLegada(w)
	}
}

func (m *Manager) borrarCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: m.nombreCookieSesion(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode})
	if m.secure {
		m.expirarCookieSesionLegada(w)
	}
}

func (m *Manager) nombreCookieSesion() string {
	if m.secure {
		return CookieName
	}
	return DevelopmentCookieName
}

func (m *Manager) expirarCookieSesionLegada(w http.ResponseWriter) {
	for _, ruta := range rutasCookieSesionLegada {
		http.SetCookie(w, &http.Cookie{Name: DevelopmentCookieName, Value: "", Path: ruta, MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}

// ── CSRF ───────────────────────────────────────────────────────────────────

const vidaCSRF = 12 * time.Hour

func (m *Manager) nombreCookieCSRF() string {
	if m.secure {
		return CSRFCookie
	}
	// El prefijo __Host- exige Secure. Sólo el modo de desarrollo usa HTTP.
	return "account_csrf"
}

// estadoCSRF acepta una sola cookie emitida por este gestor y aún vigente.
// El sellado evita firmar semillas elegidas por quien pide una página pública.
func (m *Manager) estadoCSRF(r *http.Request) (*http.Cookie, bool) {
	var encontrada *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == m.nombreCookieCSRF() {
			if encontrada != nil {
				return nil, false
			}
			encontrada = c
		}
	}
	if encontrada == nil {
		return nil, false
	}
	texto, err := m.Abrir(encontrada.Value)
	if err != nil {
		return nil, false
	}
	partes := strings.Split(texto, ":")
	if len(partes) != 2 || len(partes[0]) != 32 {
		return nil, false
	}
	if _, err := hex.DecodeString(partes[0]); err != nil {
		return nil, false
	}
	hasta, err := strconv.ParseInt(partes[1], 10, 64)
	if err != nil || hasta <= time.Now().Unix() {
		return nil, false
	}
	return encontrada, true
}

// CSRF devuelve el campo ligado a la autoridad efectiva de esta petición.
// Una sesión invalidada por Cargar ya no participa, aunque su cookie siga en r.
func (m *Manager) CSRF(w http.ResponseWriter, r *http.Request, a *Actual) string {
	c, ok := m.estadoCSRF(r)
	if !ok {
		semilla, err := aleatorio(16)
		if err != nil {
			return ""
		}
		valor, err := m.Sellar(semilla + ":" + strconv.FormatInt(time.Now().Add(vidaCSRF).Unix(), 10))
		if err != nil {
			return ""
		}
		c = &http.Cookie{Name: m.nombreCookieCSRF(), Value: valor, Path: "/", MaxAge: int(vidaCSRF.Seconds()),
			HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode}
		http.SetCookie(w, c)
	}
	return m.campoCSRF(c.Value, a)
}

// CSRFValido exige estado único, vigente y un único campo para esta sesión.
func (m *Manager) CSRFValido(r *http.Request, a *Actual) bool {
	c, ok := m.estadoCSRF(r)
	if !ok || r.ParseForm() != nil {
		return false
	}
	campos := r.PostForm[CSRFField]
	esperado := m.campoCSRF(c.Value, a)
	return len(campos) == 1 && esperado != "" && hmac.Equal([]byte(campos[0]), []byte(esperado))
}

func (m *Manager) campoCSRF(estado string, a *Actual) string {
	if a == nil {
		return m.firmar("v2:anonymous:" + estado)
	}
	if a.ID == "" {
		return ""
	}
	return m.firmar("v2:session:" + a.ID + ":" + estado)
}

func (m *Manager) firmar(semilla string) string {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte("csrf:" + semilla))
	return hex.EncodeToString(h.Sum(nil))
}

func recortar(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ── Sobres breves ──────────────────────────────────────────────────────────
//
// Entre la contraseña y el segundo factor hay un estado a medias que NO es una
// sesión de la app: los tokens aal1 de GoTrue viajan en una cookie cifrada de
// pocos minutos hasta que el código los convierte en aal2. Así ninguna sesión
// de account.sesiones existe sin haber pasado por el factor.

// Sellar cifra un texto para una cookie breve.
func (m *Manager) Sellar(texto string) (string, error) {
	b, err := m.cifrar(texto)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Abrir descifra lo que Sellar produjo.
func (m *Manager) Abrir(sellado string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(sellado)
	if err != nil {
		return "", err
	}
	return m.descifrar(b)
}

// Secure dice si las cookies van con Secure.
func (m *Manager) Secure() bool { return m.secure }
