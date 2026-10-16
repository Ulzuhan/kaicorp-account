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
	// CookieName es la cookie de sesión.
	CookieName = "account_session"
	// CSRFCookie es la cookie del doble envío.
	CSRFCookie = "__Host-account_csrf"
	// CSRFField es el nombre del campo oculto de los formularios.
	CSRFField = "_csrf"
)

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

func aleatorio(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// aalDe deduce el nivel de la sesión de GoTrue: el access token lleva `aal`,
// pero para no parsear JWTs aquí se deriva de si hubo verificación de factor.
func expiraDe(s *gotrue.Session) time.Time {
	if s.ExpiresAt > 0 {
		return time.Unix(s.ExpiresAt, 0)
	}
	return time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)
}

func emitidoDe(token string) int64 {
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
	return m.crear(ctx, w, r, gs, aal, recordar, false)
}

// CrearUnica abre una sesión sólo si puede eliminar atómicamente todas las
// demás sesiones locales de la misma persona.
func (m *Manager) CrearUnica(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar bool) (*Actual, error) {
	return m.crear(ctx, w, r, gs, aal, recordar, true)
}

func (m *Manager) crear(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string, recordar, unica bool) (*Actual, error) {
	id, err := aleatorio(32)
	if err != nil {
		return nil, err
	}
	access, err := m.cifrar(gs.AccessToken)
	if err != nil {
		return nil, err
	}
	refresh, err := m.cifrar(gs.RefreshToken)
	if err != nil {
		return nil, err
	}
	if aal == "" {
		aal = "aal1"
	}
	now := time.Now()
	vida := m.ttl
	if recordar {
		vida = m.recordarTTL
	}
	x := &store.Sesion{
		ID: id, UserID: gs.User.ID, Email: gs.User.Email, Nombre: gs.User.Name(), AAL: aal,
		AccessToken: access, RefreshToken: refresh, AccessExpira: expiraDe(gs),
		Creada: now, Ultima: now, Expira: now.Add(vida), Agente: recortar(r.UserAgent(), 200), Emitido: emitidoDe(gs.AccessToken),
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
	return &Actual{ID: id, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: aal, Creada: now, Expira: x.Expira, token: gs.AccessToken, referencia: x.Referencia}, nil
}

// Actualizar renueva tokens sin elevar el nivel ni cambiar el portador.
func (m *Manager) Actualizar(ctx context.Context, a *Actual, gs *gotrue.Session) error {
	access, err := m.cifrar(gs.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := m.cifrar(gs.RefreshToken)
	if err != nil {
		return err
	}
	if err := m.store.ActualizarTokens(ctx, a.ID, access, refresh, expiraDe(gs)); err != nil {
		return err
	}
	a.token = gs.AccessToken
	return nil
}

// Reautenticar instala una sesión reciente del proveedor bajo un portador
// nuevo y elimina atómicamente las demás sesiones locales. La referencia
// estable, el AAL y la caducidad absoluta se conservan.
func (m *Manager) Reautenticar(ctx context.Context, w http.ResponseWriter, a *Actual, gs *gotrue.Session) error {
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	access, err := m.cifrar(gs.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := m.cifrar(gs.RefreshToken)
	if err != nil {
		return err
	}
	expira, err := m.store.ReautenticarSesion(ctx, a.ID, id, access, refresh, expiraDe(gs))
	if err != nil {
		return err
	}
	a.ID, a.Expira, a.token = id, expira, gs.AccessToken
	m.ponerCookie(w, id, expira)
	return nil
}

// RotarPortador invalida copias de la cookie, conserva los tokens actuales y
// elimina atómicamente las demás sesiones locales.
func (m *Manager) RotarPortador(ctx context.Context, w http.ResponseWriter, a *Actual) error {
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	expira, err := m.store.RotarPortadorSesion(ctx, a.ID, id)
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
	id, err := aleatorio(32)
	if err != nil {
		return err
	}
	access, err := m.cifrar(gs.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := m.cifrar(gs.RefreshToken)
	if err != nil {
		return err
	}
	expira, err := m.store.PromoverSesion(ctx, a.ID, id, access, refresh, expiraDe(gs))
	if err != nil {
		return err
	}
	a.ID, a.AAL, a.Expira, a.token = id, "aal2", expira, gs.AccessToken
	m.ponerCookie(w, id, expira)
	return nil
}

// Cargar lee la sesión de la cookie. Devuelve (nil, nil) si no hay. Renueva el
// access token si está a punto de caducar; si GoTrue rechaza el refresh (la
// sesión fue revocada o cerrada desde otro sitio), la sesión de la app muere.
func (m *Manager) Cargar(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Actual, error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, nil
	}
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
	access, err := m.descifrar(x.AccessToken)
	if err != nil {
		m.invalidar(ctx, w, x.ID)
		return nil, nil
	}
	a := &Actual{ID: x.ID, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: x.AAL, Creada: x.Creada, Expira: x.Expira, token: access, referencia: x.Referencia}
	if time.Until(x.AccessExpira) < 90*time.Second {
		refresh, err := m.descifrar(x.RefreshToken)
		if err != nil {
			m.invalidar(ctx, w, x.ID)
			return nil, nil
		}
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
		if err := m.Actualizar(ctx, a, gs); err != nil {
			if errors.Is(err, store.ErrNoExiste) {
				// Otro request la cerró o promovió mientras se renovaba en GoTrue.
				// No sobrescribir la cookie que entregó esa promoción.
				return nil, nil
			}
			return nil, err
		}
	} else {
		_ = m.store.TocarSesion(ctx, x.ID)
	}
	if !a.EsAAL2() {
		// La ficha del login y el token cacheado pueden ser anteriores al alta.
		// Se consulta después del refresh: éste también puede solaparse con ella.
		u, err := m.gotrue.Me(ctx, a.Token())
		if err != nil {
			if errors.Is(err, gotrue.ErrUnauthorized) || errors.Is(err, gotrue.ErrForbidden) {
				m.invalidar(ctx, w, a.ID)
				return nil, nil
			}
			return nil, err
		}
		if u.HasVerifiedFactor() {
			m.invalidar(ctx, w, a.ID)
			return nil, nil
		}
		// Una promoción puede haber borrado esta fila mientras /user respondía
		// con una ficha leída antes del alta. No devolver esa autoridad antigua.
		if _, err := m.store.Sesion(ctx, a.ID); err != nil {
			if errors.Is(err, store.ErrNoExiste) {
				return nil, nil
			}
			return nil, err
		}
	}
	return a, nil
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
		Name: CookieName, Value: "v1." + id + "." + m.firmaSesion(id), Path: "/", Expires: expira,
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) borrarCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode})
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
