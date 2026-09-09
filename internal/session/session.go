// Package session son las sesiones de la app de cuenta y su CSRF.
//
// La sesión de verdad es la de GoTrue (access token de una hora, refresh token
// rotativo). Esta app la ENVUELVE: guarda los dos tokens cifrados en
// account.sesiones y le da al navegador una cookie opaca con el id. Así la
// persona puede ver y cerrar sus sesiones, un administrador puede echar a
// alguien, y ningún token de GoTrue viaja en ninguna cookie.
//
// CSRF: doble envío firmado. Una cookie aleatoria `account_csrf` (que va con
// sesión o sin ella: el login y el registro también son POST) y un campo de
// formulario que es su HMAC con la clave de la app. Un origen ajeno puede
// mandar la cookie pero no calcular el campo.
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
	"errors"
	"net/http"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

const (
	// CookieName es la cookie de sesión.
	CookieName = "account_session"
	// CSRFCookie es la cookie del doble envío.
	CSRFCookie = "account_csrf"
	// CSRFField es el nombre del campo oculto de los formularios.
	CSRFField = "_csrf"
)

// Manager gestiona sesiones.
type Manager struct {
	aead   cipher.AEAD
	key    []byte
	secure bool
	ttl    time.Duration
	store  *store.Store
	gotrue *gotrue.Client
}

// New crea el gestor. key son 32 bytes.
func New(key []byte, secure bool, ttl time.Duration, st *store.Store, gt *gotrue.Client) (*Manager, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Manager{aead: aead, key: key, secure: secure, ttl: ttl, store: st, gotrue: gt}, nil
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

// Crear abre una sesión de la app a partir de una sesión de GoTrue y pone la cookie.
func (m *Manager) Crear(ctx context.Context, w http.ResponseWriter, r *http.Request, gs *gotrue.Session, aal string) (*Actual, error) {
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
	x := &store.Sesion{
		ID: id, UserID: gs.User.ID, Email: gs.User.Email, Nombre: gs.User.Name(), AAL: aal,
		AccessToken: access, RefreshToken: refresh, AccessExpira: expiraDe(gs),
		Creada: now, Ultima: now, Expira: now.Add(m.ttl), Agente: recortar(r.UserAgent(), 200),
	}
	if err := m.store.CrearSesion(ctx, x); err != nil {
		return nil, err
	}
	m.ponerCookie(w, id, x.Expira)
	return &Actual{ID: id, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: aal, Creada: now, Expira: x.Expira, token: gs.AccessToken}, nil
}

// Actualizar guarda una sesión de GoTrue nueva sobre la misma sesión de la app
// (tras el segundo factor, o tras cambiar la contraseña).
func (m *Manager) Actualizar(ctx context.Context, a *Actual, gs *gotrue.Session, aal string) error {
	access, err := m.cifrar(gs.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := m.cifrar(gs.RefreshToken)
	if err != nil {
		return err
	}
	if aal == "" {
		aal = a.AAL
	}
	if err := m.store.ActualizarTokens(ctx, a.ID, access, refresh, expiraDe(gs), aal); err != nil {
		return err
	}
	a.token = gs.AccessToken
	a.AAL = aal
	return nil
}

// Cargar lee la sesión de la cookie. Devuelve (nil, nil) si no hay. Renueva el
// access token si está a punto de caducar; si GoTrue rechaza el refresh (la
// sesión fue revocada o cerrada desde otro sitio), la sesión de la app muere.
func (m *Manager) Cargar(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Actual, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" || len(c.Value) != 64 {
		return nil, nil
	}
	x, err := m.store.Sesion(ctx, c.Value)
	if err != nil {
		if errors.Is(err, store.ErrNoExiste) {
			m.borrarCookie(w)
			return nil, nil
		}
		return nil, err
	}
	if time.Now().After(x.Expira) {
		_ = m.store.BorrarSesion(ctx, x.ID)
		m.borrarCookie(w)
		return nil, nil
	}
	access, err := m.descifrar(x.AccessToken)
	if err != nil {
		_ = m.store.BorrarSesion(ctx, x.ID)
		m.borrarCookie(w)
		return nil, nil
	}
	a := &Actual{ID: x.ID, UserID: x.UserID, Email: x.Email, Nombre: x.Nombre, AAL: x.AAL, Creada: x.Creada, Expira: x.Expira, token: access}
	if time.Until(x.AccessExpira) < 90*time.Second {
		refresh, err := m.descifrar(x.RefreshToken)
		if err != nil {
			_ = m.store.BorrarSesion(ctx, x.ID)
			m.borrarCookie(w)
			return nil, nil
		}
		gs, err := m.gotrue.Refresh(ctx, refresh)
		if err != nil {
			var ge *gotrue.Error
			if errors.As(err, &ge) && ge.Status < 500 {
				// Revocada, caducada o rotada por otro: fuera.
				_ = m.store.BorrarSesion(ctx, x.ID)
				m.borrarCookie(w)
				return nil, nil
			}
			return nil, err
		}
		if err := m.Actualizar(ctx, a, gs, ""); err != nil {
			return nil, err
		}
	} else {
		_ = m.store.TocarSesion(ctx, x.ID)
	}
	return a, nil
}

// Cerrar termina la sesión: la de GoTrue (scope local) y la de la app.
func (m *Manager) Cerrar(ctx context.Context, w http.ResponseWriter, a *Actual) {
	if a != nil {
		_ = m.gotrue.Logout(ctx, a.token, "local")
		_ = m.store.BorrarSesion(ctx, a.ID)
	}
	m.borrarCookie(w)
}

func (m *Manager) ponerCookie(w http.ResponseWriter, valor string, expira time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: valor, Path: "/", Expires: expira,
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) borrarCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode})
}

// ── CSRF ───────────────────────────────────────────────────────────────────

// CSRF devuelve el valor para el campo del formulario, creando la cookie si no
// existe. Se llama al pintar cualquier formulario.
func (m *Manager) CSRF(w http.ResponseWriter, r *http.Request) string {
	var semilla string
	if c, err := r.Cookie(CSRFCookie); err == nil && len(c.Value) == 32 {
		semilla = c.Value
	} else {
		semilla, _ = aleatorio(16)
		http.SetCookie(w, &http.Cookie{
			Name: CSRFCookie, Value: semilla, Path: "/", MaxAge: 12 * 3600,
			HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode,
		})
	}
	return m.firmar(semilla)
}

// CSRFValido comprueba el campo del formulario contra la cookie.
func (m *Manager) CSRFValido(r *http.Request) bool {
	c, err := r.Cookie(CSRFCookie)
	if err != nil || len(c.Value) != 32 {
		return false
	}
	campo := r.PostFormValue(CSRFField)
	return campo != "" && hmac.Equal([]byte(campo), []byte(m.firmar(c.Value)))
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
