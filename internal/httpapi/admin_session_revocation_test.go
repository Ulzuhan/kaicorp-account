package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

const administradorRevocacion = "00000000-0000-4000-8000-000000000099"

func flashDeRespuesta(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieFlash && c.Value != "" {
			mensaje, err := url.QueryUnescape(c.Value)
			if err != nil {
				t.Fatal(err)
			}
			return mensaje
		}
	}
	return ""
}

func peticionAdminRevocacion(ruta, userID string, admin *session.Actual) *http.Request {
	form := url.Values{"user_id": {userID}}
	r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.WithContext(context.WithValue(r.Context(), claveSesion, admin))
}

func TestAdministracionNoAnunciaExitoSiLaRevocacionFalla(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo,tipo,solicitable)
		values ('account-admin','Administration','rol',false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into account.membresias(user_id,grupo,por)
		values ($1,'account-admin','test')`, administradorRevocacion); err != nil {
		t.Fatal(err)
	}
	var fallaBloqueo atomic.Bool
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/admin/users/") {
			if fallaBloqueo.Load() {
				http.Error(w, `{"msg":"fallo forzado"}`, http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(proveedor.Close)
	gt := gotrue.New(proveedor.URL, "anon", "service")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL, AdminGroup: "account-admin"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin := &session.Actual{UserID: administradorRevocacion, Email: "admin@example.com", AAL: "aal2"}

	wCerrar := httptest.NewRecorder()
	s.adminCerrarSesiones(wCerrar, peticionAdminRevocacion("/admin/cerrar-sesiones", "identidad-invalida", admin))
	if mensaje := flashDeRespuesta(t, wCerrar); mensaje == "" || strings.Contains(mensaje, "Every session") {
		t.Fatalf("el fallo local se anunció como éxito: %q", mensaje)
	}

	wBloqueoLocal := httptest.NewRecorder()
	s.adminBloquear(wBloqueoLocal, peticionAdminRevocacion("/admin/bloquear", "identidad-invalida", admin))
	if mensaje := flashDeRespuesta(t, wBloqueoLocal); mensaje == "" || strings.Contains(mensaje, "blocked and signed out everywhere") {
		t.Fatalf("el bloqueo con limpieza fallida se anunció como éxito: %q", mensaje)
	}

	// Aunque falle la API administrativa de bloqueo, la frontera local se
	// intenta igualmente y el panel comunica el resultado incompleto.
	fallaBloqueo.Store(true)
	gs := &gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Add(time.Minute).Unix()), RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	emitida := httptest.NewRecorder()
	if _, err := m.Crear(t.Context(), emitida, httptest.NewRequest(http.MethodGet, "/", nil), gs, "aal2", false); err != nil {
		t.Fatal(err)
	}
	wBloqueoProveedor := httptest.NewRecorder()
	s.adminBloquear(wBloqueoProveedor, peticionAdminRevocacion("/admin/bloquear", consentPersona, admin))
	if mensaje := flashDeRespuesta(t, wBloqueoProveedor); mensaje == "" || strings.Contains(mensaje, "blocked and signed out everywhere") {
		t.Fatalf("el fallo del proveedor se anunció como éxito: %q", mensaje)
	}
	if sesiones, err := st.SesionesDe(t.Context(), consentPersona); err != nil || len(sesiones) != 0 {
		t.Fatalf("el fallo remoto evitó la revocación local: %d %v", len(sesiones), err)
	}
}

func TestRevocacionInvalidaCargaAAL2YEmisionAnterior(t *testing.T) {
	st, _ := baseConsentimiento(t)
	gt := gotrue.New("http://unused.invalid", "anon", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	antigua := time.Now().Unix()
	gs := &gotrue.Session{AccessToken: tokenPruebaIAT(antigua), RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	emitida := httptest.NewRecorder()
	if _, err := m.Crear(t.Context(), emitida, httptest.NewRequest(http.MethodGet, "/", nil), gs, "aal2", false); err != nil {
		t.Fatal(err)
	}
	cookie := cookieSesion(emitida)
	if cookie == nil {
		t.Fatal("la prueba no obtuvo cookie de sesión")
	}
	if err := st.RevocarSesiones(t.Context(), consentPersona); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.AddCookie(cookie)
	if actual, err := m.Cargar(t.Context(), httptest.NewRecorder(), r); err != nil || actual != nil {
		t.Fatalf("la ruta rápida aal2 conservó autoridad: actual=%+v err=%v", actual, err)
	}

	// Un refresh posterior no rejuvenece la prueba que empezó antes del corte.
	refrescada := &gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Add(time.Minute).Unix()), RefreshToken: "refresh-nuevo", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	_, err = m.CrearUnicaEnEmision(t.Context(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), refrescada, "aal2", false, antigua)
	if !errors.Is(err, store.ErrCredencialAnterior) {
		t.Fatalf("un token renovado rejuveneció una autoridad anterior: %v", err)
	}
}

func TestBloqueoDeEmergenciaUsaRevocacionDurable(t *testing.T) {
	st, _ := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/admin/users/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/logout" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(proveedor.Close)
	gt := gotrue.New(proveedor.URL, "anon", "service")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL, AdminGroup: "account-admin"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	gs := &gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Add(time.Minute).Unix()), RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	if _, err := m.Crear(t.Context(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), gs, "aal2", false); err != nil {
		t.Fatal(err)
	}
	if err := s.bloquearRotacionNoProbada(t.Context(), consentPersona, errors.New("fallo forzado")); err == nil {
		t.Fatal("el bloqueo de emergencia debía conservar la causa original")
	}
	if sesiones, err := st.SesionesDe(t.Context(), consentPersona); err != nil || len(sesiones) != 0 {
		t.Fatalf("el bloqueo de emergencia dejó viva la sesión local: %d %v", len(sesiones), err)
	}
}

func TestCierreDeSeguridadMFADevuelveFalloDeLimpieza(t *testing.T) {
	st, db := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(proveedor.Close)
	gt := gotrue.New(proveedor.URL, "anon", "service")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL, AdminGroup: "account-admin"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	gs := &gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Add(time.Minute).Unix()), RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	actual, err := m.Crear(t.Context(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), gs, "aal2", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `create function falla_cierre_mfa() returns trigger language plpgsql as
		'begin raise exception ''fallo de limpieza MFA forzado''; end';
		create trigger falla_cierre_mfa before delete on account.sesiones for each statement execute function falla_cierre_mfa()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `drop trigger if exists falla_cierre_mfa on account.sesiones; drop function if exists falla_cierre_mfa()`)
	})
	err = s.fallarCierreCambioMFA(t.Context(), httptest.NewRecorder(), actual)
	if err == nil || !strings.Contains(err.Error(), "sesiones locales") {
		t.Fatalf("el fallo local del cierre MFA no se devolvió con contexto: %v", err)
	}
}
