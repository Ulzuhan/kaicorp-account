package httpapi

import (
	"context"
	"encoding/json"
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
)

func servidorPasswordSinStore(t *testing.T, proveedor http.HandlerFunc) *Server {
	t.Helper()
	falso := httptest.NewServer(proveedor)
	t.Cleanup(falso.Close)
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, nil, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	return &Server{cfg: &config.Config{PublicURL: publica}, gt: gt, ses: m, limitador: nuevoLimitador()}
}

func TestSesionesOrdinariasNoCambianPasswordSinPruebaFresca(t *testing.T) {
	var cambios atomic.Int32
	s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" && r.Method == http.MethodPut {
			cambios.Add(1)
		}
		_, _ = w.Write([]byte(`{"id":"victima"}`))
	})
	a := &session.Actual{ID: strings.Repeat("a", 64), UserID: "victima", Email: "victima@example.com", AAL: "aal1"}
	form := url.Values{"password": {"new-password-1234"}, "password2": {"new-password-1234"}}

	for _, ruta := range []string{"/cuenta/password", "/restablecer"} {
		r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
		w := httptest.NewRecorder()
		if ruta == "/cuenta/password" {
			s.cuentaPassword(w, r)
		} else {
			s.restablecerPOST(w, r)
		}
	}
	if cambios.Load() != 0 {
		t.Fatalf("una sesión ordinaria ejecutó %d cambios sin prueba fresca", cambios.Load())
	}
}

func TestCuentaPasswordExigePruebaDeLaMismaIdentidad(t *testing.T) {
	for _, tc := range []struct {
		nombre string
		uid    string
		status int
	}{
		{"contraseña incorrecta", "", http.StatusBadRequest},
		{"otra identidad", "otra-persona", http.StatusOK},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			var cambios atomic.Int32
			s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					w.WriteHeader(tc.status)
					if tc.status >= 400 {
						_, _ = w.Write([]byte(`{"error_code":"invalid_credentials","msg":"bad"}`))
						return
					}
					_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "prueba", RefreshToken: "refresh", ExpiresIn: 3600,
						User: gotrue.User{ID: tc.uid, Email: "victima@example.com"}})
				case "/logout":
					w.WriteHeader(http.StatusNoContent)
				case "/user":
					cambios.Add(1)
					_, _ = w.Write([]byte(`{"id":"victima"}`))
				default:
					t.Errorf("llamada inesperada: %s", r.URL)
				}
			})
			a := &session.Actual{ID: strings.Repeat("a", 64), UserID: "victima", Email: "victima@example.com", AAL: "aal1"}
			form := url.Values{"current_password": {"actual"}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}}
			r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
			s.cuentaPassword(httptest.NewRecorder(), r)
			if cambios.Load() != 0 {
				t.Fatal("la prueba de otra identidad llegó al cambio")
			}
		})
	}
}

func TestRecuperacionEmiteSoloCapacidadAcotada(t *testing.T) {
	s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("llamada inesperada: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "recovery-access", RefreshToken: "recovery-refresh", ExpiresIn: 3600,
			User: gotrue.User{ID: "victima", Email: "victima@example.com"}})
	})
	w := httptest.NewRecorder()
	s.restablecerGET(w, httptest.NewRequest(http.MethodGet, "/restablecer?token_hash=hash", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/restablecer" {
		t.Fatalf("canje de recuperación: %d %s", w.Code, w.Header().Get("Location"))
	}
	var recuperacion *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName {
			t.Fatal("el enlace de recuperación creó una sesión general")
		}
		if c.Name == "__Secure-account_recovery" {
			recuperacion = c
		}
	}
	if recuperacion == nil || recuperacion.Path != "/restablecer" || !recuperacion.HttpOnly || !recuperacion.Secure || recuperacion.MaxAge != 300 {
		t.Fatalf("capacidad de recuperación incorrecta: %+v", recuperacion)
	}
	// Una sesión ordinaria, incluso válida, no sustituye la capacidad.
	r := httptest.NewRequest(http.MethodGet, "/restablecer", nil)
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{ID: strings.Repeat("a", 64), UserID: "victima"}))
	w = httptest.NewRecorder()
	s.restablecerGET(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/recuperar" {
		t.Fatalf("sesión ordinaria autorizó el reset: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestCapacidadRecuperacionNoSeRepiteTrasResultadoAmbiguo(t *testing.T) {
	inicio, continuar := make(chan struct{}), make(chan struct{})
	var cambios atomic.Int32
	s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("llamada inesperada: %s", r.URL)
			return
		}
		if cambios.Add(1) == 1 {
			close(inicio)
			<-continuar
		}
		http.Error(w, `{"msg":"unknown"}`, http.StatusServiceUnavailable)
	})
	emitida := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: "recovery-access", RefreshToken: "recovery-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: "victima", Email: "victima@example.com"}}
	if err := s.emitirCapacidadPassword(emitida, gs, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range emitida.Result().Cookies() {
		if c.Name == "__Secure-account_recovery" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no se emitió la capacidad")
	}
	post := func() *httptest.ResponseRecorder {
		form := url.Values{"password": {"new-password-1234"}, "password2": {"new-password-1234"}}
		r := httptest.NewRequest(http.MethodPost, "/restablecer", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.restablecerPOST(w, r)
		return w
	}
	fin := make(chan struct{})
	go func() {
		post()
		close(fin)
	}()
	select {
	case <-inicio:
	case <-time.After(5 * time.Second):
		t.Fatal("no empezó el cambio")
	}
	post()
	close(continuar)
	<-fin
	post()
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad ejecutó %d cambios", cambios.Load())
	}
}

func TestPropositoMFANoSeInfiereDeNext(t *testing.T) {
	s := servidorPasswordSinStore(t, func(http.ResponseWriter, *http.Request) {})
	gs := &gotrue.Session{AccessToken: "a", RefreshToken: "r", User: gotrue.User{ID: "victima", Email: "v@example.com"}}
	w := httptest.NewRecorder()
	s.ponerPendienteMFA(w, gs, "/restablecer", false, "")
	r := httptest.NewRequest(http.MethodGet, "/factor", nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieMFA {
			r.AddCookie(c)
		}
	}
	p := s.leerPendienteMFA(r)
	if p == nil || p.Proposito != "" {
		t.Fatalf("un next ordinario adquirió propósito de recuperación: %+v", p)
	}
}

func TestMFARecuperacionEmiteCapacidadSinSesionGeneral(t *testing.T) {
	s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/factors/factor/verify" {
			t.Errorf("llamada inesperada: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "recovery-aal2", RefreshToken: "refresh-aal2", ExpiresIn: 3600,
			User: gotrue.User{ID: "victima", Email: "v@example.com"}})
	})
	pendiente := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: "recovery-aal1", RefreshToken: "refresh-aal1", User: gotrue.User{ID: "victima", Email: "v@example.com"}}
	s.ponerPendienteMFA(pendiente, gs, "/restablecer", false, propositoRecuperacion)
	form := url.Values{"factor_id": {"factor"}, "challenge_id": {"reto"}, "code": {"123456"}}
	r := httptest.NewRequest(http.MethodPost, "/factor", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range pendiente.Result().Cookies() {
		if c.Name == cookieMFA {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	s.factorPOST(w, r)
	var recuperacion *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName && c.MaxAge >= 0 {
			t.Fatal("MFA de recuperación creó una sesión general")
		}
		if c.Name == "__Secure-account_recovery" {
			recuperacion = c
		}
	}
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/restablecer" || recuperacion == nil {
		t.Fatalf("MFA de recuperación incompleto: HTTP %d location=%q cookie=%v", w.Code, w.Header().Get("Location"), recuperacion)
	}
}

func TestCambioPasswordLegitimoRotaSesionYConservaPrueba(t *testing.T) {
	var cambios atomic.Int32
	var tokenCambio, currentPassword string
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" && r.URL.Query().Get("grant_type") == "password":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "prueba-fresca", RefreshToken: "refresh-fresco", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			cambios.Add(1)
			tokenCambio = r.Header.Get("Authorization")
			var body struct {
				CurrentPassword string `json:"current_password"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			currentPassword = body.CurrentPassword
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/user" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	a, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
	form := url.Values{"current_password": {"actual-correcta"}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
	w := httptest.NewRecorder()
	s.cuentaPassword(w, r)
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || cambios.Load() != 1 || tokenCambio != "Bearer prueba-fresca" || currentPassword != "actual-correcta" {
		t.Fatalf("cambio legítimo incompleto: HTTP %d cambios=%d token=%q current=%q", w.Code, cambios.Load(), tokenCambio, currentPassword)
	}
	if nueva == nil || nueva.Value == anterior.Value {
		t.Fatalf("no rotó el portador: anterior=%v nueva=%v", anterior, nueva)
	}
	if vieja, err := cargarCookie(s, anterior); err != nil || vieja != nil {
		t.Fatalf("la cookie copiada siguió viva: %+v %v", vieja, err)
	}
	actual, err := cargarCookie(s, nueva)
	if err != nil || actual == nil || actual.Token() != "prueba-fresca" {
		t.Fatalf("la sesión reautenticada no sobrevivió: %+v %v", actual, err)
	}
}

func TestFalloAlCerrarProveedorNoConservaSesionesLocales(t *testing.T) {
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "prueba-fresca", RefreshToken: "refresh-fresco", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/logout":
			http.Error(w, `{"msg":"unavailable"}`, http.StatusServiceUnavailable)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	a, actual := sesionMFA(t, s, consentPersona, "aal1", 3600)
	_, copiada := sesionMFA(t, s, consentPersona, "aal2", 3600)
	form := url.Values{"current_password": {"actual-correcta"}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
	w := httptest.NewRecorder()
	s.cuentaPassword(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("el fallo de revocación se anunció como éxito: HTTP %d", w.Code)
	}
	for _, c := range []*http.Cookie{actual, copiada} {
		if viva, err := cargarCookie(s, c); err != nil || viva != nil {
			t.Fatalf("una sesión local sobrevivió al fallo del proveedor: %+v %v", viva, err)
		}
	}
	filas, err := s.st.SesionesDe(t.Context(), consentPersona)
	if err != nil || len(filas) != 0 {
		t.Fatalf("quedaron sesiones locales después del fallo: %d %v", len(filas), err)
	}
}

func TestRecuperacionValidaCambiaUnaVezYCierraSesiones(t *testing.T) {
	var cambios atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer recovery-access" {
				t.Errorf("token de recuperación incorrecto: %s", r.Header.Get("Authorization"))
			}
			cambios.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/user" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	_, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
	emitida := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: "recovery-access", RefreshToken: "recovery-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}
	if err := s.emitirCapacidadPassword(emitida, gs, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	var capacidad *http.Cookie
	for _, c := range emitida.Result().Cookies() {
		if c.Name == "__Secure-account_recovery" {
			capacidad = c
		}
	}
	post := func() *httptest.ResponseRecorder {
		form := url.Values{"password": {"new-password-1234"}, "password2": {"new-password-1234"}}
		r := httptest.NewRequest(http.MethodPost, "/restablecer", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(capacidad)
		w := httptest.NewRecorder()
		s.restablecerPOST(w, r)
		return w
	}
	w := post()
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || cambios.Load() != 1 || nueva == nil {
		t.Fatalf("recuperación legítima falló: HTTP %d cambios=%d cookie=%v", w.Code, cambios.Load(), nueva)
	}
	post()
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad se reutilizó: %d cambios", cambios.Load())
	}
	if vieja, err := cargarCookie(s, anterior); err != nil || vieja != nil {
		t.Fatalf("la recuperación conservó la sesión anterior: %+v %v", vieja, err)
	}
	if actual, err := cargarCookie(s, nueva); err != nil || actual == nil || actual.Token() != "recovery-access" {
		t.Fatalf("la nueva sesión de recuperación no carga: %+v %v", actual, err)
	}
}

func TestInvitacionConservaAltaInicialSinPasswordActual(t *testing.T) {
	var cambios atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer invite-access" {
				t.Errorf("token de invitación incorrecto: %s", r.Header.Get("Authorization"))
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if _, existe := body["current_password"]; existe {
				t.Error("la invitación exigió una contraseña que aún no existe")
			}
			cambios.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/user" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	a, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
	emitida := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: "invite-access", RefreshToken: "invite-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}
	if err := s.emitirCapacidadPassword(emitida, gs, "aal1", propositoInvitacion); err != nil {
		t.Fatal(err)
	}
	var capacidad *http.Cookie
	for _, c := range emitida.Result().Cookies() {
		if c.Name == "__Secure-account_password_setup" {
			capacidad = c
		}
	}
	form := url.Values{"password": {"first-password-1234"}, "password2": {"first-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(capacidad)
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
	w := httptest.NewRecorder()
	s.cuentaPassword(w, r)
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || cambios.Load() != 1 || nueva == nil || nueva.Value == anterior.Value {
		t.Fatalf("alta inicial falló: HTTP %d cambios=%d cookie=%v", w.Code, cambios.Load(), nueva)
	}
}
