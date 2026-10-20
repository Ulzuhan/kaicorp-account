package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func tokenPruebaIAT(iat int64) string {
	payload, _ := json.Marshal(map[string]int64{"iat": iat})
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".firma"
}

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

func TestCuentaPasswordComparteLimiteEntreReplicasEIPs(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into auth.users(id,email,email_confirmed_at) values($1,$2,now())`, consentPersona, "victima@example.com"); err != nil {
		t.Fatal(err)
	}
	var verificaciones atomic.Int32
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Errorf("llamada inesperada: %s", r.URL)
		}
		verificaciones.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"invalid_credentials","msg":"bad"}`))
	}))
	defer proveedor.Close()
	gt := gotrue.New(proveedor.URL, "anon-test", "")
	ses, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	servidores := make([]*Server, 2)
	for i := range servidores {
		servidores[i], err = New(&config.Config{PublicURL: publica}, st, gt, ses, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	a := &session.Actual{ID: strings.Repeat("a", 64), UserID: consentPersona, Email: "victima@example.com", AAL: "aal1"}
	form := url.Values{"current_password": {"incorrecta"}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}}

	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:4242", i+1)
		r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
		w := httptest.NewRecorder()
		servidores[i%len(servidores)].cuentaPassword(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("intento %d: status=%d, quería permitir la ráfaga inicial", i+1, w.Code)
		}
	}
	login := url.Values{"email": {"victima@example.com"}, "password": {"incorrecta"}}
	r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(login.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.200:4242"
	w := httptest.NewRecorder()
	servidores[1].entrarPOST(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("el intento 11 cambió de ruta, réplica e IP y recibió %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 sin Retry-After acotado")
	}
	mfa := url.Values{"purpose": {"enroll"}, "current_password": {"incorrecta"}}
	r = httptest.NewRequest(http.MethodPost, "/cuenta/mfa/autorizar", strings.NewReader(mfa.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.201:4242"
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
	w = httptest.NewRecorder()
	servidores[0].mfaAutorizar(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("MFA no compartió el presupuesto de cuenta: %d", w.Code)
	}
	if verificaciones.Load() != 10 {
		t.Fatalf("el intento bloqueado alcanzó al proveedor: %d verificaciones", verificaciones.Load())
	}
}

func TestLoginLimiteNoEnumeraCuenta(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into auth.users(id,email,email_confirmed_at) values($1,$2,now())`, consentPersona, "existe@example.com"); err != nil {
		t.Fatal(err)
	}
	var verificaciones atomic.Int32
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verificaciones.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":"invalid_credentials","msg":"bad"}`))
	}))
	defer proveedor.Close()
	gt := gotrue.New(proveedor.URL, "anon-test", "")
	ses, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica}, st, gt, ses, nil)
	if err != nil {
		t.Fatal(err)
	}
	agotar := func(email, prefijo string) *httptest.ResponseRecorder {
		t.Helper()
		for i := 0; i < 10; i++ {
			form := url.Values{"email": {email}, "password": {"incorrecta"}}
			r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = fmt.Sprintf("%s.%d:4242", prefijo, i+1)
			w := httptest.NewRecorder()
			s.entrarPOST(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s intento %d: %d", email, i+1, w.Code)
			}
		}
		form := url.Values{"email": {email}, "password": {"incorrecta"}}
		r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = prefijo + ".200:4242"
		w := httptest.NewRecorder()
		s.entrarPOST(w, r)
		return w
	}
	existe := agotar("existe@example.com", "198.51.100")
	noExiste := agotar("no-existe@example.com", "203.0.113")
	if existe.Code != http.StatusTooManyRequests || noExiste.Code != http.StatusTooManyRequests {
		t.Fatalf("respuestas distintas: existente=%d inexistente=%d", existe.Code, noExiste.Code)
	}
	if existe.Header().Get("Retry-After") != noExiste.Header().Get("Retry-After") || existe.Header().Get("Retry-After") == "" {
		t.Fatalf("backoff distinguible: existente=%q inexistente=%q", existe.Header().Get("Retry-After"), noExiste.Header().Get("Retry-After"))
	}
	if existe.Body.String() != noExiste.Body.String() {
		t.Fatal("el cuerpo del límite distingue si el correo existe")
	}
	if verificaciones.Load() != 20 {
		t.Fatalf("los intentos bloqueados alcanzaron al proveedor: %d", verificaciones.Load())
	}
}

func TestRecuperacionEmiteSoloCapacidadAcotada(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("llamada inesperada: %s", r.URL)
		}
		canjes.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "recovery-access", RefreshToken: "recovery-refresh", ExpiresIn: 3600,
			User: gotrue.User{ID: "victima", Email: "victima@example.com"}})
	})
	w := httptest.NewRecorder()
	intent, err := s.emitirIntencionRecuperacion(t.Context(), "victima@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.restablecerGET(w, httptest.NewRequest(http.MethodGet, "/restablecer?intent="+intent, nil))
	if w.Code != http.StatusOK || canjes.Load() != 0 {
		t.Fatalf("GET de recuperación: status=%d canjes=%d", w.Code, canjes.Load())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName || c.Name == "__Host-account_recovery" || c.Name == cookieMFA {
			t.Fatalf("GET emitió autoridad %s", c.Name)
		}
	}
	form := url.Values{"type": {"recovery"}, "token_hash": {"hash"}, "email": {"victima@example.com"}, "recovery_intent": {intent}}
	rCanje := httptest.NewRequest(http.MethodPost, "/verificar", strings.NewReader(form.Encode()))
	rCanje.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.verificarPOST(w, rCanje)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/restablecer" {
		t.Fatalf("canje de recuperación: %d %s", w.Code, w.Header().Get("Location"))
	}
	if canjes.Load() != 1 {
		t.Fatalf("canjes de recuperación: %d", canjes.Load())
	}
	var recuperacion *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName {
			t.Fatal("el enlace de recuperación creó una sesión general")
		}
		if c.Name == "__Host-account_recovery" {
			recuperacion = c
		}
	}
	if recuperacion == nil || recuperacion.Path != "/" || recuperacion.Domain != "" || !recuperacion.HttpOnly || !recuperacion.Secure || recuperacion.MaxAge != 300 {
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

func TestIntencionRecuperacionAnteriorNoSeRejuveneceAlCanjear(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into auth.users(id,email,email_confirmed_at) values($1,$2,now())`, consentPersona, "test@example.com"); err != nil {
		t.Fatal(err)
	}
	var canjes atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canjes.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Add(time.Hour).Unix()), RefreshToken: "refresh",
			User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := s.emitirIntencionRecuperacion(t.Context(), "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CambiarCredencial(t.Context(), consentPersona, time.Now().Unix(), nil, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"type": {"recovery"}, "token_hash": {"hash-antiguo"}, "email": {"test@example.com"}, "recovery_intent": {intent}}
	r := httptest.NewRequest(http.MethodPost, "/verificar", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.verificarPOST(w, r)
	if w.Code != http.StatusUnauthorized || canjes.Load() != 0 {
		t.Fatalf("la intención antigua alcanzó al proveedor: status=%d canjes=%d", w.Code, canjes.Load())
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
		if c.Name == "__Host-account_recovery" {
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
		if c.Name == "__Host-account_recovery" {
			recuperacion = c
		}
	}
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/restablecer" || recuperacion == nil {
		t.Fatalf("MFA de recuperación incompleto: HTTP %d location=%q cookie=%v", w.Code, w.Header().Get("Location"), recuperacion)
	}
}

func TestMFAAltaEmiteCapacidadAcotadaSinSesionGeneral(t *testing.T) {
	for _, tc := range []struct {
		nombre     string
		proposito  propositoPassword
		cookie     string
		accessAAL1 string
	}{
		{"registro", propositoRegistro, "__Host-account_signup_setup", "signup-aal1"},
		{"invitacion", propositoInvitacion, "__Host-account_password_setup", "invite-aal1"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/factors/factor/verify":
					_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: tc.nombre + "-aal2", RefreshToken: "refresh-aal2", ExpiresIn: 3600,
						User: gotrue.User{ID: "victima", Email: "v@example.com"}})
				case r.URL.Path == "/logout":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
				}
			})
			pendiente := httptest.NewRecorder()
			gs := &gotrue.Session{AccessToken: tc.accessAAL1, RefreshToken: "refresh-aal1", User: gotrue.User{ID: "victima", Email: "v@example.com"}}
			s.ponerPendienteMFAConPassword(pendiente, gs, "/welcome", false, tc.proposito, "Aa1!pendiente")
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
			var capacidad *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == session.CookieName && c.MaxAge >= 0 {
					t.Fatal("MFA de alta creó una sesión general")
				}
				if c.Name == tc.cookie {
					capacidad = c
				}
			}
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != rutaPasswordRegistro || capacidad == nil {
				t.Fatalf("MFA de alta incompleto: HTTP %d location=%q cookie=%v", w.Code, w.Header().Get("Location"), capacidad)
			}
		})
	}
}

func TestAltaRechazaCapacidadesDeRegistroEInvitacionSimultaneas(t *testing.T) {
	s := servidorPasswordSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("capacidades ambiguas llegaron al proveedor: %s %s", r.Method, r.URL)
		http.Error(w, "no", http.StatusInternalServerError)
	})
	gs := &gotrue.Session{AccessToken: "access", RefreshToken: "refresh", User: gotrue.User{ID: "victima", Email: "v@example.com"}}
	registro := httptest.NewRecorder()
	if err := s.emitirCapacidadRegistroEnAutoridad(registro, gs, "aal1", "/", "Aa1!registro", 1, 0, false); err != nil {
		t.Fatal(err)
	}
	invitacion := httptest.NewRecorder()
	if err := s.emitirCapacidadInvitacionEnAutoridad(invitacion, gs, "aal1", "/", "Aa1!invitacion", 1, 0, false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, rutaPasswordRegistro, nil)
	r.AddCookie(cookiePorNombre(registro, "__Host-account_signup_setup"))
	r.AddCookie(cookiePorNombre(invitacion, "__Host-account_password_setup"))
	w := httptest.NewRecorder()
	s.registroPasswordGET(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/recuperar" {
		t.Fatalf("capacidades ambiguas aceptadas: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestCambioPasswordInvalidaMFAPendiente(t *testing.T) {
	var verificaciones atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/factors/factor/verify" {
			verificaciones.Add(1)
		}
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Unix() + 40), RefreshToken: "refresh",
			User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
	})
	ahora := time.Now().Unix()
	pendiente := httptest.NewRecorder()
	s.ponerPendienteMFA(pendiente, &gotrue.Session{AccessToken: tokenPruebaIAT(ahora + 10), RefreshToken: "refresh",
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}, "/restablecer", false, propositoRecuperacion)
	if _, err := s.st.CambiarCredencial(t.Context(), consentPersona, ahora+20, nil, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
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
	if w.Code != http.StatusUnauthorized || verificaciones.Load() != 0 {
		t.Fatalf("MFA anterior alcanzó al proveedor: status=%d verificaciones=%d", w.Code, verificaciones.Load())
	}
}

func TestCambioPasswordDuranteMFAImpideSesionNueva(t *testing.T) {
	verificando := make(chan struct{})
	continuar := make(chan struct{})
	ahora := time.Now().Unix()
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/factors/factor/verify" {
			t.Errorf("llamada inesperada: %s", r.URL)
			return
		}
		close(verificando)
		<-continuar
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: tokenPruebaIAT(ahora + 30), RefreshToken: "refresh-aal2",
			User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
	})
	pendiente := httptest.NewRecorder()
	s.ponerPendienteMFA(pendiente, &gotrue.Session{AccessToken: tokenPruebaIAT(ahora + 10), RefreshToken: "refresh-aal1",
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}, "/", false, "")
	form := url.Values{"factor_id": {"factor"}, "challenge_id": {"reto"}, "code": {"123456"}}
	r := httptest.NewRequest(http.MethodPost, "/factor", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range pendiente.Result().Cookies() {
		if c.Name == cookieMFA {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	fin := make(chan struct{})
	go func() {
		s.factorPOST(w, r)
		close(fin)
	}()
	select {
	case <-verificando:
	case <-time.After(5 * time.Second):
		t.Fatal("MFA no alcanzó al proveedor")
	}
	if _, err := s.st.CambiarCredencial(t.Context(), consentPersona, ahora+20, nil, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	close(continuar)
	<-fin
	if w.Code != http.StatusInternalServerError || cookieSesion(w) != nil {
		t.Fatalf("MFA anterior publicó sesión: status=%d cookie=%v", w.Code, cookieSesion(w))
	}
	filas, err := s.st.SesionesDe(t.Context(), consentPersona)
	if err != nil || len(filas) != 0 {
		t.Fatalf("MFA anterior dejó sesiones: %d %v", len(filas), err)
	}
}

func TestCambioPasswordLegitimoRotaSesionYConservaPrueba(t *testing.T) {
	var cambios atomic.Int32
	var tokenCambio, currentPassword string
	ahora := time.Now().Unix()
	pruebaToken := tokenPruebaIAT(ahora + 30)
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" && r.URL.Query().Get("grant_type") == "password":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: pruebaToken, RefreshToken: "refresh-fresco", ExpiresIn: 3600,
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
	capacidadVieja := httptest.NewRecorder()
	if err := s.emitirCapacidadPassword(capacidadVieja, &gotrue.Session{AccessToken: tokenPruebaIAT(ahora + 10), RefreshToken: "recovery-refresh",
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	var cookieVieja *http.Cookie
	for _, c := range capacidadVieja.Result().Cookies() {
		if c.Name == "__Host-account_recovery" {
			cookieVieja = c
		}
	}
	if cookieVieja == nil {
		t.Fatal("no se emitió la capacidad anterior")
	}
	a, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
	form := url.Values{"current_password": {"actual-correcta"}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
	w := httptest.NewRecorder()
	s.cuentaPassword(w, r)
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || cambios.Load() != 1 || tokenCambio != "Bearer "+pruebaToken || currentPassword != "actual-correcta" {
		t.Fatalf("cambio legítimo incompleto: HTTP %d cambios=%d token=%q current=%q", w.Code, cambios.Load(), tokenCambio, currentPassword)
	}
	if nueva == nil || nueva.Value == anterior.Value {
		t.Fatalf("no rotó el portador: anterior=%v nueva=%v", anterior, nueva)
	}
	if vieja, err := cargarCookie(s, anterior); err != nil || vieja != nil {
		t.Fatalf("la cookie copiada siguió viva: %+v %v", vieja, err)
	}
	actual, err := cargarCookie(s, nueva)
	if err != nil || actual == nil || actual.Token() != pruebaToken {
		t.Fatalf("la sesión reautenticada no sobrevivió: %+v %v", actual, err)
	}
	reset := url.Values{"password": {"attacker-password-1234"}, "password2": {"attacker-password-1234"}}
	r = httptest.NewRequest(http.MethodPost, "/restablecer", strings.NewReader(reset.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieVieja)
	s.restablecerPOST(httptest.NewRecorder(), r)
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad anterior volvió a cambiar el password: %d", cambios.Load())
	}
}

func TestFalloAlCerrarProveedorNoConservaSesionesLocales(t *testing.T) {
	pruebaToken := tokenPruebaIAT(time.Now().Unix() + 30)
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: pruebaToken, RefreshToken: "refresh-fresco", ExpiresIn: 3600,
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
	recoveryToken := tokenPruebaIAT(time.Now().Unix() + 30)
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer "+recoveryToken {
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
	gs := &gotrue.Session{AccessToken: recoveryToken, RefreshToken: "recovery-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}
	if err := s.emitirCapacidadPassword(emitida, gs, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	var capacidad *http.Cookie
	for _, c := range emitida.Result().Cookies() {
		if c.Name == "__Host-account_recovery" {
			capacidad = c
		}
	}
	if capacidad == nil {
		t.Fatal("no se emitió la primera capacidad")
	}
	emitidaDos := httptest.NewRecorder()
	if err := s.emitirCapacidadPassword(emitidaDos, gs, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	var capacidadDos *http.Cookie
	for _, c := range emitidaDos.Result().Cookies() {
		if c.Name == "__Host-account_recovery" {
			capacidadDos = c
		}
	}
	if capacidadDos == nil {
		t.Fatal("no se emitió la segunda capacidad")
	}
	post := func(capacidad *http.Cookie) *httptest.ResponseRecorder {
		form := url.Values{"password": {"new-password-1234"}, "password2": {"new-password-1234"}}
		r := httptest.NewRequest(http.MethodPost, "/restablecer", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(capacidad)
		w := httptest.NewRecorder()
		s.restablecerPOST(w, r)
		return w
	}
	w := post(capacidad)
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || cambios.Load() != 1 || nueva == nil {
		t.Fatalf("recuperación legítima falló: HTTP %d cambios=%d cookie=%v", w.Code, cambios.Load(), nueva)
	}
	post(capacidadDos)
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad se reutilizó: %d cambios", cambios.Load())
	}
	if vieja, err := cargarCookie(s, anterior); err != nil || vieja != nil {
		t.Fatalf("la recuperación conservó la sesión anterior: %+v %v", vieja, err)
	}
	if actual, err := cargarCookie(s, nueva); err != nil || actual == nil || actual.Token() != recoveryToken {
		t.Fatalf("la nueva sesión de recuperación no carga: %+v %v", actual, err)
	}
}

func TestInvitacionCreaSesionSoloDespuesDelPasswordFinal(t *testing.T) {
	var cambios atomic.Int32
	var cierresOtras atomic.Int32
	inviteToken := tokenPruebaIAT(time.Now().Unix() + 30)
	passwordPendiente := "Aa1!pending-random-password-012345678901234567890123456789"
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer "+inviteToken {
				t.Errorf("token de invitación incorrecto: %s", r.Header.Get("Authorization"))
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["current_password"] != passwordPendiente {
				t.Errorf("la invitación no demostró la credencial pendiente: %v", body)
			}
			cambios.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/user" && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer invite-rotated" {
				t.Errorf("la sesión normal no consultó con el bearer rotado: %s", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/token" && r.URL.Query().Get("grant_type") == "refresh_token":
			var body map[string]string
			err := json.NewDecoder(r.Body).Decode(&body)
			if err != nil || body["refresh_token"] != "invite-refresh" {
				t.Errorf("refresh de invitación incorrecto: %v %q", err, body["refresh_token"])
			}
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "invite-rotated", RefreshToken: "invite-refresh-rotated", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/logout":
			if r.Header.Get("Authorization") != "Bearer invite-rotated" {
				t.Errorf("la limpieza no usó el bearer rotado: %s", r.Header.Get("Authorization"))
			}
			if r.URL.Query().Get("scope") == "others" {
				cierresOtras.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	emitida := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: inviteToken, RefreshToken: "invite-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}
	if err := s.emitirCapacidadInvitacionEnAutoridad(emitida, gs, "aal1", "/cuenta", passwordPendiente, emitidoSesion(gs), 0, false); err != nil {
		t.Fatal(err)
	}
	capacidad := cookiePorNombre(emitida, "__Host-account_password_setup")
	if capacidad == nil || cookieSesion(emitida) != nil {
		t.Fatalf("la invitación publicó autoridad incorrecta: capacidad=%v sesión=%v", capacidad, cookieSesion(emitida))
	}
	filas, err := s.st.SesionesDe(t.Context(), consentPersona)
	if err != nil || len(filas) != 0 {
		t.Fatalf("la invitación creó sesiones antes del password: %d %v", len(filas), err)
	}
	preauth := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	preauth.AddCookie(capacidad)
	wPreauth := httptest.NewRecorder()
	s.Handler().ServeHTTP(wPreauth, preauth)
	if wPreauth.Code != http.StatusSeeOther || !strings.HasPrefix(wPreauth.Header().Get("Location"), "/entrar") {
		t.Fatalf("la capacidad pre-auth abrió la cuenta: %d %q", wPreauth.Code, wPreauth.Header().Get("Location"))
	}
	form := url.Values{"password": {"first-password-1234"}, "password2": {"first-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, rutaPasswordRegistro, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(capacidad)
	w := httptest.NewRecorder()
	s.registroPasswordPOST(w, r)
	nueva := cookieSesion(w)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cuenta" || cambios.Load() != 1 || cierresOtras.Load() != 1 || nueva == nil {
		t.Fatalf("alta inicial falló: HTTP %d cambios=%d cookie=%v", w.Code, cambios.Load(), nueva)
	}
	partesSesion := strings.Split(nueva.Value, ".")
	if len(partesSesion) < 2 || partesSesion[1] == capacidad.Value {
		t.Fatalf("la sesión normal no rotó el portador de la capacidad: capacidad=%q sesión=%q", capacidad.Value, nueva.Value)
	}
	filas, err = s.st.SesionesDe(t.Context(), consentPersona)
	if err != nil || len(filas) != 1 {
		t.Fatalf("la invitación no dejó una sola sesión: %d %v", len(filas), err)
	}
	if actual, err := cargarCookie(s, nueva); err != nil || actual == nil || actual.Token() != "invite-rotated" {
		t.Fatalf("la sesión normal no guardó el bearer rotado: %+v %v", actual, err)
	}
	repetida := httptest.NewRecorder()
	s.registroPasswordPOST(repetida, r.Clone(t.Context()))
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad de invitación se reutilizó: %d", cambios.Load())
	}
}

func TestInvitacionNoPublicaSesionSiNoCierraProveedor(t *testing.T) {
	var cambios atomic.Int32
	var cierresLocales atomic.Int32
	inviteToken := tokenPruebaIAT(time.Now().Unix() + 30)
	passwordPendiente := "Aa1!pending-random-password-012345678901234567890123456789"
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			cambios.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
		case r.URL.Path == "/token" && r.URL.Query().Get("grant_type") == "refresh_token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "invite-rotated", RefreshToken: "invite-refresh-rotated", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/logout" && r.URL.Query().Get("scope") == "others":
			if r.Header.Get("Authorization") != "Bearer invite-rotated" {
				t.Errorf("la limpieza no usó el bearer rotado: %s", r.Header.Get("Authorization"))
			}
			http.Error(w, "provider cleanup failed", http.StatusInternalServerError)
		case r.URL.Path == "/logout" && r.URL.Query().Get("scope") == "local":
			cierresLocales.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	emitida := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: inviteToken, RefreshToken: "invite-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com"}}
	if err := s.emitirCapacidadInvitacionEnAutoridad(emitida, gs, "aal1", "/cuenta", passwordPendiente, emitidoSesion(gs), 0, false); err != nil {
		t.Fatal(err)
	}
	capacidad := cookiePorNombre(emitida, "__Host-account_password_setup")
	form := url.Values{"password": {"first-password-1234"}, "password2": {"first-password-1234"}}
	r := httptest.NewRequest(http.MethodPost, rutaPasswordRegistro, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(capacidad)
	w := httptest.NewRecorder()
	s.registroPasswordPOST(w, r)

	if w.Code != http.StatusBadGateway || cookieSesion(w) != nil || cambios.Load() != 1 || cierresLocales.Load() != 1 {
		t.Fatalf("el fallo de limpieza publicó autoridad: HTTP %d cambios=%d cierres_locales=%d sesión=%v", w.Code, cambios.Load(), cierresLocales.Load(), cookieSesion(w))
	}
	filas, err := s.st.SesionesDe(t.Context(), consentPersona)
	if err != nil || len(filas) != 0 {
		t.Fatalf("el fallo de limpieza dejó sesiones normales: %d %v", len(filas), err)
	}
	repetida := httptest.NewRecorder()
	s.registroPasswordPOST(repetida, r.Clone(t.Context()))
	if cambios.Load() != 1 {
		t.Fatalf("la capacidad se reutilizó tras el fallo de limpieza: %d cambios", cambios.Load())
	}
}
