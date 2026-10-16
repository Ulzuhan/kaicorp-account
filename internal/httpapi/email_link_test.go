package httpapi

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func servidorEnlaceSinStore(t *testing.T, proveedor http.HandlerFunc) *Server {
	t.Helper()
	falso := httptest.NewServer(proveedor)
	t.Cleanup(falso.Close)
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, nil, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica}, nil, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNavegarEnlaceCorreoNoCanjeaToken(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		canjes.Add(1)
		http.Error(w, `{"msg":"token consumido"}`, http.StatusBadRequest)
	})

	casos := []struct {
		ruta string
		typ  string
	}{
		{"/verificar", "signup"},
		{"/verificar", "invite"},
		{"/verificar", "email_change"},
		{"/verificar", "magiclink"},
		{"/verificar", "email"},
		{"/restablecer", "recovery"},
	}
	for _, tc := range casos {
		for _, metodo := range []string{http.MethodGet, http.MethodHead} {
			t.Run(tc.typ+"_"+metodo, func(t *testing.T) {
				antes := canjes.Load()
				ruta := tc.ruta + "?token_hash=hash&type=" + tc.typ + "&email=attacker%40example.com"
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, httptest.NewRequest(metodo, ruta, nil))
				if canjes.Load() != antes {
					t.Fatal("navegar el enlace llamó al proveedor")
				}
				if w.Code != http.StatusOK {
					t.Fatalf("navegar el enlace: %d", w.Code)
				}
				if metodo == http.MethodGet && strings.Contains(w.Body.String(), "attacker@example.com") {
					t.Fatal("la página reflejó un correo no verificado de la URL")
				}
				for _, c := range w.Result().Cookies() {
					if c.Name == session.CookieName || c.Name == "__Secure-account_recovery" || c.Name == cookieMFA {
						t.Fatalf("navegar el enlace emitió autoridad %s", c.Name)
					}
				}
			})
		}
	}
}

var campoOculto = regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)

func abrirConfirmacion(t *testing.T, s *Server, ruta string, entrada ...*http.Cookie) (url.Values, []*http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, ruta, nil)
	for _, c := range entrada {
		r.AddCookie(c)
	}
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("abrir confirmación: %d %s", w.Code, w.Body.String())
	}
	form := url.Values{}
	for _, m := range campoOculto.FindAllStringSubmatch(w.Body.String(), -1) {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	if form.Get(session.CSRFField) == "" || form.Get("type") == "" || form.Get("token_hash") == "" {
		t.Fatalf("formulario incompleto: %v", form)
	}
	return form, append(append([]*http.Cookie(nil), entrada...), w.Result().Cookies()...)
}

func enviarConfirmacion(s *Server, form url.Values, cookies []*http.Cookie, origen bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/verificar", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origen {
		r.Header.Set("Origin", "https://account.example.com")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestConfirmarRecuperacionExigePostCSRFYCorreo(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Fatalf("llamada inesperada: %s", r.URL)
		}
		canjes.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "recovery-access", RefreshToken: "recovery-refresh", ExpiresIn: 3600,
			User: gotrue.User{ID: "00000000-0000-0000-0000-000000000001", Email: "victima@example.com"}})
	})
	form, cookies := abrirConfirmacion(t, s, "/restablecer?token_hash=recovery-hash&email=attacker%40example.com")
	form.Set("email", " Victima@Example.COM ")

	if w := enviarConfirmacion(s, form, cookies, false); w.Code != http.StatusForbidden {
		t.Fatalf("POST sin origen: %d", w.Code)
	}
	if canjes.Load() != 0 {
		t.Fatal("el rechazo CSRF llegó al proveedor")
	}

	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/restablecer" {
		t.Fatalf("confirmar recuperación: %d %s", w.Code, w.Header().Get("Location"))
	}
	if canjes.Load() != 1 {
		t.Fatalf("canjes: %d", canjes.Load())
	}
	var capacidad bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case session.CookieName:
			t.Fatal("la recuperación creó una sesión general")
		case "__Secure-account_recovery":
			capacidad = c.Path == "/restablecer" && c.HttpOnly && c.Secure && c.MaxAge == 300
		}
	}
	if !capacidad {
		t.Fatal("no se emitió la capacidad de recuperación acotada")
	}
}

func TestConfirmarEnlaceValidaAntesDeCanjear(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		canjes.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	base, cookies := abrirConfirmacion(t, s, "/verificar?type=signup&token_hash=hash")
	casos := []struct {
		nombre string
		mutar  func(url.Values)
	}{
		{"tipo", func(v url.Values) { v.Set("type", "admin") }},
		{"hash", func(v url.Values) { v.Set("token_hash", "") }},
		{"correo", func(v url.Values) { v.Set("email", "no-es-correo") }},
	}
	for _, tc := range casos {
		t.Run(tc.nombre, func(t *testing.T) {
			form := url.Values{}
			for k, valores := range base {
				form[k] = append([]string(nil), valores...)
			}
			form.Set("email", "victima@example.com")
			tc.mutar(form)
			if w := enviarConfirmacion(s, form, cookies, true); w.Code != http.StatusBadRequest {
				t.Fatalf("status: %d", w.Code)
			}
		})
	}
	if canjes.Load() != 0 {
		t.Fatalf("entradas inválidas produjeron %d canjes", canjes.Load())
	}
}

func TestConfirmarEnlaceRechazaCorreoDistintoSinAutoridad(t *testing.T) {
	var canjes, cierres atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify":
			if canjes.Add(1) > 1 {
				http.Error(w, `{"msg":"invalid link"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "link-access", RefreshToken: "link-refresh", ExpiresIn: 3600,
				User: gotrue.User{ID: "00000000-0000-0000-0000-000000000001", Email: "provider-secret@example.com"}})
		case "/logout":
			cierres.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("llamada inesperada: %s", r.URL)
		}
	})
	form, cookies := abrirConfirmacion(t, s, "/restablecer?token_hash=one-use")
	form.Set("email", "victima@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "provider-secret@example.com") {
		t.Fatalf("rechazo inseguro: %d %s", w.Code, w.Body.String())
	}
	if canjes.Load() != 1 || cierres.Load() != 1 {
		t.Fatalf("canjes=%d cierres=%d", canjes.Load(), cierres.Load())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName || c.Name == "__Secure-account_recovery" || c.Name == cookieMFA {
			t.Fatalf("correo distinto emitió autoridad %s", c.Name)
		}
	}
	if w = enviarConfirmacion(s, form, cookies, true); w.Code != http.StatusBadRequest || canjes.Load() != 2 {
		t.Fatalf("el enlace de un uso se repitió: status=%d canjes=%d", w.Code, canjes.Load())
	}
}

func TestConfirmarEnlaceConFactorPreservaProposito(t *testing.T) {
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "factor-access", RefreshToken: "factor-refresh", ExpiresIn: 3600,
			User: gotrue.User{ID: "00000000-0000-0000-0000-000000000001", Email: "victima@example.com",
				Factors: []gotrue.Factor{{ID: "factor", Status: "verified", FactorType: "totp"}}}})
	})
	form, cookies := abrirConfirmacion(t, s, "/restablecer?token_hash=factor-hash")
	form.Set("email", "victima@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/factor" {
		t.Fatalf("factor: %d %s", w.Code, w.Header().Get("Location"))
	}
	var mfa *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieMFA {
			mfa = c
		}
		if c.Name == session.CookieName || c.Name == "__Secure-account_recovery" {
			t.Fatalf("factor pendiente emitió autoridad %s", c.Name)
		}
	}
	if mfa == nil {
		t.Fatal("no se emitió el factor pendiente")
	}
	txt, err := s.ses.Abrir(mfa.Value)
	if err != nil || !strings.Contains(txt, `"p":"recovery"`) {
		t.Fatalf("propósito MFA incorrecto: %q %v", txt, err)
	}
}

func TestCambioCorreoParcialNoEmiteAutoridad(t *testing.T) {
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(gotrue.Session{Msg: "Confirmation link accepted"})
	})
	form, cookies := abrirConfirmacion(t, s, "/verificar?type=email_change&token_hash=partial")
	form.Set("email", "victima@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "One confirmed, one to go") {
		t.Fatalf("confirmación parcial: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName || c.Name == "__Secure-account_recovery" || c.Name == cookieMFA {
			t.Fatalf("cambio parcial emitió autoridad %s", c.Name)
		}
	}
}

func TestConfirmarEnlacesOrdinariosCambiaSesionSoloTrasPost(t *testing.T) {
	st, _ := baseConsentimiento(t)
	type identidad struct {
		id    string
		email string
	}
	identidades := map[string]identidad{
		"signup":       {"00000000-0000-4000-8000-000000000051", "signup@example.com"},
		"invite":       {"00000000-0000-4000-8000-000000000052", "invite@example.com"},
		"email_change": {"00000000-0000-4000-8000-000000000053", "changed@example.com"},
		"magiclink":    {"00000000-0000-4000-8000-000000000054", "magic@example.com"},
		"email":        {"00000000-0000-4000-8000-000000000055", "email@example.com"},
	}
	var canjes atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify":
			var cuerpo map[string]string
			if json.NewDecoder(r.Body).Decode(&cuerpo) != nil || cuerpo["token_hash"] != "hash-"+cuerpo["type"] {
				http.Error(w, "bad verification body", http.StatusBadRequest)
				return
			}
			u, ok := identidades[cuerpo["type"]]
			if !ok {
				http.Error(w, "bad type", http.StatusBadRequest)
				return
			}
			canjes.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "access-" + cuerpo["type"], RefreshToken: "refresh", ExpiresIn: 3600,
				User: gotrue.User{ID: u.id, Email: u.email}})
		case "/user":
			typ := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer access-")
			u, ok := identidades[typ]
			if !ok {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: u.id, Email: u.email})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica, AdminGroup: "rol"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	victima := &gotrue.Session{AccessToken: "victim-access", RefreshToken: "victim-refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona, Email: "victim@example.com"}}
	emitida := httptest.NewRecorder()
	if _, err := s.ses.Crear(t.Context(), emitida, httptest.NewRequest(http.MethodGet, "/", nil), victima, "aal2", false); err != nil {
		t.Fatal(err)
	}
	cookieVictima := cookieSesion(emitida)

	for typ, u := range identidades {
		t.Run(typ, func(t *testing.T) {
			antes := canjes.Load()
			ruta := "/verificar?type=" + typ + "&token_hash=hash-" + typ + "&next=/welcome&email=attacker%40example.com"
			vista := httptest.NewRecorder()
			rVista := httptest.NewRequest(http.MethodGet, ruta, nil)
			rVista.AddCookie(cookieVictima)
			s.Handler().ServeHTTP(vista, rVista)
			if vista.Code != http.StatusOK || canjes.Load() != antes || !strings.Contains(vista.Body.String(), "victim@example.com") || strings.Contains(vista.Body.String(), "attacker@example.com") {
				t.Fatalf("GET inseguro: status=%d canjes=%d body=%s", vista.Code, canjes.Load()-antes, vista.Body.String())
			}

			form, cookies := abrirConfirmacion(t, s, ruta, cookieVictima)
			form.Set("email", strings.ToUpper(u.email))
			w := enviarConfirmacion(s, form, cookies, true)
			esperado := "/welcome"
			if typ == "invite" || typ == "email_change" {
				esperado = "/cuenta"
			}
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != esperado || canjes.Load() != antes+1 {
				t.Fatalf("POST: status=%d location=%s canjes=%d", w.Code, w.Header().Get("Location"), canjes.Load()-antes)
			}
			nueva := cookieSesion(w)
			if nueva == nil {
				t.Fatal("el POST confirmado no creó sesión")
			}
			actual, err := cargarCookie(s, nueva)
			if err != nil || actual == nil || actual.UserID != u.id || actual.Email != u.email {
				t.Fatalf("sesión equivocada: %+v %v", actual, err)
			}
			if typ == "invite" {
				var capacidad bool
				for _, c := range w.Result().Cookies() {
					capacidad = capacidad || c.Name == "__Secure-account_password_setup"
				}
				if !capacidad {
					t.Fatal("la invitación no conservó la capacidad de elegir contraseña")
				}
			}
		})
	}
}
