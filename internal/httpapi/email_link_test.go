package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	texttemplate "text/template"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
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

func rutaRecuperacionPrueba(t *testing.T, s *Server, hash, email string) string {
	t.Helper()
	intent, err := s.emitirIntencionRecuperacion(t.Context(), email)
	if err != nil {
		t.Fatal(err)
	}
	return "/restablecer?intent=" + url.QueryEscape(intent) + "#token_hash=" + url.QueryEscape(hash)
}

func rutaRegistroPrueba(t *testing.T, s *Server, hash, email, password string) string {
	t.Helper()
	intent, err := s.emitirIntencionRegistro(email, password)
	if err != nil {
		t.Fatal(err)
	}
	return "/verificar?type=signup&setup=" + url.QueryEscape(intent) + "#token_hash=" + url.QueryEscape(hash)
}

func rutaInvitacionPrueba(t *testing.T, s *Server, hash, email string) string {
	t.Helper()
	redirectTo, err := RedireccionInvitacion(s.cfg.PublicURL, s.ses, email)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("type", "invite")
	u.RawQuery = q.Encode()
	u.Fragment = "token_hash=" + url.QueryEscape(hash)
	return u.String()
}

func TestRedireccionInvitacionNormalizaDestinatario(t *testing.T) {
	s := servidorEnlaceSinStore(t, func(http.ResponseWriter, *http.Request) {})
	redirectTo, err := RedireccionInvitacion(s.cfg.PublicURL, s.ses, " Invite@Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatal(err)
	}
	intent := u.Query().Get("invite")
	if !s.validarIntencionInvitacion(intent, "invite@example.com") || s.validarIntencionInvitacion(intent, "Invite@Example.COM") {
		t.Fatal("la invitación no conservó el destinatario normalizado")
	}
}

func agregarQueryEnlace(t *testing.T, raw string, valores url.Values) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for nombre, lista := range valores {
		for _, valor := range lista {
			q.Add(nombre, valor)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func peticionEnlace(t *testing.T, metodo, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Fragment = ""
	return httptest.NewRequest(metodo, u.RequestURI(), nil)
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
		{"/restablecer", "recovery"},
	}
	for _, tc := range casos {
		for _, metodo := range []string{http.MethodGet, http.MethodHead} {
			t.Run(tc.typ+"_"+metodo, func(t *testing.T) {
				antes := canjes.Load()
				ruta := tc.ruta + "?type=" + tc.typ + "&email=attacker%40example.com#token_hash=hash"
				if tc.typ == "signup" {
					ruta = rutaRegistroPrueba(t, s, "hash", "victima@example.com", "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef")
				} else if tc.typ == "invite" {
					ruta = rutaInvitacionPrueba(t, s, "hash", "victima@example.com")
				} else if tc.typ == "recovery" {
					ruta = rutaRecuperacionPrueba(t, s, "hash", "victima@example.com")
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, peticionEnlace(t, metodo, ruta))
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
					if c.Name == session.CookieName || c.Name == "__Host-account_recovery" || c.Name == cookieMFA {
						t.Fatalf("navegar el enlace emitió autoridad %s", c.Name)
					}
				}
			})
		}
	}
}

func TestAliasAmbiguosSeRechazanSinCanjear(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(http.ResponseWriter, *http.Request) { canjes.Add(1) })
	for _, typ := range []string{"email", "magiclink"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, peticionEnlace(t, http.MethodGet, "/verificar?type="+typ+"#token_hash=hash"))
		if w.Code != http.StatusBadRequest || canjes.Load() != 0 {
			t.Fatalf("alias %s: status=%d canjes=%d", typ, w.Code, canjes.Load())
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, peticionEnlace(t, http.MethodGet, "/restablecer#token_hash=magic-hash"))
	if w.Code != http.StatusSeeOther || canjes.Load() != 0 {
		t.Fatalf("hash sin intención recovery: status=%d canjes=%d", w.Code, canjes.Load())
	}
}

func TestPlantillasCorreoPonenCapacidadSoloEnFragmento(t *testing.T) {
	datos := map[string]string{
		"SiteURL":    "https://account.example.com",
		"RedirectTo": "https://account.example.com/verificar?setup=proof",
		"TokenHash":  "capability-secret",
		"Email":      "victim@example.com",
		"NewEmail":   "new@example.com",
	}
	for _, nombre := range []string{"confirmacion.html", "invitacion.html", "recuperacion.html", "cambio-correo.html"} {
		t.Run(nombre, func(t *testing.T) {
			fuente, err := webPlantilla(nombre)
			if err != nil {
				t.Fatal(err)
			}
			plantilla, err := texttemplate.New(nombre).Parse(string(fuente))
			if err != nil {
				t.Fatal(err)
			}
			var salida bytes.Buffer
			if err := plantilla.Execute(&salida, datos); err != nil {
				t.Fatal(err)
			}
			html := salida.String()
			if !strings.Contains(html, "#token_hash=capability-secret") {
				t.Fatalf("la plantilla no puso la capacidad en fragmento: %s", html)
			}
			for _, inseguro := range []string{"?token_hash=capability-secret", "&token_hash=capability-secret", "&amp;token_hash=capability-secret"} {
				if strings.Contains(html, inseguro) {
					t.Fatalf("la plantilla puso la capacidad en la query (%q): %s", inseguro, html)
				}
			}
		})
	}
	magic, err := webPlantilla("magic.html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(magic, []byte("TokenHash")) || bytes.Contains(magic, []byte("token_hash")) {
		t.Fatal("la plantilla magic volvió a transportar una capacidad")
	}
}

func TestBordeHTTPDescartaCapacidadesDeLaQuery(t *testing.T) {
	var registros bytes.Buffer
	anterior := log.Writer()
	log.SetOutput(&registros)
	t.Cleanup(func() { log.SetOutput(anterior) })
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("una URL rechazada alcanzó al proveedor: %s", r.URL)
	})
	for _, ruta := range []string{
		"/verificar?type=email_change&token_hash=sentinel-secret",
		"/verificar?type=email_change&%74oken_hash=sentinel-secret",
		"/verificar?token_hash=uno&token_hash=sentinel-secret&type=email_change",
		"/verificar?type=email_change;token_hash=sentinel-secret",
		"/cualquier-ruta?token_hash=sentinel-secret",
		"/cuenta/correo/confirmar?token=sentinel-secret",
		"/cuenta//correo/confirmar?token=sentinel-secret",
		"/cuenta/x/../correo/confirmar?token=sentinel-secret",
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, ruta, nil))
		if w.Code != http.StatusSeeOther || w.Header().Get("Referrer-Policy") != "no-referrer" ||
			strings.Contains(w.Header().Get("Location"), "sentinel-secret") || strings.Contains(w.Body.String(), "sentinel-secret") {
			t.Fatalf("el borde no redactó %q: status=%d location=%q referrer=%q body=%q", ruta, w.Code,
				w.Header().Get("Location"), w.Header().Get("Referrer-Policy"), w.Body.String())
		}
	}
	if strings.Contains(registros.String(), "sentinel-secret") {
		t.Fatalf("el log del borde conservó la capacidad: %s", registros.String())
	}
}

func TestRecuperarEmiteIntencionLigadaAlCorreo(t *testing.T) {
	var redirectTo string
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/recover" || r.Method != http.MethodPost {
			t.Fatalf("llamada inesperada: %s %s", r.Method, r.URL)
		}
		redirectTo = r.URL.Query().Get("redirect_to")
		w.WriteHeader(http.StatusOK)
	})
	form := url.Values{"email": {" Victim@Example.COM "}}
	r := httptest.NewRequest(http.MethodPost, "/recuperar", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.recuperarPOST(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("recuperar: %d", w.Code)
	}
	u, err := url.Parse(redirectTo)
	if err != nil || u.Path != "/restablecer" {
		t.Fatalf("redirect recovery: %q %v", redirectTo, err)
	}
	intent := u.Query().Get("intent")
	if !s.intencionRecuperacionDisponible(intent) {
		t.Fatalf("intención ausente: %q", intent)
	}
	if !s.validarIntencionRecuperacion(intent, "victim@example.com") || s.validarIntencionRecuperacion(intent, "other@example.com") {
		t.Fatal("la intención no quedó ligada al correo")
	}
	if _, ok := s.validarIntencionRegistro(intent, "victim@example.com"); ok {
		t.Fatal("una intención recovery no debe valer para confirmar un registro")
	}
	setup, err := s.emitirIntencionRegistro("victim@example.com", "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if s.validarIntencionRecuperacion(setup, "victim@example.com") {
		t.Fatal("una intención signup no debe valer para recuperar una contraseña")
	}
	otro := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("la validación de la intención no debe llamar al proveedor: %s", r.URL.Path)
	})
	if !otro.validarIntencionRecuperacion(intent, "victim@example.com") {
		t.Fatal("la intención sellada debe sobrevivir un salto a otra réplica con la misma clave")
	}
	wmfa := httptest.NewRecorder()
	s.ponerPendienteMFA(wmfa, &gotrue.Session{
		AccessToken: "access", RefreshToken: "refresh",
		User: gotrue.User{ID: "00000000-0000-0000-0000-000000000001", Email: "victim@example.com"},
	}, "/", false, propositoRecuperacion)
	encontrada := false
	for _, c := range wmfa.Result().Cookies() {
		if c.Name == cookieMFA {
			encontrada = true
			if s.validarIntencionRecuperacion(c.Value, "victim@example.com") {
				t.Fatal("un sobre MFA no debe valer como intención de recuperación")
			}
		}
	}
	if !encontrada {
		t.Fatal("la prueba no encontró el sobre MFA")
	}
}

var campoOculto = regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)

func abrirConfirmacion(t *testing.T, s *Server, ruta string, entrada ...*http.Cookie) (url.Values, []*http.Cookie) {
	t.Helper()
	u, err := url.Parse(ruta)
	if err != nil {
		t.Fatal(err)
	}
	fragmento, err := url.ParseQuery(u.Fragment)
	if err != nil || len(fragmento["token_hash"]) != 1 || fragmento.Get("token_hash") == "" {
		t.Fatalf("fragmento de prueba inválido: %q %v", u.Fragment, err)
	}
	hash := fragmento.Get("token_hash")
	w := httptest.NewRecorder()
	r := peticionEnlace(t, http.MethodGet, ruta)
	for _, c := range entrada {
		r.AddCookie(c)
	}
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("abrir confirmación: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(w.Body.String(), "/static/js/email-link.js?") ||
		strings.Contains(w.Body.String(), `value="`+html.EscapeString(hash)+`"`) {
		t.Fatalf("intersticial expuso la capacidad: referrer=%q body=%s", w.Header().Get("Referrer-Policy"), w.Body.String())
	}
	form := url.Values{}
	for _, m := range campoOculto.FindAllStringSubmatch(w.Body.String(), -1) {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	if form.Get(session.CSRFField) == "" || form.Get("type") == "" || form.Get("token_hash") != "" {
		t.Fatalf("formulario incompleto: %v", form)
	}
	// Simula email-link.js: el fragmento nunca entró en la petición GET; sólo
	// se copia al cuerpo del POST después de limpiar la entrada de historial.
	form.Set("token_hash", hash)
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
	ruta := agregarQueryEnlace(t, rutaRecuperacionPrueba(t, s, "recovery-hash", "victima@example.com"), url.Values{"email": {"attacker@example.com"}})
	form, cookies := abrirConfirmacion(t, s, ruta)
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
		case "__Host-account_recovery":
			capacidad = c.Path == "/" && c.Domain == "" && c.HttpOnly && c.Secure && c.MaxAge == 300
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
	base, cookies := abrirConfirmacion(t, s, rutaRegistroPrueba(t, s, "hash", "victima@example.com", "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef"))
	casos := []struct {
		nombre string
		mutar  func(url.Values)
	}{
		{"tipo", func(v url.Values) { v.Set("type", "admin") }},
		{"tipo duplicado", func(v url.Values) { v["type"] = []string{"signup", "invite"} }},
		{"alias email", func(v url.Values) { v.Set("type", "email") }},
		{"alias magiclink", func(v url.Values) { v.Set("type", "magiclink") }},
		{"hash", func(v url.Values) { v.Set("token_hash", "") }},
		{"hash duplicado", func(v url.Values) { v["token_hash"] = []string{"hash", "otro"} }},
		{"correo", func(v url.Values) { v.Set("email", "no-es-correo") }},
		{"correo duplicado", func(v url.Values) { v["email"] = []string{"victima@example.com", "otra@example.com"} }},
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

func TestPropositoConfirmacionNoSePuedeSustituir(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(http.ResponseWriter, *http.Request) { canjes.Add(1) })
	s.resolverEnlaceCorreo = func(context.Context, string, string) (*store.EnlaceCorreoPendiente, error) {
		return &store.EnlaceCorreoPendiente{
			UserID:       "00000000-0000-4000-8000-000000000071",
			Destinatario: "victima@example.com",
			EmailFinal:   "victima@example.com",
			Hasta:        time.Now().Add(time.Hour),
		}, nil
	}

	registro, cookiesRegistro := abrirConfirmacion(t, s, rutaRegistroPrueba(t, s, "hash-signup", "victima@example.com", "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef"))
	registro.Set("email", "victima@example.com")
	registro.Set("type", "invite")
	if w := enviarConfirmacion(s, registro, cookiesRegistro, true); w.Code != http.StatusBadRequest {
		t.Fatalf("signup reinterpretado como invite: %d", w.Code)
	}

	invitacion, cookiesInvitacion := abrirConfirmacion(t, s, rutaInvitacionPrueba(t, s, "hash-invite", "victima@example.com"))
	invitacion.Set("email", "victima@example.com")
	invitacion.Set("type", "signup")
	if w := enviarConfirmacion(s, invitacion, cookiesInvitacion, true); w.Code != http.StatusBadRequest {
		t.Fatalf("invite reinterpretado como signup: %d", w.Code)
	}
	if canjes.Load() != 0 {
		t.Fatalf("sustituir propósito produjo %d canjes", canjes.Load())
	}
}

func TestConfirmarEnlaceRechazaCorreoDistintoAntesDeCanjear(t *testing.T) {
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
	s.resolverEnlaceCorreo = func(context.Context, string, string) (*store.EnlaceCorreoPendiente, error) {
		return &store.EnlaceCorreoPendiente{
			UserID:       "00000000-0000-0000-0000-000000000001",
			Destinatario: "provider-secret@example.com",
			EmailFinal:   "provider-secret@example.com",
			Hasta:        time.Now().Add(time.Hour),
		}, nil
	}
	form, cookies := abrirConfirmacion(t, s, rutaRecuperacionPrueba(t, s, "one-use", "victima@example.com"))
	form.Set("email", "victima@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "provider-secret@example.com") {
		t.Fatalf("rechazo inseguro: %d %s", w.Code, w.Body.String())
	}
	if canjes.Load() != 0 || cierres.Load() != 0 {
		t.Fatalf("canjes=%d cierres=%d", canjes.Load(), cierres.Load())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName || c.Name == "__Host-account_recovery" || c.Name == cookieMFA {
			t.Fatalf("correo distinto emitió autoridad %s", c.Name)
		}
	}
	if w = enviarConfirmacion(s, form, cookies, true); w.Code != http.StatusBadRequest || canjes.Load() != 0 {
		t.Fatalf("el rechazo local consumió el token: status=%d canjes=%d", w.Code, canjes.Load())
	}
}

func TestConfirmarEnlaceCaducadoNoSeCanjea(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(http.ResponseWriter, *http.Request) { canjes.Add(1) })
	s.resolverEnlaceCorreo = func(context.Context, string, string) (*store.EnlaceCorreoPendiente, error) {
		return &store.EnlaceCorreoPendiente{
			UserID:       "00000000-0000-4000-8000-000000000081",
			Destinatario: "victima@example.com",
			EmailFinal:   "victima@example.com",
			Hasta:        time.Now().Add(-time.Second),
		}, nil
	}
	form, cookies := abrirConfirmacion(t, s, rutaRecuperacionPrueba(t, s, "expired", "victima@example.com"))
	form.Set("email", "victima@example.com")
	if w := enviarConfirmacion(s, form, cookies, true); w.Code != http.StatusBadRequest {
		t.Fatalf("enlace caducado: status=%d body=%s", w.Code, w.Body.String())
	}
	if canjes.Load() != 0 {
		t.Fatalf("el enlace caducado llegó %d veces a /verify", canjes.Load())
	}
}

func TestConfirmarEnlaceConFactorPreservaProposito(t *testing.T) {
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "factor-access", RefreshToken: "factor-refresh", ExpiresIn: 3600,
			User: gotrue.User{ID: "00000000-0000-0000-0000-000000000001", Email: "victima@example.com",
				Factors: []gotrue.Factor{{ID: "factor", Status: "verified", FactorType: "totp"}}}})
	})
	form, cookies := abrirConfirmacion(t, s, rutaRecuperacionPrueba(t, s, "factor-hash", "victima@example.com"))
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
		if c.Name == session.CookieName || c.Name == "__Host-account_recovery" {
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
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		canjes.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.Session{Msg: "Confirmation link accepted"})
	})
	s.resolverEnlaceCorreo = func(_ context.Context, typ, hash string) (*store.EnlaceCorreoPendiente, error) {
		if typ != "email_change" || hash != "partial" {
			return nil, store.ErrNoExiste
		}
		return &store.EnlaceCorreoPendiente{
			UserID:       "00000000-0000-4000-8000-000000000053",
			Destinatario: "victima@example.com",
			EmailFinal:   "nueva@example.com",
			Hasta:        time.Now().Add(time.Hour),
		}, nil
	}
	form, cookies := abrirConfirmacion(t, s, "/verificar?type=email_change#token_hash=partial")
	form.Set("email", "attacker@example.com")
	if rechazada := enviarConfirmacion(s, form, cookies, true); rechazada.Code != http.StatusBadRequest || canjes.Load() != 0 {
		t.Fatalf("correo distinto consumió el enlace parcial: status=%d canjes=%d", rechazada.Code, canjes.Load())
	}
	form.Set("email", "victima@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "One confirmed, one to go") || canjes.Load() != 1 {
		t.Fatalf("confirmación parcial: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName || c.Name == "__Host-account_recovery" || c.Name == cookieMFA {
			t.Fatalf("cambio parcial emitió autoridad %s", c.Name)
		}
	}
}

func TestCambioCorreoSeguroAceptaAmbosOrdenesYNoRepiteLaPrimeraMitad(t *testing.T) {
	st, _ := baseConsentimiento(t)
	type estadoCambio struct {
		mu        sync.Mutex
		userID    string
		pendiente map[string]string
		canjes    int
	}
	var estado *estadoCambio
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		var cuerpo map[string]string
		if json.NewDecoder(r.Body).Decode(&cuerpo) != nil || cuerpo["type"] != "email_change" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		estado.mu.Lock()
		defer estado.mu.Unlock()
		if _, ok := estado.pendiente[cuerpo["token_hash"]]; !ok {
			http.Error(w, `{"error_code":"otp_expired"}`, http.StatusBadRequest)
			return
		}
		delete(estado.pendiente, cuerpo["token_hash"])
		estado.canjes++
		if len(estado.pendiente) == 1 {
			_ = json.NewEncoder(w).Encode(gotrue.Session{Msg: "Confirmation link accepted"})
			return
		}
		_ = json.NewEncoder(w).Encode(gotrue.Session{
			AccessToken: "access-final", RefreshToken: "refresh-final", ExpiresIn: 3600,
			User: gotrue.User{ID: estado.userID, Email: "new@example.com"},
		})
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
	s.resolverEnlaceCorreo = func(_ context.Context, typ, hash string) (*store.EnlaceCorreoPendiente, error) {
		if typ != "email_change" {
			return nil, store.ErrNoExiste
		}
		estado.mu.Lock()
		defer estado.mu.Unlock()
		destinatario, ok := estado.pendiente[hash]
		if !ok {
			return nil, store.ErrNoExiste
		}
		return &store.EnlaceCorreoPendiente{UserID: estado.userID, Destinatario: destinatario,
			EmailFinal: "new@example.com", Hasta: time.Now().Add(time.Hour)}, nil
	}

	for i, orden := range [][]string{{"hash-old", "hash-new"}, {"hash-new", "hash-old"}} {
		t.Run(strings.Join(orden, "_then_"), func(t *testing.T) {
			estado = &estadoCambio{
				userID:    fmt.Sprintf("00000000-0000-4000-8000-%012d", 90+i),
				pendiente: map[string]string{"hash-old": "old@example.com", "hash-new": "new@example.com"},
			}
			confirmar := func(hash string) *httptest.ResponseRecorder {
				form, cookies := abrirConfirmacion(t, s, "/verificar?type=email_change#token_hash="+hash)
				form.Set("email", map[string]string{"hash-old": "old@example.com", "hash-new": "new@example.com"}[hash])
				return enviarConfirmacion(s, form, cookies, true)
			}
			primera := confirmar(orden[0])
			if primera.Code != http.StatusOK || !strings.Contains(primera.Body.String(), "One confirmed, one to go") || cookieSesion(primera) != nil {
				t.Fatalf("primera mitad: status=%d body=%s", primera.Code, primera.Body.String())
			}
			repetida := confirmar(orden[0])
			if repetida.Code != http.StatusBadRequest {
				t.Fatalf("primera mitad repetida: status=%d", repetida.Code)
			}
			segunda := confirmar(orden[1])
			if segunda.Code != http.StatusSeeOther || segunda.Header().Get("Location") != "/cuenta" || cookieSesion(segunda) == nil {
				t.Fatalf("segunda mitad: status=%d location=%s", segunda.Code, segunda.Header().Get("Location"))
			}
			estado.mu.Lock()
			canjes := estado.canjes
			estado.mu.Unlock()
			if canjes != 2 {
				t.Fatalf("canjes=%d, quería sólo las dos mitades", canjes)
			}
		})
	}
}

func TestRespuestaParcialNoSeAceptaParaOtroProposito(t *testing.T) {
	var canjes atomic.Int32
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, _ *http.Request) {
		canjes.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.Session{Msg: "unexpected partial"})
	})
	s.resolverEnlaceCorreo = func(context.Context, string, string) (*store.EnlaceCorreoPendiente, error) {
		return &store.EnlaceCorreoPendiente{
			UserID:       "00000000-0000-4000-8000-000000000052",
			Destinatario: "invite@example.com",
			EmailFinal:   "invite@example.com",
			Hasta:        time.Now().Add(time.Hour),
		}, nil
	}
	form, cookies := abrirConfirmacion(t, s, rutaInvitacionPrueba(t, s, "partial-invite", "invite@example.com"))
	form.Set("email", "invite@example.com")
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusBadGateway || canjes.Load() != 1 || strings.Contains(w.Body.String(), "One confirmed") {
		t.Fatalf("respuesta parcial no ligada al propósito: status=%d canjes=%d body=%s", w.Code, canjes.Load(), w.Body.String())
	}
}

func TestResolverEnlaceCorreoLigaPropositoBuzonYUsuario(t *testing.T) {
	st, db := baseConsentimiento(t)
	const (
		altaID   = "00000000-0000-4000-8000-000000000061"
		inviteID = "00000000-0000-4000-8000-000000000062"
		recID    = "00000000-0000-4000-8000-000000000063"
		cambioID = "00000000-0000-4000-8000-000000000064"
	)
	if _, err := db.Exec(t.Context(), `insert into auth.users
		(id,email,confirmation_token,confirmation_sent_at,recovery_token,recovery_sent_at,
		 email_change,email_change_token_current,email_change_token_new,email_change_sent_at,email_change_confirm_status,invited_at)
		values
		($1,'signup@example.com','hash-signup',now(),'',null,'','','',null,0,null),
		($2,'invite@example.com','hash-invite',now(),'',null,'','','',null,0,now()),
		($3,'recovery@example.com','',null,'hash-recovery',now(),'','','',null,0,null),
		($4,'old@example.com','',null,'',null,'new@example.com','hash-old','hash-new',now(),0,null)`,
		altaID, inviteID, recID, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.one_time_tokens(user_id,token_type,token_hash,relates_to) values
		($1,'confirmation_token','hash-signup','signup@example.com'),
		($2,'confirmation_token','hash-invite','invite@example.com'),
		($3,'recovery_token','hash-recovery','recovery@example.com'),
		($4,'email_change_token_current','hash-old','old@example.com'),
		($4,'email_change_token_new','hash-new','new@example.com')`, altaID, inviteID, recID, cambioID); err != nil {
		t.Fatal(err)
	}
	casos := []struct {
		tipo, hash, id, destinatario, final string
	}{
		{"signup", "hash-signup", altaID, "signup@example.com", "signup@example.com"},
		{"invite", "hash-invite", inviteID, "invite@example.com", "invite@example.com"},
		{"recovery", "hash-recovery", recID, "recovery@example.com", "recovery@example.com"},
		{"email_change", "hash-old", cambioID, "old@example.com", "new@example.com"},
		{"email_change", "hash-new", cambioID, "new@example.com", "new@example.com"},
	}
	for _, tc := range casos {
		t.Run(tc.tipo+"/"+tc.hash, func(t *testing.T) {
			enlace, err := st.ResolverEnlaceCorreo(t.Context(), tc.tipo, tc.hash, vidaEnlaceCorreo(tc.tipo))
			if enlace != nil {
				defer enlace.Cerrar()
			}
			if err != nil || enlace.UserID != tc.id || enlace.Destinatario != tc.destinatario || enlace.EmailFinal != tc.final || !time.Now().Before(enlace.Hasta) {
				t.Fatalf("vínculo incorrecto: %+v %v", enlace, err)
			}
		})
	}
	if _, err := st.ResolverEnlaceCorreo(t.Context(), "signup", "hash-invite", 24*time.Hour); err != store.ErrNoExiste {
		t.Fatalf("invite reinterpretado como signup: %v", err)
	}

	// GoTrue 2.189 elimina auth.one_time_tokens al consumir cada mitad. Aunque
	// una carrera restaurase la columna antigua de auth.users, no revive el hash.
	if _, err := db.Exec(t.Context(), `delete from auth.one_time_tokens
		where user_id=$1 and token_type='email_change_token_current'`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `update auth.users set email_change_confirm_status=1,
		email_change_token_current='hash-old',email_change_token_new='hash-new' where id=$1`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResolverEnlaceCorreo(t.Context(), "email_change", "hash-old", 24*time.Hour); err != store.ErrNoExiste {
		t.Fatalf("hash viejo ya consumido siguió pendiente: %v", err)
	}
	if enlace, err := st.ResolverEnlaceCorreo(t.Context(), "email_change", "hash-new", 24*time.Hour); err != nil {
		t.Fatalf("hash nuevo restante rechazado: %v", err)
	} else {
		enlace.Cerrar()
	}
	if _, err := db.Exec(t.Context(), `delete from auth.one_time_tokens where user_id=$1`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.one_time_tokens(user_id,token_type,token_hash,relates_to)
		values($1,'email_change_token_current','hash-old','old@example.com')`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `update auth.users set
		email_change_token_current='hash-old',email_change_token_new='hash-new' where id=$1`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResolverEnlaceCorreo(t.Context(), "email_change", "hash-new", 24*time.Hour); err != store.ErrNoExiste {
		t.Fatalf("hash nuevo ya consumido siguió pendiente: %v", err)
	}
	if enlace, err := st.ResolverEnlaceCorreo(t.Context(), "email_change", "hash-old", 24*time.Hour); err != nil {
		t.Fatalf("hash viejo restante rechazado: %v", err)
	} else {
		enlace.Cerrar()
	}

	if _, err := db.Exec(t.Context(), `update auth.one_time_tokens set relates_to='attacker@example.com'
		where user_id=$1 and token_type='recovery_token'`, recID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResolverEnlaceCorreo(t.Context(), "recovery", "hash-recovery", 24*time.Hour); err != store.ErrNoExiste {
		t.Fatalf("token con destinatario distinto siguió pendiente: %v", err)
	}

	if _, err := db.Exec(t.Context(), `update auth.users set
		confirmation_sent_at=case when id in ($1,$2) then now()-interval '25 hours' else confirmation_sent_at end,
		recovery_sent_at=case when id=$3 then now()-interval '2 hours' else recovery_sent_at end,
		email_change_sent_at=case when id=$4 then now()-interval '25 hours' else email_change_sent_at end,
		email_change_confirm_status=case when id=$4 then 0 else email_change_confirm_status end,
		email_change_token_current=case when id=$4 then 'hash-old' else email_change_token_current end,
		email_change_token_new=case when id=$4 then 'hash-new' else email_change_token_new end
		where id in ($1,$2,$3,$4)`,
		altaID, inviteID, recID, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `update auth.one_time_tokens set relates_to='recovery@example.com' where user_id=$1`, recID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `delete from auth.one_time_tokens where user_id=$1`, cambioID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.one_time_tokens(user_id,token_type,token_hash,relates_to) values
		($1,'email_change_token_current','hash-old','old@example.com'),
		($1,'email_change_token_new','hash-new','new@example.com')`, cambioID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range casos {
		if _, err := st.ResolverEnlaceCorreo(t.Context(), tc.tipo, tc.hash, vidaEnlaceCorreo(tc.tipo)); err != store.ErrNoExiste {
			t.Errorf("%s/%s caducado siguió pendiente: %v", tc.tipo, tc.hash, err)
		}
	}
}

func TestResolverEnlaceCorreoSerializaMitadesDelMismoCambio(t *testing.T) {
	st, db := baseConsentimiento(t)
	const id = "00000000-0000-4000-8000-000000000065"
	if _, err := db.Exec(t.Context(), `insert into auth.users
		(id,email,email_change,email_change_sent_at,email_change_confirm_status)
		values($1,'old@example.com','new@example.com',now(),0)`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.one_time_tokens(user_id,token_type,token_hash,relates_to) values
			($1,'email_change_token_current','hash-old-lock','old@example.com'),
			($1,'email_change_token_new','hash-new-lock','new@example.com')`, id); err != nil {
		t.Fatal(err)
	}
	primero, err := st.ResolverEnlaceCorreo(t.Context(), "email_change", "hash-old-lock", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer primero.Cerrar()
	type resultado struct {
		enlace *store.EnlaceCorreoPendiente
		err    error
	}
	iniciada := make(chan struct{})
	terminada := make(chan resultado, 1)
	go func() {
		close(iniciada)
		enlace, err := st.ResolverEnlaceCorreo(context.Background(), "email_change", "hash-new-lock", 24*time.Hour)
		terminada <- resultado{enlace: enlace, err: err}
	}()
	<-iniciada
	select {
	case r := <-terminada:
		if r.enlace != nil {
			r.enlace.Cerrar()
		}
		t.Fatalf("la segunda mitad atravesó el bloqueo: %v", r.err)
	case <-time.After(150 * time.Millisecond):
	}
	primero.Cerrar()
	select {
	case r := <-terminada:
		if r.enlace != nil {
			r.enlace.Cerrar()
		}
		if r.err != nil {
			t.Fatalf("la segunda mitad falló al liberar el bloqueo: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("la segunda mitad no continuó al liberar el bloqueo")
	}
}

func TestAltaPublicaNoReclasificaInvitacionPendiente(t *testing.T) {
	st, db := baseConsentimiento(t)
	const id = "00000000-0000-4000-8000-000000000072"
	if _, err := db.Exec(t.Context(), `insert into auth.users
		(id,email,confirmation_token,invited_at) values ($1,'invite@example.com','hash-invite',now())`, id); err != nil {
		t.Fatal(err)
	}
	var llamadas atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		llamadas.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "service-test")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	preparada, err := s.prepararPendienteExistente(t.Context(), "invite@example.com", "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil || preparada {
		t.Fatalf("invitación reclasificable: preparada=%v err=%v", preparada, err)
	}
	if llamadas.Load() != 0 {
		t.Fatalf("la preparación llamó %d veces al proveedor", llamadas.Load())
	}
	var hash string
	if err := db.QueryRow(t.Context(), `select confirmation_token from auth.users where id=$1`, id).Scan(&hash); err != nil || hash != "hash-invite" {
		t.Fatalf("token de invitación alterado: %q %v", hash, err)
	}
}

func TestConfirmarEnlacesAgrupaAliasPorAutoridad(t *testing.T) {
	st, _ := baseConsentimiento(t)
	type identidad struct {
		id    string
		email string
	}
	identidades := map[string]identidad{
		"signup":       {"00000000-0000-4000-8000-000000000051", "signup@example.com"},
		"invite":       {"00000000-0000-4000-8000-000000000052", "invite@example.com"},
		"email_change": {"00000000-0000-4000-8000-000000000053", "changed@example.com"},
	}
	var canjes, rotacionesAlta atomic.Int32
	var mu sync.Mutex
	passwordsPendientes := map[string]string{}
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/verify":
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
		case strings.HasPrefix(r.URL.Path, "/admin/users/") && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer service-test" {
				http.Error(w, "bad service token", http.StatusUnauthorized)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/admin/users/")
			var typ string
			var u identidad
			for candidato, identidad := range identidades {
				if identidad.id == id {
					typ, u = candidato, identidad
					break
				}
			}
			if typ != "signup" && typ != "invite" {
				http.Error(w, "bad admin target", http.StatusBadRequest)
				return
			}
			var cuerpo map[string]string
			if json.NewDecoder(r.Body).Decode(&cuerpo) != nil || cuerpo["password"] == "" {
				http.Error(w, "bad password", http.StatusBadRequest)
				return
			}
			mu.Lock()
			passwordsPendientes[typ] = cuerpo["password"]
			mu.Unlock()
			rotacionesAlta.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: u.id, Email: u.email})
		case r.URL.Path == "/token" && r.Method == http.MethodPost:
			var cuerpo map[string]string
			_ = json.NewDecoder(r.Body).Decode(&cuerpo)
			var typ string
			var u identidad
			mu.Lock()
			for candidato, identidad := range identidades {
				if identidad.email == cuerpo["email"] && passwordsPendientes[candidato] == cuerpo["password"] {
					typ, u = candidato, identidad
					break
				}
			}
			mu.Unlock()
			if typ == "" {
				http.Error(w, `{"error_code":"invalid_credentials","msg":"bad"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "rotated-" + typ, RefreshToken: "refresh-rotated", ExpiresIn: 3600,
				User: gotrue.User{ID: u.id, Email: u.email}})
		case r.URL.Path == "/user" && r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer victim-access":
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "victim@example.com"})
		case r.URL.Path == "/user" && r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer access-email_change":
			u := identidades["email_change"]
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: u.id, Email: u.email})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "service-test")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica, AdminGroup: "rol"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.resolverEnlaceCorreo = func(_ context.Context, typ, hash string) (*store.EnlaceCorreoPendiente, error) {
		u, ok := identidades[typ]
		if !ok || hash != "hash-"+typ {
			return nil, store.ErrNoExiste
		}
		return &store.EnlaceCorreoPendiente{UserID: u.id, Destinatario: u.email, EmailFinal: u.email, Hasta: time.Now().Add(time.Hour)}, nil
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
			ruta := "/verificar?type=" + typ + "&next=/welcome&email=attacker%40example.com#token_hash=hash-" + typ
			if typ == "signup" {
				ruta = agregarQueryEnlace(t, rutaRegistroPrueba(t, s, "hash-signup", u.email, "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef"),
					url.Values{"next": {"/welcome"}, "email": {"attacker@example.com"}})
			} else if typ == "invite" {
				ruta = agregarQueryEnlace(t, rutaInvitacionPrueba(t, s, "hash-invite", u.email),
					url.Values{"next": {"/welcome"}, "email": {"attacker@example.com"}})
			}
			vista := httptest.NewRecorder()
			rVista := peticionEnlace(t, http.MethodGet, ruta)
			rVista.AddCookie(cookieVictima)
			s.Handler().ServeHTTP(vista, rVista)
			if vista.Code != http.StatusOK || canjes.Load() != antes || !strings.Contains(vista.Body.String(), "victim@example.com") || strings.Contains(vista.Body.String(), "attacker@example.com") {
				t.Fatalf("GET inseguro: status=%d canjes=%d body=%s", vista.Code, canjes.Load()-antes, vista.Body.String())
			}

			form, cookies := abrirConfirmacion(t, s, ruta, cookieVictima)
			form.Set("email", strings.ToUpper(u.email))
			w := enviarConfirmacion(s, form, cookies, true)
			esperado := "/welcome"
			if typ == "signup" || typ == "invite" {
				esperado = rutaPasswordRegistro
			} else if typ == "email_change" {
				esperado = "/cuenta"
			}
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != esperado || canjes.Load() != antes+1 {
				t.Fatalf("POST: status=%d location=%s canjes=%d", w.Code, w.Header().Get("Location"), canjes.Load()-antes)
			}
			nueva := cookieSesion(w)
			if typ == "signup" || typ == "invite" {
				if nueva != nil {
					t.Fatal("el alta o invitación creó sesión antes de elegir contraseña")
				}
				nombreCapacidad := "__Host-account_signup_setup"
				if typ == "invite" {
					nombreCapacidad = "__Host-account_password_setup"
				}
				var capacidad bool
				for _, c := range w.Result().Cookies() {
					capacidad = capacidad || c.Name == nombreCapacidad && c.Path == "/" && c.MaxAge == 300
				}
				if !capacidad {
					t.Fatal("el alta o invitación no emitió la capacidad acotada para elegir contraseña")
				}
				return
			}
			if nueva == nil {
				t.Fatal("el POST confirmado no creó sesión")
			}
			actual, err := cargarCookie(s, nueva)
			if err != nil || actual == nil || actual.UserID != u.id || actual.Email != u.email {
				t.Fatalf("sesión equivocada: %+v %v", actual, err)
			}
		})
	}
	if rotacionesAlta.Load() != 1 {
		t.Fatalf("rotaciones de contraseña al confirmar signup/invite: %d", rotacionesAlta.Load())
	}
}
