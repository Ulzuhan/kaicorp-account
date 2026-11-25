package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func TestCSRFOrigenFormulario(t *testing.T) {
	s := servidorMinimo()
	s.cfg.PublicURL, _ = url.Parse("https://ACCOUNT.example.com:443")
	for _, tc := range []struct {
		nombre   string
		origenes []string
		referer  []string
		valido   bool
	}{
		{"propio", []string{"https://account.example.com"}, nil, true},
		{"puerto por defecto", []string{"https://account.example.com:443"}, nil, true},
		{"hermano", []string{"https://evil.example.com"}, nil, false},
		{"padre", []string{"https://example.com"}, nil, false},
		{"esquema distinto", []string{"http://account.example.com"}, nil, false},
		{"puerto distinto", []string{"https://account.example.com:8443"}, nil, false},
		{"nulo", []string{"null"}, nil, false},
		{"vacío", []string{""}, nil, false},
		{"duplicado", []string{"https://account.example.com", "https://account.example.com"}, nil, false},
		{"lista", []string{"https://account.example.com https://evil.example.com"}, nil, false},
		{"usuario", []string{"https://evil@account.example.com"}, nil, false},
		{"ruta", []string{"https://account.example.com/"}, nil, false},
		{"query", []string{"https://account.example.com?"}, nil, false},
		{"fragmento", []string{"https://account.example.com#"}, nil, false},
		{"malformado", []string{"https://account.example.com:bad"}, nil, false},
		{"sin metadatos", nil, nil, false},
		{"referer propio", nil, []string{"https://account.example.com/entrar?next=/"}, true},
		{"referer hermano", nil, []string{"https://evil.example.com/form"}, false},
		{"referer usuario", nil, []string{"https://evil@account.example.com/form"}, false},
		{"referer relativo", nil, []string{"/entrar"}, false},
		{"referer duplicado", nil, []string{"https://account.example.com/a", "https://account.example.com/b"}, false},
		{"origin inválido no cae a referer", []string{"null"}, []string{"https://account.example.com/entrar"}, false},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/cuenta/password", nil)
			// Ni Host ni las cabeceras reenviadas definen el origen de confianza.
			r.Host = "evil.example.com"
			r.Header.Set("X-Forwarded-Host", "account.example.com")
			for _, o := range tc.origenes {
				r.Header.Add("Origin", o)
			}
			for _, v := range tc.referer {
				r.Header.Add("Referer", v)
			}
			if got := s.origenFormularioValido(r); got != tc.valido {
				t.Fatalf("origen válido: %v, quería %v", got, tc.valido)
			}
		})
	}
}

func TestCSRFGuardiaYDesarrolloHTTP(t *testing.T) {
	for _, seguro := range []bool{true, false} {
		u, _ := url.Parse("https://account.example.com")
		if !seguro {
			u, _ = url.Parse("http://localhost:3467")
		}
		m, err := session.New(make([]byte, 32), seguro, time.Hour, time.Hour, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(&config.Config{PublicURL: u}, nil, nil, m, nil)
		if err != nil {
			t.Fatal(err)
		}
		mint := httptest.NewRecorder()
		campo := m.CSRF(mint, httptest.NewRequest(http.MethodGet, "/entrar", nil), nil)
		for _, metadatos := range []string{"origin", "referer", "hermano", "ausentes"} {
			r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(url.Values{session.CSRFField: {campo}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(mint.Result().Cookies()[0])
			switch metadatos {
			case "origin":
				r.Header.Set("Origin", u.Scheme+"://"+u.Host)
			case "referer":
				r.Header.Set("Referer", u.String()+"/entrar")
			case "hermano":
				r.Header.Set("Origin", "https://evil.example.com")
			}
			w := httptest.NewRecorder()
			s.conCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
			want := http.StatusForbidden
			if metadatos == "origin" || metadatos == "referer" {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("Secure=%v, %s: HTTP %d, quería %d", seguro, metadatos, w.Code, want)
			}
		}
		// Una cookie de sesión borrada no liga el nuevo formulario anónimo.
		get := httptest.NewRequest(http.MethodGet, "/entrar", nil)
		get.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sesion-caducada"})
		w := httptest.NewRecorder()
		campo = m.CSRF(w, get, nil)
		r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(url.Values{session.CSRFField: {campo}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(w.Result().Cookies()[0])
		if !m.CSRFValido(r, nil) {
			t.Fatal("la sesión invalidada impidió volver a entrar")
		}
	}
}

func TestCSRFOrigenIPv6Canonico(t *testing.T) {
	s := servidorMinimo()
	s.cfg.PublicURL, _ = url.Parse("http://[0:0:0:0:0:0:0:1]:3467")
	for _, tc := range []struct {
		origen string
		valido bool
	}{
		{"http://[::1]:3467", true},
		{"http://[::2]:3467", false},
		{"http://127.0.0.1:3467", false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/entrar", nil)
		r.Header.Set("Origin", tc.origen)
		if got := s.origenFormularioValido(r); got != tc.valido {
			t.Fatalf("origen %s: %v, quería %v", tc.origen, got, tc.valido)
		}
	}
}

func TestCSRFProtegeMutacionesAutenticadas(t *testing.T) {
	var cambios atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" && r.Method == http.MethodGet {
			fmt.Fprint(w, `{"id":"`+consentPersona+`"}`)
			return
		}
		if r.URL.Path != "/user" || r.Method != http.MethodPut {
			t.Errorf("llamada inesperada al proveedor: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cambios.Add(1)
		fmt.Fprint(w, `{"id":"`+consentPersona+`"}`)
	})
	if err := s.st.Conceder(t.Context(), consentPersona, "rol", "test"); err != nil {
		t.Fatal(err)
	}
	a, victima := sesionMFA(t, s, consentPersona, "aal2", 3600)
	h := s.Handler()
	formulario := func(c *http.Cookie) (string, *http.Cookie) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/recuperar", nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		match := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if w.Code != http.StatusOK || len(match) != 2 {
			t.Fatal("no se pintó el formulario", w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == session.CSRFCookie {
				return match[1], c
			}
		}
		t.Fatal("no se emitió la cookie CSRF")
		return "", nil
	}
	publico, cookiePublica := formulario(nil)
	propio, cookiePropia := formulario(victima)
	destino := "00000000-0000-4000-8000-000000000055"
	for _, ruta := range []string{"/cuenta/password", "/restablecer", "/admin/conceder"} {
		post := func(campo string, csrf *http.Cookie, origen string, duplicada bool) *httptest.ResponseRecorder {
			form := url.Values{session.CSRFField: {campo}, "password": {"new-password-1234"}, "password2": {"new-password-1234"}, "user_id": {destino}, "grupo": {"rol"}}
			r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", origen)
			r.AddCookie(victima)
			r.AddCookie(csrf)
			if duplicada {
				r.AddCookie(cookiePropia)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w
		}
		for _, ataque := range []struct {
			campo     string
			cookie    *http.Cookie
			origen    string
			duplicada bool
		}{
			{publico, cookiePublica, "https://evil.example.com", false},
			{publico, cookiePublica, "https://account.example.com", false},
			{propio, cookiePropia, "https://evil.example.com", false},
			{publico, cookiePublica, "https://account.example.com", true},
		} {
			antes := cambios.Load()
			w := post(ataque.campo, ataque.cookie, ataque.origen, ataque.duplicada)
			if w.Code != http.StatusForbidden || cambios.Load() != antes {
				t.Fatalf("%s ejecutó un formulario forjado: %d", ruta, w.Code)
			}
			if ok, err := s.st.EsMiembro(t.Context(), destino, "rol"); err != nil || ok {
				t.Fatal("se concedió membresía mediante CSRF", ok, err)
			}
		}
		w := post(propio, cookiePropia, "https://account.example.com", false)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s rechazó el formulario legítimo: %d %s", ruta, w.Code, w.Body.String())
		}
	}
	// Un CSRF legítimo ya no basta para cambiar credenciales: cuenta exige la
	// contraseña actual y restablecer exige su capacidad de recuperación.
	if cambios.Load() != 0 {
		t.Fatal("un formulario sin prueba fresca llegó al proveedor", cambios.Load())
	}
	if ok, err := s.st.EsMiembro(t.Context(), destino, "rol"); err != nil || !ok {
		t.Fatal("la concesión legítima falló", ok, err)
	}
	// La misma cookie CSRF no mantiene el campo al rotar la autoridad a aal2.
	anterior := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookiePropia)
	viejo := s.ses.CSRF(anterior, r, a)
	copia := *a
	copia.ID = strings.Repeat("c", 64)
	post := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(url.Values{session.CSRFField: {viejo}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://account.example.com")
	post.AddCookie(cookiePropia)
	post = post.WithContext(context.WithValue(post.Context(), claveSesion, &copia))
	w := httptest.NewRecorder()
	s.conCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, post)
	if w.Code != http.StatusForbidden {
		t.Fatal("el formulario anterior sobrevivió al cambio de sesión", w.Code)
	}
}

func TestCSRFSesionCaducadaPermiteLogin(t *testing.T) {
	var llamadas atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != http.MethodPost {
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
		}
		llamadas.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error_code":"invalid_credentials","msg":"invalid"}`)
	})
	m, err := session.New(make([]byte, 32), true, -time.Hour, time.Hour, s.st, s.gt)
	if err != nil {
		t.Fatal(err)
	}
	s.ses = m
	_, caducada := sesionMFA(t, s, consentPersona, "aal2", 3600)
	h := s.Handler()
	get := httptest.NewRequest(http.MethodGet, "/entrar", nil)
	get.AddCookie(caducada)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, get)
	match := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || len(match) != 2 {
		t.Fatal("no se pintó el login tras invalidar la sesión", w.Code)
	}
	post := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(url.Values{
		session.CSRFField: {match[1]}, "email": {"test@example.com"}, "password": {"wrong-password"},
	}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://account.example.com")
	borrada := false
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName && c.MaxAge < 0 {
			borrada = true
		} else if c.Name == session.CSRFCookie {
			post.AddCookie(c)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if !borrada || w.Code != http.StatusUnauthorized || llamadas.Load() != 1 {
		t.Fatal("el login no llegó al proveedor después de borrar la cookie caducada", borrada, w.Code, llamadas.Load())
	}
}
