package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
	"github.com/Ulzuhan/kaicorp-account/internal/web"
)

func servidorMinimo() *Server {
	u, _ := url.Parse("https://account.example.com")
	return &Server{cfg: &config.Config{PublicURL: u}, limitador: nuevoLimitador()}
}

type fakeSesionStore struct {
	grupos      []store.Grupo
	membresias  []store.Membresia
	solicitudes []store.Solicitud
}

func (f fakeSesionStore) Grupos(context.Context) ([]store.Grupo, error) { return f.grupos, nil }
func (f fakeSesionStore) MembresiasDe(context.Context, string) ([]store.Membresia, error) {
	return f.membresias, nil
}
func (f fakeSesionStore) SolicitudesDe(context.Context, string) ([]store.Solicitud, error) {
	return f.solicitudes, nil
}
func (f fakeSesionStore) EsMiembro(_ context.Context, _ string, grupo string) (bool, error) {
	for _, m := range f.membresias {
		if m.Grupo == grupo {
			return true, nil
		}
	}
	return false, nil
}

func TestNextSeguro(t *testing.T) {
	s := servidorMinimo()
	casos := map[string]string{
		"":                                   "/",
		"/solicitar/docdrop":                 "/solicitar/docdrop",
		"//evil.example":                     "/",
		"/\\evil.example":                    "/",
		"https://evil.example/x":             "/",
		"https://account.example.com/cuenta": "/cuenta",
		"http://account.example.com/cuenta":  "/",
		"javascript:alert(1)":                "/",
	}
	for in, want := range casos {
		if got := s.nextSeguro(in); got != want {
			t.Errorf("nextSeguro(%q) = %q, quería %q", in, got, want)
		}
	}
}

func TestCorreoValido(t *testing.T) {
	if _, ok := correoValido(" Alguien@Ejemplo.com "); !ok {
		t.Fatal("un correo normal tiene que valer, recortado y en minúsculas")
	}
	for _, malo := range []string{"", "sin-arroba", "Nombre <a@b.c>", "a@b.c, d@e.f"} {
		if _, ok := correoValido(malo); ok {
			t.Errorf("%q no debería valer", malo)
		}
	}
}

func TestLimitadorFrenaYRecarga(t *testing.T) {
	l := nuevoLimitador()
	for i := 0; i < 3; i++ {
		if !l.permite("x", 3, 60) {
			t.Fatalf("intento %d dentro del cupo tenía que pasar", i)
		}
	}
	if l.permite("x", 3, 60) {
		t.Fatal("el cuarto tenía que frenar")
	}
	if !l.permite("y", 3, 60) {
		t.Fatal("otra clave tiene su propio cubo")
	}
}

// Todas las páginas compilan con el layout, y ninguna plantilla del directorio
// se queda fuera de la lista (que es lo que daba «plantilla desconocida»).
func TestPlantillasCompilan(t *testing.T) {
	for _, p := range paginas {
		if _, err := template.New("layout.html").ParseFS(web.EmbeddedFS, "templates/layout.html", "templates/"+p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	entradas, err := fs.ReadDir(web.EmbeddedFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	listadas := map[string]bool{"layout.html": true}
	for _, p := range paginas {
		listadas[p] = true
	}
	for _, e := range entradas {
		if !listadas[e.Name()] {
			t.Errorf("templates/%s existe pero no está en `paginas`", e.Name())
		}
	}
}

func TestGrupoSSOURL(t *testing.T) {
	g := store.Grupo{URL: "https://tabup.example.com"}
	if got, want := g.SSOURL(), "https://tabup.example.com/?sso=1"; got != want {
		t.Fatalf("SSOURL() = %q, quería %q", got, want)
	}
	gSlash := store.Grupo{URL: "https://docdrop.example.com/"}
	if got, want := gSlash.SSOURL(), "https://docdrop.example.com/?sso=1"; got != want {
		t.Fatalf("SSOURL() con barra = %q, quería %q", got, want)
	}
}

func TestHomeUsaSSOURL(t *testing.T) {
	tpl, err := template.New("layout.html").ParseFS(web.EmbeddedFS, "templates/layout.html", "templates/home.html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, "layout.html", map[string]any{
		"Title":      "Your tools",
		"User":       &session.Actual{UserID: "u1", Email: "ada@example.com", Nombre: "Ada"},
		"Concedidas": 1,
		"Herramientas": []herramientaVista{{
			Grupo:   store.Grupo{Nombre: "tabup", Titulo: "TabUp", URL: "https://tabup.example.com", Solicitable: true},
			Miembro: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `href="https://tabup.example.com/?sso=1"`) {
		t.Fatalf("home.html debe enlazar ?sso=1 en herramientas concedidas:\n%s", buf.String())
	}
}

func TestAPISesion(t *testing.T) {
	u, _ := url.Parse("https://account.example.com")
	s := &Server{
		cfg: &config.Config{
			PublicURL:  u,
			AdminGroup: "account-admin",
			SessionOrigins: []string{
				"https://example.com",
				"https://tabup.example.com",
				"https://docdrop.example.com",
				"https://link.example.com",
				"https://chorus.example.com",
			},
		},
		limitador: nuevoLimitador(),
		stSesion: fakeSesionStore{
			grupos: []store.Grupo{
				{Nombre: "tabup", URL: "https://tabup.example.com", Solicitable: true},
				{Nombre: "docdrop", URL: "https://docdrop.example.com", Solicitable: true},
				{Nombre: "linkup", URL: "https://link.example.com", Solicitable: true},
				{Nombre: "chorus", URL: "https://chorus.example.com", Solicitable: false},
				{Nombre: "account-admin", URL: "", Solicitable: false},
			},
			membresias: []store.Membresia{
				{UserID: "u1", Grupo: "tabup"},
				{UserID: "u1", Grupo: "account-admin"},
			},
			solicitudes: []store.Solicitud{
				{UserID: "u1", Grupo: "docdrop", Estado: "pendiente"},
			},
		},
	}

	call := func(origin string, withSession bool) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if withSession {
			req = req.WithContext(context.WithValue(req.Context(), claveSesion, &session.Actual{
				UserID: "u1", Email: "ada@example.com", Nombre: "Ada",
			}))
		}
		rec := httptest.NewRecorder()
		s.apiSesion(rec, req)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("JSON inválido: %v (%s)", err, rec.Body.String())
		}
		return rec, body
	}

	// 1. Anónimo
	rec, body := call("https://example.com", false)
	if body["signed_in"] != false {
		t.Fatalf("anónimo esperaba signed_in=false, llegó %#v", body)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("faltaba CORS para origen permitido")
	}

	// 2. Origen ajeno: sin CORS y sin listas ni tool_access
	rec, body = call("https://evil.example", true)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("no debía emitir CORS para origen ajeno")
	}
	if _, ok := body["granted"]; ok {
		t.Fatalf("no debía exponer granted a origen ajeno: %#v", body)
	}
	if _, ok := body["tool_access"]; ok {
		t.Fatalf("no debía exponer tool_access a origen ajeno: %#v", body)
	}

	// 3. Portal principal: devuelve granted y pending (sin roles)
	rec, body = call("https://example.com", true)
	if body["signed_in"] != true || body["name"] != "Ada" || body["admin"] != true {
		t.Fatalf("campos base inesperados: %#v", body)
	}
	if got := toStringSlice(t, body["granted"]); !slices.Equal(got, []string{"tabup.example.com"}) {
		t.Fatalf("granted = %v, quería [tabup.example.com]", got)
	}
	if got := toStringSlice(t, body["pending"]); !slices.Equal(got, []string{"docdrop.example.com"}) {
		t.Fatalf("pending = %v, quería [docdrop.example.com]", got)
	}
	if _, ok := body["tool_access"]; ok {
		t.Fatalf("portal no debe recibir tool_access: %#v", body)
	}

	// 4. Cuatro estados por origen de herramienta (sin filtrar otras apps)
	estados := map[string]string{
		"https://tabup.example.com":   "granted",
		"https://docdrop.example.com": "pending",
		"https://link.example.com":    "requestable",
		"https://chorus.example.com":  "invite_only",
	}
	for orig, want := range estados {
		rec, body = call(orig, true)
		if rec.Header().Get("Access-Control-Allow-Origin") != orig {
			t.Fatalf("%s: faltaba ACAO", orig)
		}
		if body["tool_access"] != want {
			t.Fatalf("%s: tool_access = %v, quería %q", orig, body["tool_access"], want)
		}
		if body["account_url"] != "https://account.example.com/" {
			t.Fatalf("%s: account_url = %v", orig, body["account_url"])
		}
		if _, ok := body["granted"]; ok {
			t.Fatalf("%s: una herramienta no debe ver la lista global granted", orig)
		}
	}
}

func toStringSlice(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("se esperaba []any, llegó %T (%#v)", v, v)
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		s, ok := x.(string)
		if !ok {
			t.Fatalf("elemento %d no string: %T", i, x)
		}
		out[i] = s
	}
	return out
}
