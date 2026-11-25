package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
	"github.com/Ulzuhan/kaicorp-account/internal/web"
)

func servidorMinimo() *Server {
	u, _ := url.Parse("https://account.example.com")
	return &Server{cfg: &config.Config{PublicURL: u}, limitador: nuevoLimitador()}
}

func servidorMiddlewarePrueba(t *testing.T) *Server {
	t.Helper()
	publica, _ := url.Parse("https://account.example.com")
	gt := gotrue.New("https://gotrue.example/auth/v1", "anon-test", "service-test")
	ses, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, nil, gt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&config.Config{PublicURL: publica}, nil, gt, ses, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func capturarLogPrueba(t *testing.T) *bytes.Buffer {
	t.Helper()
	var registros bytes.Buffer
	anteriorSalida, anterioresFlags, anteriorPrefijo := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&registros)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(anteriorSalida)
		log.SetFlags(anterioresFlags)
		log.SetPrefix(anteriorPrefijo)
	})
	return &registros
}

func lineasLogSeguras(t *testing.T, registros string, cantidad int) []string {
	t.Helper()
	if !strings.HasSuffix(registros, "\n") {
		t.Fatalf("registro sin terminador: %q", registros)
	}
	lineas := strings.Split(strings.TrimSuffix(registros, "\n"), "\n")
	if len(lineas) != cantidad {
		t.Fatalf("el request inyectó líneas: got=%d want=%d registro=%q", len(lineas), cantidad, registros)
	}
	for _, linea := range lineas {
		for _, r := range linea {
			if r < 0x20 || r >= 0x7f && r <= 0x9f {
				t.Fatalf("control U+%04X sin escapar en %q", r, linea)
			}
		}
	}
	return lineas
}

func TestRegistroHTTPCodificaYEntrecomillaLaRuta(t *testing.T) {
	registros := capturarLogPrueba(t)
	s := servidorMiddlewarePrueba(t)
	casos := []string{
		"/normal",
		"/probe%0Aforged",
		"/probe%0Dforged",
		"/probe%09forged",
		"/probe%00forged",
		"/probe%1B%5B31mforged",
		"/probe%7Fforged",
		"/probe%85forged",
		"/probe%C2%85forged",
		"/probe%22%5Cforged",
		"/probe%2Fforged",
		"/probe%250Aforged",
		"/café",
	}
	for _, objetivo := range casos {
		registros.Reset()
		r := httptest.NewRequest(http.MethodGet, "https://account.example.com"+objetivo+"?visible=ignored", nil)
		w := httptest.NewRecorder()
		s.registrando(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%q: status=%d", objetivo, w.Code)
		}
		linea := lineasLogSeguras(t, registros.String(), 1)[0]
		ruta := strconv.Quote(rutaLogHTTP(r))
		if !strings.Contains(linea, "GET "+ruta+" 204 ") || strings.Contains(linea, "visible=ignored") {
			t.Fatalf("%q no quedó como ruta codificada y sin query: %q", objetivo, linea)
		}
	}

	registros.Reset()
	r := httptest.NewRequest(http.MethodGet, "https://account.example.com/normal", nil)
	r.URL.Path = "/probe\nforged"
	r.URL.RawPath = "/%zz"
	s.registrando(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), r)
	linea := lineasLogSeguras(t, registros.String(), 1)[0]
	if !strings.Contains(linea, strconv.Quote(rutaLogHTTP(r))) {
		t.Fatalf("RawPath inválido no usó el fallback seguro: %q", linea)
	}

	// El exploit real entra por el catch-all público con todos los middlewares.
	registros.Reset()
	r = httptest.NewRequest(http.MethodGet,
		"https://account.example.com/unknown%0Aforged?ordinary=ignored", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("catch-all status=%d", w.Code)
	}
	linea = lineasLogSeguras(t, registros.String(), 1)[0]
	if !strings.Contains(linea, strconv.Quote(rutaLogHTTP(r))) || strings.Contains(linea, "ordinary=ignored") {
		t.Fatalf("catch-all no conservó el límite de log: %q", linea)
	}
}

func TestRutaLogHTTPCanonizaCodificacionesEquivalentes(t *testing.T) {
	for _, objetivo := range []string{
		"/probe/forged",
		"/probe%2Fforged",
		"/probe%2fforged",
		"/%70robe/forged",
	} {
		r := httptest.NewRequest(http.MethodGet, "https://account.example.com"+objetivo, nil)
		if r.URL.Path != "/probe/forged" {
			t.Fatalf("precondición %q: Path=%q", objetivo, r.URL.Path)
		}
		if got := rutaLogHTTP(r); got != "/probe/forged" {
			t.Fatalf("rutaLogHTTP(%q)=%q", objetivo, got)
		}
	}
}

func TestRegistroDePanicoUsaLaMismaRutaSegura(t *testing.T) {
	registros := capturarLogPrueba(t)
	s := servidorMiddlewarePrueba(t)
	r := httptest.NewRequest(http.MethodGet,
		"https://account.example.com/panic%0Aforged%C2%85%1B?token_hash=sentinel-secret", nil)
	w := httptest.NewRecorder()
	s.registrando(s.recuperando(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))).ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", w.Code)
	}
	lineas := lineasLogSeguras(t, registros.String(), 2)
	ruta := strconv.Quote(rutaLogHTTP(r))
	for _, linea := range lineas {
		if !strings.Contains(linea, ruta) || strings.Contains(linea, "sentinel-secret") {
			t.Fatalf("panic/access log no compartió ruta segura sin query: %q", linea)
		}
	}
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
		"":                                                 "/",
		" /solicitar/docdrop ":                             "/solicitar/docdrop",
		"/cuenta?tab=security#passkeys":                    "/cuenta?tab=security#passkeys",
		"/a/../cuenta?tab=security#passkeys":               "/cuenta?tab=security#passkeys",
		"//evil.example":                                   "/",
		"/\\evil.example":                                  "/",
		"\t/seguro":                                        "/",
		"/\t/evil.example":                                 "/",
		"/\r/evil.example":                                 "/",
		"/\n/evil.example":                                 "/",
		"/a/../\\attacker.example":                         "/",
		"/a/../\\\\attacker.example":                       "/",
		"/safe\\later":                                     "/",
		"/%5C/evil.example":                                "/",
		"/%09/evil.example":                                "/",
		"/%2F%2Fevil.example":                              "/evil.example",
		"/cuenta?next=%5Cevil.example":                     "/",
		"/cuenta#%09evil.example":                          "/",
		"https://evil.example/x":                           "/",
		"https://user@account.example.com/cuenta":          "/",
		"https://account.example.com/cuenta?tab=x#frag":    "/cuenta?tab=x",
		"https://account.example.com?tab=x#frag":           "/?tab=x",
		"https://example.com/x?y=1#frag":                   "https://example.com/x?y=1#frag",
		"https://tool.example.com/x?y=1#frag":              "https://tool.example.com/x?y=1#frag",
		"https://tool.example.com/a/../\\attacker.example": "/",
		"http://account.example.com/cuenta":                "/",
		"javascript:alert(1)":                              "/",
	}
	for in, want := range casos {
		if got := s.nextSeguro(in); got != want {
			t.Errorf("nextSeguro(%q) = %q, quería %q", in, got, want)
		}
	}
}

func TestSalirGETNoRedirigeTrasNormalizarNext(t *testing.T) {
	s := servidorMinimo()
	for _, destino := range []string{
		"/salir?next=/%09/evil.example",
		"/salir?next=%2Fa%2F..%2F%5Cattacker.example",
		"/salir?next=%2Fa%2F..%2F%5C%5Cattacker.example",
	} {
		r := httptest.NewRequest(http.MethodGet, destino, nil)
		w := httptest.NewRecorder()
		s.salirGET(w, r)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
			t.Errorf("%s produjo HTTP %d Location %q", destino, w.Code, w.Header().Get("Location"))
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
			Grupo:   store.Grupo{Nombre: "tabup", Tipo: store.TipoGrupoHerramienta, Titulo: "TabUp", URL: "https://tabup.example.com", Solicitable: true},
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
				"https://role.example.com",
			},
		},
		limitador: nuevoLimitador(),
		stSesion: fakeSesionStore{
			grupos: []store.Grupo{
				{Nombre: "tabup", Tipo: store.TipoGrupoHerramienta, URL: "https://tabup.example.com", Solicitable: true},
				{Nombre: "docdrop", Tipo: store.TipoGrupoHerramienta, URL: "https://docdrop.example.com", Solicitable: true},
				{Nombre: "linkup", Tipo: store.TipoGrupoHerramienta, URL: "https://link.example.com", Solicitable: true},
				{Nombre: "chorus", Tipo: store.TipoGrupoHerramienta, URL: "https://chorus.example.com", Solicitable: false},
				{Nombre: "account-admin", Tipo: store.TipoGrupoRol, URL: "https://role.example.com", Solicitable: false},
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

	// Un origen permitido ajeno a las herramientas y al portal no recibe listas.
	for _, orig := range []string{"https://role.example.com", ""} {
		_, body = call(orig, true)
		for _, k := range []string{"granted", "pending", "tool_access", "account_url"} {
			if _, ok := body[k]; ok {
				t.Fatalf("origen %q no debe recibir %s: %#v", orig, k, body)
			}
		}
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
