package httpapi

import (
	"bytes"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
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
