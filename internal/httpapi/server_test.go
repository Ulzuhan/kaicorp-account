package httpapi

import (
	"html/template"
	"io/fs"

	"github.com/Ulzuhan/kaicorp-account/internal/web"
	"net/url"
	"testing"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
)

func servidorMinimo() *Server {
	u, _ := url.Parse("https://account.example.com")
	return &Server{cfg: &config.Config{PublicURL: u}, limitador: nuevoLimitador()}
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
