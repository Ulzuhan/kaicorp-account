package httpapi

import (
	"net/url"
	"testing"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
)

func servidorMinimo() *Server {
	u, _ := url.Parse("https://account.kaicorplabs.com")
	return &Server{cfg: &config.Config{PublicURL: u}, limitador: nuevoLimitador()}
}

func TestNextSeguro(t *testing.T) {
	s := servidorMinimo()
	casos := map[string]string{
		"":                                       "/",
		"/solicitar/docdrop":                     "/solicitar/docdrop",
		"//evil.example":                         "/",
		"/\\evil.example":                        "/",
		"https://evil.example/x":                 "/",
		"https://account.kaicorplabs.com/cuenta": "/cuenta",
		"http://account.kaicorplabs.com/cuenta":  "/",
		"javascript:alert(1)":                    "/",
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
