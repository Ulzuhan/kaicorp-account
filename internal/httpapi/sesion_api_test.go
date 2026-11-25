package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func TestProyeccionSesionAPINoExponeCorreoConMetadatosVacios(t *testing.T) {
	casos := []struct {
		nombre string
		sesion session.Actual
	}{
		{
			nombre: "invitación sin nombre",
			sesion: session.Actual{Email: "invitee@example.com"},
		},
		{
			nombre: "sesión heredada con nombre en blanco",
			sesion: session.Actual{Email: "legacy@example.com", Nombre: " \t\n"},
		},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			respuesta, err := json.Marshal(proyectarSesionAPI(caso.sesion.Nombre, false))
			if err != nil {
				t.Fatal(err)
			}
			const esperada = `{"signed_in":true,"name":"Account","admin":false}`
			if string(respuesta) != esperada {
				t.Fatalf("proyección inesperada: %s", respuesta)
			}
			if bytes.Contains(respuesta, []byte(caso.sesion.Email)) || bytes.Contains(respuesta, []byte(`"email"`)) {
				t.Fatalf("la respuesta serializada expuso el correo: %s", respuesta)
			}
		})
	}
}

func TestAPISesionNoExponeCorreoEnLaRespuestaCORS(t *testing.T) {
	st, _ := baseConsentimiento(t)
	gt := gotrue.New("http://unused.invalid", "test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	const origen = "https://www.example.com"
	s, err := New(&config.Config{
		PublicURL:      publicURL,
		AdminGroup:     "account-admin",
		SessionOrigins: []string{origen},
	}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}

	casos := []session.Actual{
		{UserID: consentPersona, Email: "invitee@example.com"},
		{UserID: consentPersona, Email: "legacy@example.com", Nombre: " \t\n"},
	}
	for _, actual := range casos {
		r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		r.Header.Set("Origin", origen)
		r = r.WithContext(context.WithValue(r.Context(), claveSesion, &actual))
		w := httptest.NewRecorder()

		s.apiSesion(w, r)

		const esperada = "{\"signed_in\":true,\"name\":\"Account\",\"admin\":false}\n"
		if w.Code != http.StatusOK || w.Body.String() != esperada {
			t.Fatalf("respuesta inesperada para %q: %d %s", actual.Email, w.Code, w.Body.String())
		}
		if bytes.Contains(w.Body.Bytes(), []byte(actual.Email)) || bytes.Contains(w.Body.Bytes(), []byte(`"email"`)) {
			t.Fatalf("la respuesta CORS expuso el correo: %s", w.Body.Bytes())
		}
		if w.Header().Get("Access-Control-Allow-Origin") != origen || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Fatalf("contrato CORS alterado: %v", w.Header())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "Origin" {
			t.Fatalf("contrato de caché alterado: %v", w.Header())
		}
	}
}

func TestProyeccionSesionAPIConservaContratoLegitimo(t *testing.T) {
	conNombre, err := json.Marshal(proyectarSesionAPI(" Ada Lovelace ", true))
	if err != nil {
		t.Fatal(err)
	}
	const nombreEsperado = `{"signed_in":true,"name":" Ada Lovelace ","admin":true}`
	if string(conNombre) != nombreEsperado {
		t.Fatalf("proyección con nombre inesperada: %s", conNombre)
	}

	anonima, err := json.Marshal(respuestaSesionAPI{SignedIn: false})
	if err != nil {
		t.Fatal(err)
	}
	if string(anonima) != `{"signed_in":false}` {
		t.Fatalf("proyección anónima inesperada: %s", anonima)
	}
}
