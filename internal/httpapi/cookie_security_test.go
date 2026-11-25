package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func servidorCookies(t *testing.T, seguro bool) *Server {
	t.Helper()
	m, err := session.New(make([]byte, 32), seguro, time.Hour, time.Hour, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{ses: m}
}

func cookieActiva(cookies []*http.Cookie, nombre string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == nombre && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func exigeCookieHost(t *testing.T, c *http.Cookie, nombre string, segura bool, sameSite http.SameSite) {
	t.Helper()
	if c == nil || c.Name != nombre || c.Path != "/" || c.Domain != "" || c.Secure != segura || !c.HttpOnly || c.SameSite != sameSite {
		t.Fatalf("cookie de autoridad incorrecta: %+v", c)
	}
}

func TestCookiesDeAutoridadHostOnlyPorModo(t *testing.T) {
	gs := &gotrue.Session{AccessToken: "access", RefreshToken: "refresh", User: gotrue.User{ID: "persona", Email: "p@example.com"}}
	for _, segura := range []bool{true, false} {
		t.Run(map[bool]string{true: "https", false: "http-desarrollo"}[segura], func(t *testing.T) {
			s := servidorCookies(t, segura)

			mfa := httptest.NewRecorder()
			s.ponerPendienteMFA(mfa, gs, "/", false, "")
			nombreMFA := cookieMFADevelopment
			if segura {
				nombreMFA = cookieMFA
			}
			exigeCookieHost(t, cookieActiva(mfa.Result().Cookies(), nombreMFA), nombreMFA, segura, http.SameSiteLaxMode)

			for _, tc := range []struct {
				proposito propositoPassword
				nombreTLS string
				nombreDev string
			}{
				{propositoRecuperacion, "__Host-account_recovery", "account_recovery"},
				{propositoInvitacion, "__Host-account_password_setup", "account_password_setup"},
				{propositoRegistro, "__Host-account_signup_setup", "account_signup_setup"},
			} {
				w := httptest.NewRecorder()
				var err error
				switch tc.proposito {
				case propositoRegistro:
					err = s.emitirCapacidadRegistroEnAutoridad(w, gs, "aal1", "/", "Aa1!pendiente", 1, 0, false)
				case propositoInvitacion:
					err = s.emitirCapacidadInvitacionEnAutoridad(w, gs, "aal1", "/", "Aa1!pendiente", 1, 0, false)
				default:
					err = s.emitirCapacidadPassword(w, gs, "aal1", tc.proposito)
				}
				if err != nil {
					t.Fatal(err)
				}
				nombre := tc.nombreDev
				if segura {
					nombre = tc.nombreTLS
				}
				exigeCookieHost(t, cookieActiva(w.Result().Cookies(), nombre), nombre, segura, http.SameSiteLaxMode)
			}

			autoridad := httptest.NewRecorder()
			s.ponerCookieAutoridadMFA(autoridad, strings.Repeat("a", 64), 300)
			nombreAutoridad := cookieAutoridadMFADevelopment
			if segura {
				nombreAutoridad = cookieAutoridadMFA
			}
			exigeCookieHost(t, cookieActiva(autoridad.Result().Cookies(), nombreAutoridad), nombreAutoridad, segura, http.SameSiteStrictMode)
		})
	}
}

func TestCookiesDeAutoridadDuplicadasSeRechazan(t *testing.T) {
	s := servidorCookies(t, true)
	gs := &gotrue.Session{AccessToken: "access", RefreshToken: "refresh", User: gotrue.User{ID: "persona", Email: "p@example.com"}}

	wMFA := httptest.NewRecorder()
	s.ponerPendienteMFA(wMFA, gs, "/", false, "")
	cMFA := cookieActiva(wMFA.Result().Cookies(), cookieMFA)
	rMFA := httptest.NewRequest(http.MethodGet, "/factor", nil)
	rMFA.AddCookie(cMFA)
	rMFA.Header.Add("Cookie", (&http.Cookie{Name: cookieMFA, Value: cMFA.Value}).String())
	if s.leerPendienteMFA(rMFA) != nil {
		t.Fatal("se aceptó un estado MFA duplicado")
	}

	wPassword := httptest.NewRecorder()
	if err := s.emitirCapacidadPassword(wPassword, gs, "aal1", propositoRecuperacion); err != nil {
		t.Fatal(err)
	}
	cPassword := cookieActiva(wPassword.Result().Cookies(), "__Host-account_recovery")
	rPassword := httptest.NewRequest(http.MethodGet, "/restablecer", nil)
	rPassword.AddCookie(cPassword)
	rPassword.AddCookie(&http.Cookie{Name: cPassword.Name, Value: strings.Repeat("b", 64)})
	if _, ok := s.idCookiePassword(rPassword, propositoRecuperacion); ok {
		t.Fatal("se aceptó una capacidad de contraseña duplicada")
	}

	cAutoridad := &http.Cookie{Name: cookieAutoridadMFA, Value: strings.Repeat("c", 64)}
	rAutoridad := httptest.NewRequest(http.MethodPost, "/cuenta/factor/alta", nil)
	rAutoridad.AddCookie(cAutoridad)
	rAutoridad.AddCookie(&http.Cookie{Name: cAutoridad.Name, Value: strings.Repeat("d", 64)})
	if _, ok := s.idCookieAutoridadMFA(rAutoridad); ok {
		t.Fatal("se aceptó una autoridad MFA duplicada")
	}
}

func TestCookiesDeAutoridadExpiranNombresLegados(t *testing.T) {
	s := servidorCookies(t, true)
	gs := &gotrue.Session{AccessToken: "access", RefreshToken: "refresh", User: gotrue.User{ID: "persona", Email: "p@example.com"}}

	casos := []struct {
		nombre string
		ruta   string
		emitir func(*httptest.ResponseRecorder)
	}{
		{cookieMFADevelopment, "/factor", func(w *httptest.ResponseRecorder) { s.ponerPendienteMFA(w, gs, "/", false, "") }},
		{"__Secure-account_recovery", "/restablecer", func(w *httptest.ResponseRecorder) {
			if err := s.emitirCapacidadPassword(w, gs, "aal1", propositoRecuperacion); err != nil {
				t.Fatal(err)
			}
		}},
		{cookieAutoridadMFALegacy, "/cuenta", func(w *httptest.ResponseRecorder) {
			s.ponerCookieAutoridadMFA(w, strings.Repeat("e", 64), 300)
		}},
	}
	for _, tc := range casos {
		t.Run(tc.nombre, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.emitir(w)
			for _, c := range w.Result().Cookies() {
				if c.Name == tc.nombre && c.Path == tc.ruta && c.MaxAge < 0 && c.Domain == "" {
					return
				}
			}
			t.Fatalf("no se expiró %s en %s: %+v", tc.nombre, tc.ruta, w.Result().Cookies())
		})
	}
}
