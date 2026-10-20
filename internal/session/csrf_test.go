package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func peticionCSRF(cookie *http.Cookie, campos ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/cuenta/password", strings.NewReader(url.Values{CSRFField: campos}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func TestCSRFLigadoASesion(t *testing.T) {
	m := gestor(t)
	a := &Actual{ID: strings.Repeat("a", 64), UserID: "misma-persona"}
	b := &Actual{ID: strings.Repeat("b", 64), UserID: a.UserID}
	for _, emisor := range []*Actual{nil, a} {
		w := httptest.NewRecorder()
		campo := m.CSRF(w, httptest.NewRequest(http.MethodGet, "/", nil), emisor)
		cookie := w.Result().Cookies()[0]
		if !m.CSRFValido(peticionCSRF(cookie, campo), emisor) {
			t.Fatal("el formulario del mismo navegador y sesión no pasa")
		}
		for _, receptor := range []*Actual{nil, a, b, {}} {
			if receptor == emisor {
				continue
			}
			if m.CSRFValido(peticionCSRF(cookie, campo), receptor) {
				t.Fatalf("se transfirió un formulario entre autoridades: %v -> %v", emisor, receptor)
			}
		}
		// Renovar tokens mantiene el ID; otra petición conserva el formulario.
		r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
		r.AddCookie(cookie)
		otra := httptest.NewRecorder()
		if m.CSRF(otra, r, emisor) != campo || len(otra.Result().Cookies()) != 0 {
			t.Fatal("una recarga sin cambiar de sesión perdió el formulario")
		}
	}
}

func TestCSRFCookieEmitidaYUnica(t *testing.T) {
	for _, seguro := range []bool{true, false} {
		m := gestor(t)
		m.secure = seguro
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/entrar", nil)
		// Ni el estado elegido por el atacante ni el alias antiguo se firman.
		r.AddCookie(&http.Cookie{Name: m.nombreCookieCSRF(), Value: strings.Repeat("a", 32)})
		campo := m.CSRF(w, r, nil)
		cookie := w.Result().Cookies()[0]
		if cookie.Name != m.nombreCookieCSRF() || cookie.Value == strings.Repeat("a", 32) || cookie.Secure != seguro || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 12*3600 {
			t.Fatalf("estado o atributos incorrectos: %+v", cookie)
		}
		for _, tc := range []struct {
			nombre string
			cookie *http.Cookie
			campos []string
		}{
			{"sin cookie", nil, []string{campo}},
			{"alterada", &http.Cookie{Name: cookie.Name, Value: cookie.Value + "x"}, []string{campo}},
			{"semilla elegida", &http.Cookie{Name: cookie.Name, Value: strings.Repeat("a", 32)}, []string{campo}},
			{"sin campo", cookie, nil},
			{"campo duplicado", cookie, []string{campo, campo}},
			{"campo distinto", cookie, []string{"inventado"}},
		} {
			t.Run(tc.nombre+strconv.FormatBool(seguro), func(t *testing.T) {
				if m.CSRFValido(peticionCSRF(tc.cookie, tc.campos...), nil) {
					t.Fatal("se aceptó estado ambiguo o inválido")
				}
			})
		}
		for _, valor := range []string{cookie.Value, strings.Repeat("b", 32)} {
			post := peticionCSRF(cookie, campo)
			post.Header.Add("Cookie", (&http.Cookie{Name: cookie.Name, Value: valor}).String())
			if m.CSRFValido(post, nil) {
				t.Fatal("se aceptaron cookies duplicadas, incluso en cabeceras distintas")
			}
		}
		alias := "account_csrf"
		if !seguro {
			alias = CSRFCookie
		}
		if m.CSRFValido(peticionCSRF(&http.Cookie{Name: alias, Value: cookie.Value}, campo), nil) {
			t.Fatal("se aceptó el alias del otro modo")
		}
		query := peticionCSRF(cookie)
		query.URL.RawQuery = url.Values{CSRFField: {campo}}.Encode()
		if m.CSRFValido(query, nil) {
			t.Fatal("un token en la query sustituyó al campo POST")
		}
		// La misma clave mantiene los formularios tras un reinicio o en otra instancia.
		otra, err := New(m.key, seguro, time.Hour, time.Hour, nil, nil)
		if err != nil || !otra.CSRFValido(peticionCSRF(cookie, campo), nil) {
			t.Fatal("se perdió un formulario entre instancias", err)
		}
	}
}

func TestCSRFEstadoCaducado(t *testing.T) {
	m := gestor(t)
	for _, texto := range []string{strings.Repeat("a", 32) + ":" + strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10), "invalido", strings.Repeat("z", 32) + ":9999999999"} {
		valor, err := m.Sellar(texto)
		if err != nil {
			t.Fatal(err)
		}
		cookie := &http.Cookie{Name: CSRFCookie, Value: valor}
		if m.CSRFValido(peticionCSRF(cookie, m.campoCSRF(valor, nil)), nil) {
			t.Fatal("se aceptó estado caducado o mal formado")
		}
	}
}
