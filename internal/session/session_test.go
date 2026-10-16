package session

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func gestor(t *testing.T) *Manager {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	m, err := New(key, true, 12*time.Hour, 30*24*time.Hour, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSellarYAbrir(t *testing.T) {
	m := gestor(t)
	s, err := m.Sellar("hola")
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Abrir(s)
	if err != nil || out != "hola" {
		t.Fatalf("roundtrip: %q %v", out, err)
	}
	if _, err := m.Abrir(s[:len(s)-2] + "zz"); err == nil {
		t.Fatal("un sobre manipulado tiene que fallar")
	}
	otro := gestor(t)
	if _, err := otro.Abrir(s); err == nil {
		t.Fatal("otra clave no abre el sobre")
	}
}

func TestCSRFDobleEnvio(t *testing.T) {
	m := gestor(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/entrar", nil)
	campo := m.CSRF(rec, r, nil)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CSRFCookie || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("cookie csrf: %+v", cookies)
	}
	form := url.Values{CSRFField: {campo}}
	post := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookies[0])
	if !m.CSRFValido(post, nil) {
		t.Fatal("cookie + campo firmado tiene que pasar")
	}
	// Sin cookie: no pasa. Con la cookie de otro: no pasa.
	post2 := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
	post2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.CSRFValido(post2, nil) {
		t.Fatal("sin cookie no puede pasar")
	}
	post3 := httptest.NewRequest(http.MethodPost, "/entrar", bytes.NewReader([]byte(form.Encode())))
	post3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post3.AddCookie(&http.Cookie{Name: CSRFCookie, Value: strings.Repeat("a", 32)})
	if m.CSRFValido(post3, nil) {
		t.Fatal("una cookie distinta de la firmada no puede pasar")
	}
}

func TestCookieSesionFirmada(t *testing.T) {
	m := gestor(t)
	id := strings.Repeat("ab", 32)
	expira := time.Now().Add(time.Hour).Truncate(time.Second)
	w := httptest.NewRecorder()
	m.ponerCookie(w, id, expira)
	cookie := w.Result().Cookies()[0]
	if cookie.Name != CookieName || cookie.Value == id || !cookie.Expires.Equal(expira) || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie firmada o política incorrectas: %+v", cookie)
	}
	if leido, ok := m.idDeCookie(cookie.Value); !ok || leido != id {
		t.Fatalf("la cookie emitida no recupera el id: %q %t", leido, ok)
	}
	// Una instancia nueva con la misma clave acepta la cookie; otra clave no.
	mismo, err := New(m.key, true, time.Hour, time.Hour, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if leido, ok := mismo.idDeCookie(cookie.Value); !ok || leido != id {
		t.Fatal("reiniciar el gestor perdió la cookie")
	}
	otro := gestor(t)
	sobre, err := m.Sellar(id)
	if err != nil {
		t.Fatal(err)
	}
	casos := map[string]string{
		"vacía":                 "",
		"id de base sin firma":  id,
		"referencia de gestión": "00000000-0000-4000-8000-000000000001",
		"id alterado":           "v1." + strings.Repeat("cd", 32) + "." + m.firmaSesion(id),
		"id no hexadecimal":     "v1." + strings.Repeat("z", 64) + "." + m.firmaSesion(strings.Repeat("z", 64)),
		"id con otra grafía":    "v1." + strings.ToUpper(id) + "." + m.firmaSesion(id),
		"firma alterada":        "v1." + id + "." + strings.Repeat("0", 64),
		"otra clave":            "v1." + id + "." + otro.firmaSesion(id),
		"versión desconocida":   "v2." + id + "." + m.firmaSesion(id),
		"firma de CSRF":         "v1." + id + "." + m.firmar(id),
		"sobre cifrado":         sobre,
		"truncada":              cookie.Value[:len(cookie.Value)-1],
		"ampliada":              cookie.Value + "0",
		"separador alterado":    strings.Replace(cookie.Value, ".", "-", 1),
	}
	for nombre, valor := range casos {
		t.Run(nombre, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
			r.AddCookie(&http.Cookie{Name: CookieName, Value: valor})
			w := httptest.NewRecorder()
			// No hay store: cualquier consulta antes de rechazar la cookie falla.
			if actual, err := m.Cargar(t.Context(), w, r); err != nil || actual != nil {
				t.Fatalf("cookie inválida aceptada: %+v %v", actual, err)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("una cookie inválida sobrescribió otra respuesta concurrente")
			}
		})
	}
}
