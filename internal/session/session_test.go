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
	campo := m.CSRF(rec, r)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CSRFCookie || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("cookie csrf: %+v", cookies)
	}
	form := url.Values{CSRFField: {campo}}
	post := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookies[0])
	if !m.CSRFValido(post) {
		t.Fatal("cookie + campo firmado tiene que pasar")
	}
	// Sin cookie: no pasa. Con la cookie de otro: no pasa.
	post2 := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
	post2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.CSRFValido(post2) {
		t.Fatal("sin cookie no puede pasar")
	}
	post3 := httptest.NewRequest(http.MethodPost, "/entrar", bytes.NewReader([]byte(form.Encode())))
	post3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post3.AddCookie(&http.Cookie{Name: CSRFCookie, Value: strings.Repeat("a", 32)})
	if m.CSRFValido(post3) {
		t.Fatal("una cookie distinta de la firmada no puede pasar")
	}
}
