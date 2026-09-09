package gotrue

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Un GoTrue de mentira que devuelve lo que se le diga y anota qué recibió.
func falso(t *testing.T, status int, body any, visto *http.Request) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*visto = *r
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/auth/v1", "anon-key", "service-key")
}

func TestLoginMandaApikeyYSinBearer(t *testing.T) {
	var visto http.Request
	c := falso(t, 200, map[string]any{"access_token": "a", "refresh_token": "r", "expires_in": 3600, "user": map[string]any{"id": "u1", "email": "x@y"}}, &visto)
	s, err := c.Login(context.Background(), "x@y", "secreto")
	if err != nil || s.AccessToken != "a" || s.User.ID != "u1" {
		t.Fatalf("login: %v %+v", err, s)
	}
	if visto.Header.Get("apikey") != "anon-key" || visto.Header.Get("Authorization") != "" {
		t.Fatalf("cabeceras: %v", visto.Header)
	}
	if visto.URL.Path != "/auth/v1/token" || visto.URL.Query().Get("grant_type") != "password" {
		t.Fatalf("ruta: %s", visto.URL)
	}
}

func TestErroresConservanCodigoYErrorCode(t *testing.T) {
	var visto http.Request
	c := falso(t, 400, map[string]any{"code": 400, "error_code": "invalid_credentials", "msg": "Invalid login credentials"}, &visto)
	_, err := c.Login(context.Background(), "x@y", "mal")
	if !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("esperaba ErrInvalidLogin, tengo %v", err)
	}
	var ge *Error
	if !errors.As(err, &ge) || ge.Status != 400 {
		t.Fatalf("error sin código: %v", err)
	}
	c429 := falso(t, 429, map[string]any{"error_code": "over_email_send_rate_limit", "msg": "wait"}, &visto)
	if err := c429.Recover(context.Background(), "x@y", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("esperaba ErrRateLimited, tengo %v", err)
	}
}

func TestAdminUsaLaClaveDeServicioComoBearer(t *testing.T) {
	var visto http.Request
	c := falso(t, 200, map[string]any{}, &visto)
	if err := c.AdminDeleteUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if visto.Header.Get("Authorization") != "Bearer service-key" || visto.Header.Get("apikey") != "service-key" {
		t.Fatalf("cabeceras admin: %v", visto.Header)
	}
	sin := New("http://127.0.0.1:1/auth/v1", "anon", "")
	if err := sin.AdminDeleteUser(context.Background(), "u1"); err == nil {
		t.Fatal("sin clave de servicio tiene que fallar antes de llamar")
	}
}

func TestAutorizacionAutoAprobada(t *testing.T) {
	var visto http.Request
	c := falso(t, 200, map[string]any{"redirect_url": "https://app/cb?code=1"}, &visto)
	a, err := c.GetAuthorization(context.Background(), "tok", "abc")
	if err != nil || !a.AutoApproved() {
		t.Fatalf("auto-aprobada mal leída: %v %+v", err, a)
	}
	if visto.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("falta el bearer de la persona: %v", visto.Header)
	}
}

func TestHasVerifiedFactor(t *testing.T) {
	u := &User{Factors: []Factor{{Status: "unverified"}}}
	if u.HasVerifiedFactor() {
		t.Fatal("un factor sin verificar no cuenta")
	}
	u.Factors = append(u.Factors, Factor{Status: "verified", FactorType: "totp"})
	if !u.HasVerifiedFactor() {
		t.Fatal("un factor verificado sí cuenta")
	}
}

func TestQRDataURL(t *testing.T) {
	var f EnrolledFactor
	f.TOTP.QRCode = "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"
	got := f.QRDataURL()
	if !strings.HasPrefix(got, "data:image/svg+xml;base64,") {
		t.Fatalf("no es URL de datos: %q", got)
	}
	f.TOTP.QRCode = "data:image/png;base64,AAAA"
	if f.QRDataURL() != f.TOTP.QRCode {
		t.Fatal("una URL de datos ya hecha se respeta")
	}
}
