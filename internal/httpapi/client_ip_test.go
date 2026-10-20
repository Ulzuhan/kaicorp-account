package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func servidorLimitado(t *testing.T, cfg *config.Config, gt *gotrue.Client) *Server {
	t.Helper()
	cfg.PublicURL, _ = url.Parse("https://account.example.com")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, nil, gt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, nil, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProxyConservaClientesYAcciones(t *testing.T) {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		t.Run(header, func(t *testing.T) {
			cfg := &config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, ClientIPHeader: header}
			s := servidorLimitado(t, cfg, nil)
			other := "CF-Connecting-IP"
			if header == other {
				other = "X-Real-IP"
			}
			for i, tc := range []struct {
				peer, client, action string
				want                 int
			}{
				{"192.0.2.1:1234", "198.51.100.1", "verificar", http.StatusOK},
				{"192.0.2.2:1235", "198.51.100.1", "verificar", http.StatusTooManyRequests},
				{"192.0.2.1:1236", "198.51.100.2", "verificar", http.StatusOK},
				{"192.0.2.1:1237", "198.51.100.1", "recuperar", http.StatusOK},
				{"203.0.113.1:1238", "198.51.100.3", "verificar", http.StatusOK},
				{"203.0.113.1:1239", "198.51.100.4", "verificar", http.StatusTooManyRequests},
			} {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = tc.peer
				r.Header.Set(header, tc.client)
				r.Header.Set(other, fmt.Sprintf("rotating-unselected-%d", i))
				w := httptest.NewRecorder()
				blocked := s.frena(w, r, tc.action, 1, 0)
				if w.Code != tc.want || blocked != (tc.want != http.StatusOK) {
					t.Fatalf("caso %d: HTTP %d, bloqueado %v; quería %d", i, w.Code, blocked, tc.want)
				}
			}
		})
	}
}

func TestFrenaComparteIPCanonica(t *testing.T) {
	for _, tc := range []struct {
		nombre string
		proxy  bool
		values []string
	}{
		{"IPv6 del transporte", false, []string{"[2001:0DB8:0:0:0:0:0:1]:1234", "[2001:db8::1]:5678"}},
		{"IPv4 mapeada del transporte", false, []string{"198.51.100.1:1234", "[::ffff:198.51.100.1]:5678"}},
		{"IPv6 reenviada", true, []string{"2001:0DB8:0:0:0:0:0:1", "2001:db8::1"}},
		{"IPv4 mapeada reenviada", true, []string{"198.51.100.1", "::ffff:198.51.100.1"}},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			cfg := &config.Config{}
			if tc.proxy {
				cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("::1/128")}
				cfg.ClientIPHeader = "CF-Connecting-IP"
			}
			s := servidorLimitado(t, cfg, nil)
			for i, value := range tc.values {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = value
				if tc.proxy {
					r.RemoteAddr = "[::1]:1234"
					r.Header.Set(cfg.ClientIPHeader, value)
				}
				w := httptest.NewRecorder()
				blocked := s.frena(w, r, "factor", 1, 0)
				if blocked != (i > 0) || (i > 0 && w.Code != http.StatusTooManyRequests) {
					t.Fatalf("representación %q: HTTP %d, bloqueado %v", value, w.Code, blocked)
				}
			}
		})
	}
}

func TestFrenaRechazaIdentidadInvalida(t *testing.T) {
	for _, values := range [][]string{
		nil, {""}, {"not-an-ip"}, {"198.51.100.1:1234"}, {"198.51.100.1, 198.51.100.2"},
		{"198.51.100.1", "198.51.100.2"}, {"198.51.100.1", "198.51.100.1"},
		{"fe80::1%eth0"}, {"::ffff:198.51.100.1%alias"}, {"[2001:db8::1]"},
	} {
		t.Run(fmt.Sprint(values), func(t *testing.T) {
			cfg := &config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, ClientIPHeader: "X-Real-IP"}
			s := servidorLimitado(t, cfg, nil)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "[::ffff:192.0.2.1]:1234"
			for _, v := range values {
				r.Header.Add(cfg.ClientIPHeader, v)
			}
			// Una cabecera alternativa válida nunca rescata la identidad inválida.
			r.Header.Set("CF-Connecting-IP", "198.51.100.1")
			w := httptest.NewRecorder()
			if !s.frena(w, r, "factor", 1, 0) || w.Code != http.StatusBadRequest || len(s.limitador.cubos) != 0 {
				t.Fatalf("identidad inválida: HTTP %d, cubos %d", w.Code, len(s.limitador.cubos))
			}
		})
	}
	for _, peer := range []string{"", "not-an-ip:1234", "198.51.100.1", "198.51.100.1:bad"} {
		s := servidorLimitado(t, &config.Config{}, nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		r.Header.Set("CF-Connecting-IP", "198.51.100.1")
		w := httptest.NewRecorder()
		if !s.frena(w, r, "entrar", 1, 0) || w.Code != http.StatusBadRequest || len(s.limitador.cubos) != 0 {
			t.Fatalf("par inválido %q: HTTP %d, cubos %d", peer, w.Code, len(s.limitador.cubos))
		}
	}
}

// Recorre el login y su CSRF real; el proveedor falso sólo rechaza credenciales.
func TestLoginNoReiniciaLimiteConCabeceras(t *testing.T) {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		t.Run(header, func(t *testing.T) {
			var llamadas atomic.Int32
			proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				llamadas.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error_code":"invalid_credentials","msg":"invalid"}`)
			}))
			defer proveedor.Close()
			s := servidorLimitado(t, &config.Config{}, gotrue.New(proveedor.URL, "test", ""))
			h := s.Handler()
			get := httptest.NewRecorder()
			h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/entrar", nil))
			match := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(get.Body.String())
			if get.Code != http.StatusOK || len(match) != 2 {
				t.Fatalf("formulario de entrada: %d %s", get.Code, get.Body.String())
			}
			form := url.Values{session.CSRFField: {match[1]}, "email": {"test@example.com"}, "password": {"wrong-password"}}
			for i := 0; i < 11; i++ {
				r := httptest.NewRequest(http.MethodPost, "/entrar", strings.NewReader(form.Encode()))
				r.RemoteAddr = fmt.Sprintf("198.51.100.10:%d", 20000+i)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Origin", s.cfg.PublicURL.Scheme+"://"+s.cfg.PublicURL.Host)
				r.Header.Set(header, fmt.Sprintf("203.0.113.%d", i+1))
				for _, c := range get.Result().Cookies() {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := http.StatusUnauthorized
				if i == 10 {
					want = http.StatusTooManyRequests
				}
				if w.Code != want {
					t.Fatalf("intento %d: HTTP %d, quería %d", i+1, w.Code, want)
				}
			}
			if got := llamadas.Load(); got != 10 {
				t.Fatalf("llamadas al proveedor: %d, quería 10", got)
			}
		})
	}
}
