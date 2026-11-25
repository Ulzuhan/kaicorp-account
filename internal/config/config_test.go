package config

import (
	"strings"
	"testing"
)

func configuracionMinima(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"ACCOUNT_PUBLIC_URL": "https://account.example.com",
		"ACCOUNT_GOTRUE_URL": "https://gotrue.example/auth/v1",
		"ACCOUNT_ANON_KEY":   "test", "ACCOUNT_SERVICE_KEY": "test",
		"ACCOUNT_DATABASE_URL": "postgres://test", "ACCOUNT_SESSION_KEY": strings.Repeat("00", 32),
		"ACCOUNT_EMAIL_LINK_TTL_SECONDS": "86400",
		"GOTRUE_MAILER_OTP_EXP":          "86400",
		"ACCOUNT_SESSION_TTL_HOURS":      "", "ACCOUNT_SESSION_REMEMBER_DAYS": "",
		"ACCOUNT_UNCONFIRMED_DAYS": "", "ACCOUNT_SMTP_HOST": "",
		"ACCOUNT_GOTRUE_INSECURE_HTTP": "",
		"ACCOUNT_INSECURE_COOKIES":     "",
	} {
		t.Setenv(k, v)
	}
}

func TestConfiguracionExpiracionEnlacesCoincideConGoTrue(t *testing.T) {
	for _, tc := range []struct {
		nombre, valor string
		valida        bool
		want          string
	}{
		{nombre: "un día", valor: "86400", valida: true, want: "24h0m0s"},
		{nombre: "una hora", valor: "3600", valida: true, want: "1h0m0s"},
		{nombre: "ausente"},
		{nombre: "cero", valor: "0"},
		{nombre: "más de un día", valor: "86401"},
		{nombre: "no entero", valor: "one-day"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			configuracionMinima(t)
			t.Setenv("ACCOUNT_EMAIL_LINK_TTL_SECONDS", tc.valor)
			if tc.valida {
				t.Setenv("GOTRUE_MAILER_OTP_EXP", tc.valor)
			}
			c, err := FromEnv()
			if !tc.valida {
				if err == nil {
					t.Fatal("la expiración inválida tenía que impedir el arranque")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := c.EmailLinkTTL.String(); got != tc.want {
				t.Fatalf("EmailLinkTTL=%s, quería %s", got, tc.want)
			}
		})
	}
}

func TestConfiguracionExpiracionEnlacesRechazaDiferenciaConGoTrue(t *testing.T) {
	for _, tc := range []struct {
		nombre, cuenta, proveedor string
	}{
		{nombre: "app más corta", cuenta: "3600", proveedor: "86400"},
		{nombre: "app más larga", cuenta: "86400", proveedor: "3600"},
		{nombre: "proveedor ausente", cuenta: "86400"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			configuracionMinima(t)
			t.Setenv("ACCOUNT_EMAIL_LINK_TTL_SECONDS", tc.cuenta)
			t.Setenv("GOTRUE_MAILER_OTP_EXP", tc.proveedor)
			if _, err := FromEnv(); err == nil {
				t.Fatal("la app arrancó con expiraciones distintas o incompletas")
			}
		})
	}
}

func TestConfiguracionCookiesInsegurasSoloEnLoopbackHTTPExplicito(t *testing.T) {
	for _, tc := range []struct {
		nombre, publica, permiso string
		valida                   bool
		segura                   bool
	}{
		{nombre: "https normal", publica: "https://account.example.com", valida: true, segura: true},
		{nombre: "https con permiso inseguro", publica: "https://account.example.com", permiso: "1"},
		{nombre: "http loopback sin permiso", publica: "http://127.0.0.1:3467"},
		{nombre: "IPv4 loopback explícito", publica: "http://127.0.0.42:3467", permiso: "1", valida: true},
		{nombre: "IPv6 loopback explícito", publica: "http://[::1]:3467", permiso: "1", valida: true},
		{nombre: "http remoto", publica: "http://account.example.com", permiso: "1"},
		{nombre: "localhost no literal", publica: "http://localhost:3467", permiso: "1"},
		{nombre: "IPv4 mapeada", publica: "http://[::ffff:127.0.0.1]:3467", permiso: "1"},
		{nombre: "dirección indeterminada", publica: "http://0.0.0.0:3467", permiso: "1"},
		{nombre: "permiso ambiguo", publica: "http://127.0.0.1:3467", permiso: "true"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			configuracionMinima(t)
			t.Setenv("ACCOUNT_PUBLIC_URL", tc.publica)
			t.Setenv("ACCOUNT_INSECURE_COOKIES", tc.permiso)
			c, err := FromEnv()
			if !tc.valida {
				if err == nil {
					t.Fatalf("configuración insegura admitida: %s", tc.publica)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.CookieSecure() != tc.segura {
				t.Fatalf("CookieSecure=%t, quería %t", c.CookieSecure(), tc.segura)
			}
		})
	}
}

func TestConfiguracionProxy(t *testing.T) {
	configuracionMinima(t)
	for _, tc := range []struct {
		nombre, proxies, header, wantHeader string
		wantCIDRs                           []string
		invalida                            bool
	}{
		{nombre: "sin proxy"},
		{nombre: "Cloudflare", proxies: "127.0.0.1/32, ::1/128", header: "CF-Connecting-IP", wantHeader: "CF-Connecting-IP", wantCIDRs: []string{"127.0.0.1/32", "::1/128"}},
		{nombre: "X-Real y red", proxies: "192.0.2.7/24,2001:db8::1234/64", header: "x-real-ip", wantHeader: "X-Real-IP", wantCIDRs: []string{"192.0.2.0/24", "2001:db8::/64"}},
		{nombre: "sin cabecera", proxies: "127.0.0.1/32", invalida: true},
		{nombre: "sin pares", header: "X-Real-IP", invalida: true},
		{nombre: "cabecera no admitida", proxies: "127.0.0.1/32", header: "X-Forwarded-For", invalida: true},
		{nombre: "dos cabeceras", proxies: "127.0.0.1/32", header: "CF-Connecting-IP,X-Real-IP", invalida: true},
		{nombre: "sin prefijo", proxies: "127.0.0.1", header: "X-Real-IP", invalida: true},
		{nombre: "host", proxies: "localhost/32", header: "X-Real-IP", invalida: true},
		{nombre: "entrada vacía", proxies: "127.0.0.1/32,", header: "X-Real-IP", invalida: true},
		{nombre: "prefijo inválido", proxies: "192.0.2.1/33", header: "X-Real-IP", invalida: true},
		{nombre: "CIDR mapeada", proxies: "::ffff:192.0.2.1/128", header: "X-Real-IP", invalida: true},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			t.Setenv("ACCOUNT_TRUSTED_PROXY_CIDRS", tc.proxies)
			t.Setenv("ACCOUNT_CLIENT_IP_HEADER", tc.header)
			c, err := FromEnv()
			if tc.invalida {
				if err == nil {
					t.Fatal("la configuración inválida tiene que impedir el arranque")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.ClientIPHeader != tc.wantHeader || len(c.TrustedProxies) != len(tc.wantCIDRs) {
				t.Fatalf("configuración de proxy: %q %v", c.ClientIPHeader, c.TrustedProxies)
			}
			for i, want := range tc.wantCIDRs {
				if got := c.TrustedProxies[i].String(); got != want {
					t.Errorf("CIDR %d: %q, quería %q", i, got, want)
				}
			}
		})
	}
}

func TestConfiguracionGoTrueExigeTransporteSeguro(t *testing.T) {
	configuracionMinima(t)
	for _, tc := range []struct {
		nombre, raw, permitir, want string
		valida                      bool
	}{
		{nombre: "https", raw: "https://gotrue.example/auth/v1", valida: true, want: "https://gotrue.example/auth/v1"},
		{nombre: "https sin barra final", raw: " https://gotrue.example/auth/v1/// ", valida: true, want: "https://gotrue.example/auth/v1"},
		{nombre: "http remoto", raw: "http://gotrue.example/auth/v1"},
		{nombre: "http loopback sin permiso", raw: "http://127.0.0.1:9999/auth/v1"},
		{nombre: "IPv4 loopback de desarrollo", raw: "http://127.0.0.42:9999/auth/v1", permitir: "1", valida: true, want: "http://127.0.0.42:9999/auth/v1"},
		{nombre: "IPv6 loopback de desarrollo", raw: "http://[::1]:9999/auth/v1", permitir: "1", valida: true, want: "http://[::1]:9999/auth/v1"},
		{nombre: "remoto incluso con permiso", raw: "http://10.0.0.8/auth/v1", permitir: "1"},
		{nombre: "nombre localhost", raw: "http://localhost/auth/v1", permitir: "1"},
		{nombre: "IPv4 mapeada", raw: "http://[::ffff:127.0.0.1]/auth/v1", permitir: "1"},
		{nombre: "dirección indeterminada", raw: "http://0.0.0.0/auth/v1", permitir: "1"},
		{nombre: "IPv4 abreviada", raw: "http://127.1/auth/v1", permitir: "1"},
		{nombre: "IPv4 decimal", raw: "http://2130706433/auth/v1", permitir: "1"},
		{nombre: "sin host", raw: "https:///auth/v1"},
		{nombre: "con usuario", raw: "https://usuario@gotrue.example/auth/v1"},
		{nombre: "con query", raw: "https://gotrue.example/auth/v1?destino=http://otro"},
		{nombre: "con fragmento", raw: "https://gotrue.example/auth/v1#otro"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			t.Setenv("ACCOUNT_GOTRUE_URL", tc.raw)
			t.Setenv("ACCOUNT_GOTRUE_INSECURE_HTTP", tc.permitir)
			c, err := FromEnv()
			if !tc.valida {
				if err == nil {
					t.Fatalf("la URL insegura o mal formada fue admitida: %q", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.GoTrueURL != tc.want {
				t.Fatalf("GoTrueURL = %q, quería %q", c.GoTrueURL, tc.want)
			}
		})
	}
}

func TestConfiguracionGoTrueRechazaPermisoInseguroAmbiguo(t *testing.T) {
	configuracionMinima(t)
	t.Setenv("ACCOUNT_GOTRUE_INSECURE_HTTP", "true")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "sólo se admite 1") {
		t.Fatalf("el permiso ambiguo tiene que impedir el arranque: %v", err)
	}
}
