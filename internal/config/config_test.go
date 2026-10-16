package config

import (
	"strings"
	"testing"
)

func TestConfiguracionProxy(t *testing.T) {
	for k, v := range map[string]string{
		"ACCOUNT_PUBLIC_URL": "https://account.example.com",
		"ACCOUNT_GOTRUE_URL": "http://gotrue.example/auth/v1",
		"ACCOUNT_ANON_KEY":   "test", "ACCOUNT_SERVICE_KEY": "test",
		"ACCOUNT_DATABASE_URL": "postgres://test", "ACCOUNT_SESSION_KEY": strings.Repeat("00", 32),
		"ACCOUNT_SESSION_TTL_HOURS": "", "ACCOUNT_SESSION_REMEMBER_DAYS": "",
		"ACCOUNT_UNCONFIRMED_DAYS": "", "ACCOUNT_SMTP_HOST": "",
	} {
		t.Setenv(k, v)
	}
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
