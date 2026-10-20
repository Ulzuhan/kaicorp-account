// Package config lee la configuración del entorno y la valida al arrancar.
//
// Todo lo que hace falta para hablar con GoTrue y con Postgres viene por
// variables ACCOUNT_*. Sin ellas la aplicación NO arranca: una app de cuenta a
// medio configurar no es una app de cuenta, es una puerta abierta a medias.
//
// Los ejemplos de esta documentación son genéricos a propósito: los nombres
// reales de una instalación viven en su compose y en su fichero de entorno.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config es la configuración validada.
type Config struct {
	// PublicURL es la dirección que ve el navegador: https://account.example.com.
	// Se usa para construir enlaces absolutos y para decidir si la cookie va Secure.
	PublicURL *url.URL
	// GoTrueURL es la base HTTPS de la API de GoTrue, con su prefijo /auth/v1.
	// Lleva contraseñas y claves administrativas: una red interna no sustituye
	// la autenticación y el cifrado del transporte.
	GoTrueURL string
	// GoTrueInsecureHTTP sólo permite HTTP hacia una IP literal de loopback. Es
	// una excepción explícita para desarrollo local, nunca para redes Docker.
	GoTrueInsecureHTTP bool
	// AnonKey es la clave pública (JWT con role anon) que GoTrue exige en `apikey`.
	AnonKey string
	// ServiceKey es la clave de administración (role service_role). Sólo la usan
	// las operaciones de administración: borrar cuentas y bloquearlas.
	ServiceKey string
	// EmailLinkTTL debe ser el mismo valor que GOTRUE_MAILER_OTP_EXP. La app lo
	// usa para rechazar un hash caducado antes de que /verify pueda consumirlo.
	EmailLinkTTL time.Duration
	// DatabaseURL es la conexión al Postgres de la instancia con el rol `account`.
	DatabaseURL string
	// MigrationDatabaseURL usa el rol dueño `account_migrator`. Sólo se lee para
	// la orden `account migrar`; el servidor nunca debe conservar esta credencial.
	MigrationDatabaseURL string
	// SessionKey son 32 bytes: cifran los tokens en reposo y firman el CSRF.
	SessionKey []byte
	// SessionTTL es la vida máxima de una sesión de esta app, 1 a 24 h.
	SessionTTL time.Duration
	// RememberTTL es la vida de una sesión con «keep me signed in», 1 a 90 días.
	RememberTTL time.Duration
	// SessionOrigins son los orígenes (https://kaicorplabs.com) a los que
	// /api/session contesta con credenciales: la web pública, para enseñar
	// quién ha entrado. Por defecto, el dominio padre del PublicURL.
	SessionOrigins []string
	// TrustedProxies son los CIDR de los pares inmediatos que sobrescriben
	// ClientIPHeader. Sin configuración, sólo se usa la IP del transporte.
	TrustedProxies []netip.Prefix
	ClientIPHeader string
	// AdminGroup es la membresía que abre /admin.
	AdminGroup string
	// SMTP* es la cuenta con la que la app manda SUS correos (el aviso de acceso
	// concedido); GoTrue manda los suyos con la suya. Sin SMTPHost no se envía
	// nada y el acceso se concede igual.
	SMTPHost, SMTPPort, SMTPUser, SMTPPass, SMTPFrom string
	// UnconfirmedDays: una cuenta que se registró sola y nunca confirmó el correo
	// se borra pasados estos días (14 por defecto; 0 desactiva la purga). Las
	// invitadas no se tocan: la invitación la decidió una persona y se reenvía.
	UnconfirmedDays int
	// InsecureCookies selecciona nombres sin __Host- sólo para desarrollo HTTP
	// explícito sobre una IP literal de loopback.
	InsecureCookies bool
	// Addr es host:puerto de escucha.
	Addr string
}

// FromEnv construye la configuración o devuelve todos los errores juntos: es
// mejor un arranque que dice las cinco cosas que faltan que cinco arranques.
func FromEnv() (*Config, error) {
	var errs []error
	c := &Config{AdminGroup: "account-admin", SessionTTL: 12 * time.Hour, RememberTTL: 30 * 24 * time.Hour}

	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_PUBLIC_URL")); raw == "" {
		errs = append(errs, errors.New("ACCOUNT_PUBLIC_URL: falta (https://account.example.com)"))
	} else if u, err := url.Parse(raw); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		errs = append(errs, fmt.Errorf("ACCOUNT_PUBLIC_URL: no es una URL http(s) válida: %q", raw))
	} else {
		u.Path = strings.TrimRight(u.Path, "/")
		u.RawQuery, u.Fragment = "", ""
		c.PublicURL = u
	}
	switch raw := strings.TrimSpace(os.Getenv("ACCOUNT_INSECURE_COOKIES")); raw {
	case "":
	case "1":
		c.InsecureCookies = true
	default:
		errs = append(errs, fmt.Errorf("ACCOUNT_INSECURE_COOKIES: sólo se admite 1 para desarrollo local, no %q", raw))
	}
	if c.PublicURL != nil {
		switch {
		case c.PublicURL.Scheme == "https" && c.InsecureCookies:
			errs = append(errs, errors.New("ACCOUNT_INSECURE_COOKIES: no se admite con ACCOUNT_PUBLIC_URL https"))
		case c.PublicURL.Scheme == "http" && !c.InsecureCookies:
			errs = append(errs, errors.New("ACCOUNT_PUBLIC_URL: http exige ACCOUNT_INSECURE_COOKIES=1 para desarrollo local"))
		case c.PublicURL.Scheme == "http" && !esLoopbackLiteral(c.PublicURL.Hostname()):
			errs = append(errs, errors.New("ACCOUNT_PUBLIC_URL: el http de desarrollo sólo admite una IP literal de loopback"))
		}
	}

	switch raw := strings.TrimSpace(os.Getenv("ACCOUNT_GOTRUE_INSECURE_HTTP")); raw {
	case "":
	case "1":
		c.GoTrueInsecureHTTP = true
	default:
		errs = append(errs, fmt.Errorf("ACCOUNT_GOTRUE_INSECURE_HTTP: sólo se admite 1 para desarrollo local, no %q", raw))
	}
	if gotrueURL, err := validarGoTrueURL(os.Getenv("ACCOUNT_GOTRUE_URL"), c.GoTrueInsecureHTTP); err != nil {
		errs = append(errs, err)
	} else {
		c.GoTrueURL = gotrueURL
	}

	c.AnonKey = strings.TrimSpace(os.Getenv("ACCOUNT_ANON_KEY"))
	if c.AnonKey == "" {
		errs = append(errs, errors.New("ACCOUNT_ANON_KEY: falta"))
	}
	c.ServiceKey = strings.TrimSpace(os.Getenv("ACCOUNT_SERVICE_KEY"))
	if c.ServiceKey == "" {
		errs = append(errs, errors.New("ACCOUNT_SERVICE_KEY: falta"))
	}
	var ttlCuenta, ttlProveedor int
	var ttlCuentaOK, ttlProveedorOK bool
	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_EMAIL_LINK_TTL_SECONDS")); raw == "" {
		errs = append(errs, errors.New("ACCOUNT_EMAIL_LINK_TTL_SECONDS: falta"))
	} else if segundos, err := strconv.Atoi(raw); err != nil || segundos < 1 || segundos > 86400 {
		errs = append(errs, fmt.Errorf("ACCOUNT_EMAIL_LINK_TTL_SECONDS: entero entre 1 y 86400, no %q", raw))
	} else {
		ttlCuenta, ttlCuentaOK = segundos, true
	}
	if raw := strings.TrimSpace(os.Getenv("GOTRUE_MAILER_OTP_EXP")); raw == "" {
		errs = append(errs, errors.New("GOTRUE_MAILER_OTP_EXP: falta en el entorno de la app para comprobar la configuración del proveedor"))
	} else if segundos, err := strconv.Atoi(raw); err != nil || segundos < 1 || segundos > 86400 {
		errs = append(errs, fmt.Errorf("GOTRUE_MAILER_OTP_EXP: entero entre 1 y 86400, no %q", raw))
	} else {
		ttlProveedor, ttlProveedorOK = segundos, true
	}
	if ttlCuentaOK && ttlProveedorOK {
		if ttlCuenta != ttlProveedor {
			errs = append(errs, fmt.Errorf("ACCOUNT_EMAIL_LINK_TTL_SECONDS (%d) debe coincidir con GOTRUE_MAILER_OTP_EXP (%d)", ttlCuenta, ttlProveedor))
		} else {
			c.EmailLinkTTL = time.Duration(ttlCuenta) * time.Second
		}
	}
	c.DatabaseURL = strings.TrimSpace(os.Getenv("ACCOUNT_DATABASE_URL"))
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("ACCOUNT_DATABASE_URL: falta"))
	}
	c.MigrationDatabaseURL = strings.TrimSpace(os.Getenv("ACCOUNT_MIGRATION_DATABASE_URL"))

	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_SESSION_KEY")); raw == "" {
		errs = append(errs, errors.New("ACCOUNT_SESSION_KEY: falta (64 caracteres hex: openssl rand -hex 32)"))
	} else if k, err := hex.DecodeString(raw); err != nil || len(k) != 32 {
		errs = append(errs, errors.New("ACCOUNT_SESSION_KEY: tienen que ser 32 bytes en hex (64 caracteres)"))
	} else {
		c.SessionKey = k
	}

	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_SESSION_TTL_HOURS")); raw != "" {
		h, err := strconv.Atoi(raw)
		if err != nil || h < 1 || h > 24 {
			errs = append(errs, fmt.Errorf("ACCOUNT_SESSION_TTL_HOURS: entre 1 y 24, no %q", raw))
		} else {
			c.SessionTTL = time.Duration(h) * time.Hour
		}
	}
	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_SESSION_REMEMBER_DAYS")); raw != "" {
		d, err := strconv.Atoi(raw)
		if err != nil || d < 1 || d > 90 {
			errs = append(errs, fmt.Errorf("ACCOUNT_SESSION_REMEMBER_DAYS: entre 1 y 90, no %q", raw))
		} else {
			c.RememberTTL = time.Duration(d) * 24 * time.Hour
		}
	}
	if raw := strings.TrimSpace(os.Getenv("ACCOUNT_SESSION_ORIGINS")); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.SessionOrigins = append(c.SessionOrigins, strings.TrimRight(o, "/"))
			}
		}
	} else if c.PublicURL != nil {
		// account.kaicorplabs.com → https://kaicorplabs.com
		if host := c.PublicURL.Hostname(); strings.Count(host, ".") >= 2 {
			padre := host[strings.Index(host, ".")+1:]
			c.SessionOrigins = []string{c.PublicURL.Scheme + "://" + padre}
		}
	}
	if g := strings.TrimSpace(os.Getenv("ACCOUNT_ADMIN_GROUP")); g != "" {
		c.AdminGroup = g
	}
	proxies := strings.TrimSpace(os.Getenv("ACCOUNT_TRUSTED_PROXY_CIDRS"))
	header := strings.TrimSpace(os.Getenv("ACCOUNT_CLIENT_IP_HEADER"))
	if proxies != "" {
		for _, raw := range strings.Split(proxies, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil || p.Addr().Is4In6() {
				errs = append(errs, errors.New("ACCOUNT_TRUSTED_PROXY_CIDRS: se esperan CIDR IPv4 o IPv6 (sin IPv4 mapeada) separados por comas"))
			} else {
				c.TrustedProxies = append(c.TrustedProxies, p.Masked())
			}
		}
	}
	if header != "" {
		switch strings.ToLower(header) {
		case "cf-connecting-ip":
			c.ClientIPHeader = "CF-Connecting-IP"
		case "x-real-ip":
			c.ClientIPHeader = "X-Real-IP"
		default:
			errs = append(errs, errors.New("ACCOUNT_CLIENT_IP_HEADER: sólo CF-Connecting-IP o X-Real-IP"))
		}
	}
	if (proxies == "") != (header == "") {
		errs = append(errs, errors.New("ACCOUNT_TRUSTED_PROXY_CIDRS y ACCOUNT_CLIENT_IP_HEADER: se configuran juntas"))
	}
	c.UnconfirmedDays = 14
	if v := strings.TrimSpace(os.Getenv("ACCOUNT_UNCONFIRMED_DAYS")); v != "" {
		if d, err := strconv.Atoi(v); err != nil || d < 0 || d > 365 {
			errs = append(errs, fmt.Errorf("ACCOUNT_UNCONFIRMED_DAYS: entero de 0 (desactivado) a 365: %q", v))
		} else {
			c.UnconfirmedDays = d
		}
	}
	c.SMTPHost = strings.TrimSpace(os.Getenv("ACCOUNT_SMTP_HOST"))
	c.SMTPPort = strings.TrimSpace(os.Getenv("ACCOUNT_SMTP_PORT"))
	c.SMTPUser = strings.TrimSpace(os.Getenv("ACCOUNT_SMTP_USER"))
	c.SMTPPass = os.Getenv("ACCOUNT_SMTP_PASS")
	c.SMTPFrom = strings.TrimSpace(os.Getenv("ACCOUNT_SMTP_FROM"))
	if c.SMTPHost != "" && (c.SMTPUser == "" || c.SMTPPass == "" || c.SMTPFrom == "") {
		errs = append(errs, errors.New("ACCOUNT_SMTP_HOST está pero faltan ACCOUNT_SMTP_USER, ACCOUNT_SMTP_PASS o ACCOUNT_SMTP_FROM (\"Nombre <correo>\")"))
	}
	host := os.Getenv("HOSTNAME")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3467"
	}
	c.Addr = host + ":" + port

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func validarGoTrueURL(raw string, permitirHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("ACCOUNT_GOTRUE_URL: falta (https://<pasarela>/auth/v1)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("ACCOUNT_GOTRUE_URL: no es una URL https válida: %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("ACCOUNT_GOTRUE_URL: no admite usuario, query ni fragmento: %q", raw)
	}
	if u.Scheme == "http" {
		if !permitirHTTP {
			return "", errors.New("ACCOUNT_GOTRUE_URL: exige https; sólo desarrollo local puede usar http con ACCOUNT_GOTRUE_INSECURE_HTTP=1")
		}
		if !esLoopbackLiteral(u.Hostname()) {
			return "", errors.New("ACCOUNT_GOTRUE_URL: el http de desarrollo sólo admite una IP literal de loopback")
		}
	}
	return strings.TrimRight(raw, "/"), nil
}

func esLoopbackLiteral(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && !ip.Is4In6() && ip.Zone() == "" && ip.IsLoopback()
}

// CookieSecure dice si las cookies llevan Secure. FromEnv sólo permite false
// para el modo HTTP explícito sobre una IP literal de loopback.
func (c *Config) CookieSecure() bool {
	return !c.InsecureCookies && c.PublicURL.Scheme == "https"
}
