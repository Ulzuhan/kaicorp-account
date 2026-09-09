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
	// GoTrueURL es la base INTERNA de la API de GoTrue, con su prefijo /auth/v1:
	// http://<pasarela>/auth/v1. Dentro de un contenedor 127.0.0.1 es el
	// contenedor, así que aquí va el nombre de la pasarela en su red.
	GoTrueURL string
	// AnonKey es la clave pública (JWT con role anon) que GoTrue exige en `apikey`.
	AnonKey string
	// ServiceKey es la clave de administración (role service_role). Sólo la usan
	// las operaciones de administración: borrar cuentas y bloquearlas.
	ServiceKey string
	// DatabaseURL es la conexión al Postgres de la instancia con el rol `account`.
	DatabaseURL string
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
	// AdminGroup es la membresía que abre /admin.
	AdminGroup string
	// InsecureCookies quita `Secure` de las cookies: sólo para pruebas por http.
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

	c.GoTrueURL = strings.TrimRight(strings.TrimSpace(os.Getenv("ACCOUNT_GOTRUE_URL")), "/")
	if c.GoTrueURL == "" {
		errs = append(errs, errors.New("ACCOUNT_GOTRUE_URL: falta (http://<pasarela>/auth/v1)"))
	} else if !strings.HasPrefix(c.GoTrueURL, "http://") && !strings.HasPrefix(c.GoTrueURL, "https://") {
		errs = append(errs, fmt.Errorf("ACCOUNT_GOTRUE_URL: tiene que ser http(s): %q", c.GoTrueURL))
	}

	c.AnonKey = strings.TrimSpace(os.Getenv("ACCOUNT_ANON_KEY"))
	if c.AnonKey == "" {
		errs = append(errs, errors.New("ACCOUNT_ANON_KEY: falta"))
	}
	c.ServiceKey = strings.TrimSpace(os.Getenv("ACCOUNT_SERVICE_KEY"))
	if c.ServiceKey == "" {
		errs = append(errs, errors.New("ACCOUNT_SERVICE_KEY: falta"))
	}
	c.DatabaseURL = strings.TrimSpace(os.Getenv("ACCOUNT_DATABASE_URL"))
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("ACCOUNT_DATABASE_URL: falta"))
	}

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
	c.InsecureCookies = os.Getenv("ACCOUNT_INSECURE_COOKIES") == "1"

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

// CookieSecure dice si las cookies llevan Secure: siempre salvo en pruebas por http.
func (c *Config) CookieSecure() bool {
	return !c.InsecureCookies && c.PublicURL.Scheme == "https"
}
