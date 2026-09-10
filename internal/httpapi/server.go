// Package httpapi es la cara HTTP de la app de cuenta: el enrutador, las
// cabeceras de seguridad, la carga de sesión y CSRF, y las páginas.
//
// Todo se sirve desde plantillas Go embebidas y sin JavaScript: una interfaz
// de autenticación con CSP estricta y sin build es más pequeña y más fácil de
// auditar. El cromado es el de la casa, calcado de LinkUp.
package httpapi

import (
	"context"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/correo"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
	"github.com/Ulzuhan/kaicorp-account/internal/web"
)

// Server es la aplicación HTTP.
type Server struct {
	cfg       *config.Config
	st        *store.Store
	gt        *gotrue.Client
	ses       *session.Manager
	correo    *correo.Remitente // nil si no hay SMTP: se concede sin avisar
	paginas   map[string]*template.Template
	limitador *limitador
	// enrolando guarda, por sesión y unos minutos, el factor TOTP a medias de
	// dar de alta: el QR es demasiado grande para una cookie.
	enrolando sync.Map
}

// paginas son las plantillas de página; cada una se compila con layout.html.
// Una página que no esté aquí da «plantilla desconocida» al servirse (pasó con
// salir.html en 0.3.3), así que la prueba TestPlantillasCompilan las recorre.
var paginas = []string{"home.html", "entrar.html", "registro.html", "correo.html", "recuperar.html", "restablecer.html",
	"factor.html", "consent.html", "sin-acceso.html", "cuenta.html", "admin.html", "admin-cuenta.html", "error.html", "salir.html", "reenviar.html"}

// New construye el servidor y compila las plantillas.
func New(cfg *config.Config, st *store.Store, gt *gotrue.Client, ses *session.Manager, rem *correo.Remitente) (*Server, error) {
	s := &Server{cfg: cfg, st: st, gt: gt, ses: ses, correo: rem, paginas: map[string]*template.Template{}, limitador: nuevoLimitador()}
	for _, p := range paginas {
		t, err := template.New("layout.html").ParseFS(web.EmbeddedFS, "templates/layout.html", "templates/"+p)
		if err != nil {
			return nil, err
		}
		s.paginas[p] = t
	}
	return s, nil
}

type claveCtx int

const claveSesion claveCtx = 1

func sesionDe(r *http.Request) *session.Actual {
	a, _ := r.Context().Value(claveSesion).(*session.Actual)
	return a
}

// Handler devuelve el enrutador con todo el middleware puesto.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", web.StaticFS()))
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /plantillas/{nombre}", s.plantilla)

	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /entrar", s.entrarGET)
	mux.HandleFunc("POST /entrar", s.entrarPOST)
	mux.HandleFunc("GET /registro", s.registroGET)
	mux.HandleFunc("POST /registro", s.registroPOST)
	mux.HandleFunc("GET /verificar", s.verificar)
	mux.HandleFunc("GET /reenviar", s.reenviarGET)
	mux.HandleFunc("POST /reenviar", s.reenviarPOST)
	mux.HandleFunc("GET /recuperar", s.recuperarGET)
	mux.HandleFunc("POST /recuperar", s.recuperarPOST)
	mux.HandleFunc("GET /restablecer", s.restablecerGET)
	mux.HandleFunc("POST /restablecer", s.restablecerPOST)
	mux.HandleFunc("GET /factor", s.factorGET)
	mux.HandleFunc("POST /factor", s.factorPOST)
	mux.HandleFunc("GET /salir", s.salirGET)
	mux.HandleFunc("POST /salir", s.salir)
	mux.HandleFunc("GET /api/session", s.apiSesion)

	mux.HandleFunc("POST /solicitar/{grupo}", s.solicitar)
	mux.HandleFunc("GET /oauth/consent", s.consentGET)
	mux.HandleFunc("POST /oauth/consent", s.consentPOST)

	mux.HandleFunc("GET /cuenta", s.cuenta)
	mux.HandleFunc("POST /cuenta/nombre", s.cuentaNombre)
	mux.HandleFunc("POST /cuenta/password", s.cuentaPassword)
	mux.HandleFunc("POST /cuenta/factor/alta", s.factorAlta)
	mux.HandleFunc("POST /cuenta/factor/verificar", s.factorVerificar)
	mux.HandleFunc("POST /cuenta/factor/borrar", s.factorBorrar)
	mux.HandleFunc("POST /cuenta/grant/revocar", s.grantRevocar)
	mux.HandleFunc("POST /cuenta/sesiones/cerrar", s.sesionesCerrar)

	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /admin/cuenta/{id}", s.adminCuenta)
	mux.HandleFunc("POST /admin/solicitud", s.adminSolicitud)
	mux.HandleFunc("POST /admin/vincular", s.adminVincular)
	mux.HandleFunc("POST /admin/invitar", s.adminInvitar)
	mux.HandleFunc("POST /admin/conceder", s.adminConceder)
	mux.HandleFunc("POST /admin/revocar", s.adminRevocar)
	mux.HandleFunc("POST /admin/cerrar-sesiones", s.adminCerrarSesiones)
	mux.HandleFunc("POST /admin/bloquear", s.adminBloquear)

	mux.HandleFunc("/", s.noEncontrado)
	return s.registrando(s.cabeceras(s.conSesion(s.conCSRF(s.recuperando(mux)))))
}

// registrando escribe una línea por petición: método, ruta (sin query, que
// lleva token_hash y authorization_id), código y milisegundos. Nada de quién.
func (s *Server) registrando(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		inicio := time.Now()
		rw := &conCodigo{ResponseWriter: w, codigo: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d %dms", r.Method, r.URL.Path, rw.codigo, time.Since(inicio).Milliseconds())
	})
}

type conCodigo struct {
	http.ResponseWriter
	codigo int
}

func (c *conCodigo) WriteHeader(code int) {
	c.codigo = code
	c.ResponseWriter.WriteHeader(code)
}

// contentSecurityPolicy: sin scripts, sin inline, sin nada de fuera. Las
// imágenes en data: son los QR de los factores, que GoTrue devuelve así.
//
// `form-action` lleva, además de 'self', el dominio de la casa y sus
// subdominios. No porque haya formularios que envíen fuera: porque Chrome
// aplica form-action también a la REDIRECCIÓN que responde a un formulario, y
// dos formularios de aquí terminan en otro origen de la casa: el consentimiento
// OAuth (303 al callback de la herramienta) y entrar o salir desde la web
// pública (303 de vuelta a kaicorplabs.com). Con 'self' a secas, Chrome deja a
// la persona clavada en la página con el envío hecho y sin explicación; Firefox
// no lo bloquea, y por eso un cliente HTTP de prueba tampoco lo ve.
func contentSecurityPolicy(publicURL *url.URL) string {
	formAction := "'self'"
	if host := publicURL.Hostname(); strings.Count(host, ".") >= 2 {
		padre := host[strings.Index(host, ".")+1:]
		formAction += " https://" + padre + " https://*." + padre
	}
	return "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'none'; form-action " + formAction + "; base-uri 'none'; frame-ancestors 'none'"
}

func (s *Server) cabeceras(next http.Handler) http.Handler {
	csp := contentSecurityPolicy(s.cfg.PublicURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") && !strings.HasPrefix(r.URL.Path, "/plantillas/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recuperando(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("pánico en %s %s: %v", r.Method, r.URL.Path, rec)
				s.errorPagina(w, r, http.StatusInternalServerError, "Something went wrong", "The page could not be served. It has been logged.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) conSesion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/plantillas/") || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		a, err := s.ses.Cargar(r.Context(), w, r)
		if err != nil {
			log.Printf("sesión: %v", err)
			s.errorPagina(w, r, http.StatusServiceUnavailable, "Temporarily unavailable", "The account service cannot reach its database right now. Try again in a minute.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claveSesion, a)))
	})
}

func (s *Server) conCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				s.errorPagina(w, r, http.StatusBadRequest, "Bad request", "The form could not be read.")
				return
			}
			if !s.ses.CSRFValido(r) {
				s.errorPagina(w, r, http.StatusForbidden, "The form expired", "Go back, reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ── Render ─────────────────────────────────────────────────────────────────

func (s *Server) render(w http.ResponseWriter, r *http.Request, pagina, titulo string, datos map[string]any, status int) {
	if datos == nil {
		datos = map[string]any{}
	}
	a := sesionDe(r)
	datos["Title"] = titulo
	datos["AssetVersion"] = web.AssetVersion()
	datos["CSRF"] = s.ses.CSRF(w, r)
	datos["User"] = a
	if a != nil {
		if _, ok := datos["IsAdmin"]; !ok {
			datos["IsAdmin"] = s.esAdmin(r.Context(), a)
		}
	}
	if _, ok := datos["Flash"]; !ok {
		datos["Flash"] = s.leerFlash(w, r)
	}
	t := s.paginas[pagina]
	if t == nil {
		http.Error(w, "plantilla desconocida", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout.html", datos); err != nil {
		log.Printf("plantilla %s: %v", pagina, err)
	}
}

func (s *Server) errorPagina(w http.ResponseWriter, r *http.Request, status int, titulo, mensaje string) {
	s.render(w, r, "error.html", titulo, map[string]any{"Mensaje": mensaje}, status)
}

func (s *Server) noEncontrado(w http.ResponseWriter, r *http.Request) {
	s.errorPagina(w, r, http.StatusNotFound, "Not found", "There is nothing at this address.")
}

// esAdmin consulta la membresía de administración.
func (s *Server) esAdmin(ctx context.Context, a *session.Actual) bool {
	if a == nil {
		return false
	}
	ok, err := s.st.EsMiembro(ctx, a.UserID, s.cfg.AdminGroup)
	return err == nil && ok
}

func (s *Server) membresias(ctx context.Context, userID string) []string {
	ms, err := s.st.MembresiasDe(ctx, userID)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Grupo)
	}
	return out
}

// ── Flash ──────────────────────────────────────────────────────────────────

const cookieFlash = "account_flash"

func (s *Server) ponerFlash(w http.ResponseWriter, texto string) {
	http.SetCookie(w, &http.Cookie{Name: cookieFlash, Value: url.QueryEscape(texto), Path: "/", MaxAge: 120,
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
}

func (s *Server) leerFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(cookieFlash)
	if err != nil || c.Value == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: cookieFlash, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	v, _ := url.QueryUnescape(c.Value)
	return v
}

// ── Ayudas ─────────────────────────────────────────────────────────────────

// nextSeguro decide a dónde se vuelve tras entrar, registrarse o salir, sin ser
// un redirector abierto: rutas internas; URLs absolutas de ESTE origen (lo que
// GoTrue devuelve en {{ .RedirectTo }}), recortadas a su ruta; y URLs https de
// la casa —el dominio padre del PublicURL y sus subdominios: la web pública y
// las herramientas—, que se devuelven enteras para que quien vino de
// kaicorplabs.com vuelva a kaicorplabs.com. Todo lo demás es «/».
func (s *Server) nextSeguro(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil {
			return "/"
		}
		if u.Scheme == s.cfg.PublicURL.Scheme && u.Host == s.cfg.PublicURL.Host {
			raw = u.RequestURI()
		} else if u.Scheme == "https" && s.hostDeCasa(u.Hostname()) {
			return u.String()
		} else {
			return "/"
		}
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	return raw
}

// hostDeCasa: kaicorplabs.com o cualquier *.kaicorplabs.com, tomando el padre
// del PublicURL (account.kaicorplabs.com → kaicorplabs.com).
func (s *Server) hostDeCasa(host string) bool {
	host = strings.ToLower(host)
	propio := s.cfg.PublicURL.Hostname()
	if strings.Count(propio, ".") < 2 {
		return false
	}
	padre := propio[strings.Index(propio, ".")+1:]
	return host == padre || strings.HasSuffix(host, "."+padre)
}

// requiereSesion redirige a /entrar conservando el destino.
func (s *Server) requiereSesion(w http.ResponseWriter, r *http.Request) *session.Actual {
	a := sesionDe(r)
	if a == nil {
		http.Redirect(w, r, "/entrar?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil
	}
	return a
}

// requiereAdmin exige sesión y membresía de administración.
func (s *Server) requiereAdmin(w http.ResponseWriter, r *http.Request) *session.Actual {
	a := s.requiereSesion(w, r)
	if a == nil {
		return nil
	}
	if !policy.Administra(s.cfg.AdminGroup, s.membresias(r.Context(), a.UserID)) {
		s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "This page is for administrators.")
		return nil
	}
	return a
}

// ipDe saca la IP real detrás del túnel.
func ipDe(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// mensajeGoTrue traduce un error del proveedor a algo que se le puede decir a
// la persona sin contarle de más ni mentirle.
func mensajeGoTrue(err error) string {
	var ge *gotrue.Error
	if !errors.As(err, &ge) {
		return "The identity service did not answer. Try again in a minute."
	}
	switch {
	case ge.ErrorCode == "weak_password":
		return "That password is too weak: use 12 characters or more, and not something common."
	case ge.ErrorCode == "signup_disabled":
		return "Registration is closed right now."
	case ge.ErrorCode == "over_email_send_rate_limit", ge.Status == 429:
		return "Too many attempts. Wait a minute and try again."
	case ge.ErrorCode == "otp_expired", ge.ErrorCode == "otp_disabled":
		return "That link has expired or was already used. Ask for a new one."
	case ge.ErrorCode == "mfa_verification_failed", ge.ErrorCode == "mfa_challenge_expired":
		return "The code is not right or has expired."
	case ge.ErrorCode == "same_password":
		return "The new password is the same as the current one."
	case ge.ErrorCode == "user_banned":
		return "This account is blocked."
	case ge.Status == 401 || ge.Status == 403:
		return "Your session is no longer valid. Sign in again."
	}
	log.Printf("gotrue: %v", err)
	return "The identity service refused the request. Try again; if it persists, tell us."
}

// ── Limitador ──────────────────────────────────────────────────────────────

// limitador es un cubo por IP y por acción, en memoria. El borde ya frena
// (8 POST por 10 s), esto es la segunda capa y protege los endpoints caros.
type limitador struct {
	mu     sync.Mutex
	cubos  map[string]*cubo
	ultima time.Time
}

type cubo struct {
	fichas float64
	visto  time.Time
}

func nuevoLimitador() *limitador { return &limitador{cubos: map[string]*cubo{}, ultima: time.Now()} }

// permite descuenta una ficha del cubo clave; capacidad `max`, recarga `porMinuto`.
func (l *limitador) permite(clave string, max, porMinuto float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.ultima) > 10*time.Minute {
		for k, c := range l.cubos {
			if now.Sub(c.visto) > 10*time.Minute {
				delete(l.cubos, k)
			}
		}
		l.ultima = now
	}
	c := l.cubos[clave]
	if c == nil {
		c = &cubo{fichas: max, visto: now}
		l.cubos[clave] = c
	}
	c.fichas += now.Sub(c.visto).Minutes() * porMinuto
	if c.fichas > max {
		c.fichas = max
	}
	c.visto = now
	if c.fichas < 1 {
		return false
	}
	c.fichas--
	return true
}

func (s *Server) frena(w http.ResponseWriter, r *http.Request, accion string, max, porMinuto float64) bool {
	if s.limitador.permite(accion+"|"+ipDe(r), max, porMinuto) {
		return false
	}
	s.errorPagina(w, r, http.StatusTooManyRequests, "Too many attempts", "Wait a minute and try again.")
	return true
}
