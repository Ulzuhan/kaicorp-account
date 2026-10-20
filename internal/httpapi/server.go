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
	"net/http"
	"net/netip"
	"net/url"
	"path"
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
	correo    remitenteCorreo // nil si no hay SMTP propio
	paginas   map[string]*template.Template
	limitador *limitador
	// intentosPasswordLocal sólo existe para servidores unitarios sin Store.
	// Producción persiste siempre este estado en PostgreSQL.
	intentosPasswordMu    sync.Mutex
	intentosPasswordLocal map[string]*intentoPasswordLocal
	// enrolando guarda, por sesión y unos minutos, el factor TOTP a medias de
	// dar de alta: el QR es demasiado grande para una cookie.
	enrolando           sync.Map
	capacidadesPassword sync.Map
	autoridadesMFA      sync.Map
	bloqueosMFA         sync.Map
	cambiosCorreo       sync.Map
	// resolverEnlaceCorreo relee el estado de un solo uso del proveedor antes
	// de canjearlo. Es función para que las pruebas unitarias puedan modelar el
	// contrato sin levantar PostgreSQL; producción siempre instala la del Store.
	resolverEnlaceCorreo func(context.Context, string, string) (*store.EnlaceCorreoPendiente, error)
}

type remitenteCorreo interface {
	EnviarAcceso(context.Context, string, correo.Acceso) error
	EnviarCambioCorreo(context.Context, string, string, correo.CambioCorreo) error
}

// paginas son las plantillas de página; cada una se compila con layout.html.
// Una página que no esté aquí da «plantilla desconocida» al servirse (pasó con
// salir.html en 0.3.3), así que la prueba TestPlantillasCompilan las recorre.
var paginas = []string{"home.html", "entrar.html", "registro.html", "registro-password.html", "correo.html", "enlace.html", "confirmar-correo.html", "recuperar.html", "restablecer.html",
	"factor.html", "consent.html", "sin-acceso.html", "cuenta.html", "admin.html", "admin-cuenta.html", "error.html", "salir.html", "reenviar.html"}

// New construye el servidor y compila las plantillas.
func New(cfg *config.Config, st *store.Store, gt *gotrue.Client, ses *session.Manager, rem *correo.Remitente) (*Server, error) {
	s := &Server{cfg: cfg, st: st, gt: gt, ses: ses, correo: rem, paginas: map[string]*template.Template{}, limitador: nuevoLimitador(),
		intentosPasswordLocal: map[string]*intentoPasswordLocal{}}
	if st != nil {
		s.resolverEnlaceCorreo = func(ctx context.Context, tipo, hash string) (*store.EnlaceCorreoPendiente, error) {
			return st.ResolverEnlaceCorreo(ctx, tipo, hash, cfg.EmailLinkTTL)
		}
	}
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
	mux.HandleFunc("GET /registro/password", s.registroPasswordGET)
	mux.HandleFunc("POST /registro/password", s.registroPasswordPOST)
	mux.HandleFunc("GET /verificar", s.verificar)
	mux.HandleFunc("POST /verificar", s.verificarPOST)
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
	mux.HandleFunc("POST /cuenta/correo", s.cuentaCorreo)
	mux.HandleFunc("GET /cuenta/correo/confirmar", s.cuentaCorreoConfirmarGET)
	mux.HandleFunc("POST /cuenta/correo/confirmar", s.cuentaCorreoConfirmarPOST)
	mux.HandleFunc("POST /cuenta/password", s.cuentaPassword)
	mux.HandleFunc("POST /cuenta/mfa/autorizar", s.mfaAutorizar)
	mux.HandleFunc("POST /cuenta/mfa/confirmar", s.mfaConfirmar)
	mux.HandleFunc("POST /cuenta/factor/alta", s.factorAlta)
	mux.HandleFunc("POST /cuenta/factor/verificar", s.factorVerificar)
	mux.HandleFunc("POST /cuenta/factor/borrar", s.factorBorrar)
	mux.HandleFunc("POST /cuenta/passkey/alta", s.passkeyAlta)
	mux.HandleFunc("POST /cuenta/passkey/verificar", s.passkeyVerificar)
	mux.HandleFunc("POST /cuenta/grant/revocar", s.grantRevocar)
	mux.HandleFunc("POST /cuenta/sesiones/cerrar", s.sesionesCerrar)

	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /admin/cuenta/{id}", s.adminCuenta)
	mux.HandleFunc("POST /admin/solicitud", s.adminSolicitud)
	mux.HandleFunc("POST /admin/vincular", s.adminVincular)
	mux.HandleFunc("POST /admin/invitar", s.adminInvitar)
	mux.HandleFunc("POST /admin/reenviar-invitacion", s.adminReenviarInvitacion)
	mux.HandleFunc("POST /admin/conceder", s.adminConceder)
	mux.HandleFunc("POST /admin/revocar", s.adminRevocar)
	mux.HandleFunc("POST /admin/cerrar-sesiones", s.adminCerrarSesiones)
	mux.HandleFunc("POST /admin/bloquear", s.adminBloquear)

	mux.HandleFunc("/", s.noEncontrado)
	return s.registrando(s.cabeceras(s.sinCapacidadesEnURL(s.conSesion(s.conCSRF(s.recuperando(mux))))))
}

// registrando escribe una línea por petición: método, ruta (sin query, que
// lleva capacidades y autorizaciones), código y milisegundos. Nada de quién.
// La ruta se vuelve a codificar desde Path y se entrecomilla: URL.Path ya está
// decodificada y no puede cruzar tal cual a un registro orientado a líneas.
// No se reutiliza RawPath, para que codificaciones equivalentes tengan una sola
// representación en el registro.
func rutaLogHTTP(r *http.Request) string {
	return (&url.URL{Path: r.URL.Path}).EscapedPath()
}

func (s *Server) registrando(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		inicio := time.Now()
		rw := &conCodigo{ResponseWriter: w, codigo: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %q %d %dms", r.Method, rutaLogHTTP(r), rw.codigo, time.Since(inicio).Milliseconds())
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

// contentSecurityPolicy: sólo scripts nuestros (passkey.js para WebAuthn y
// email-link.js para sacar capacidades del fragmento), nada inline ni externo.
// Las imágenes en data: son los QR de los factores, que GoTrue devuelve así.
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
	return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'none'; form-action " + formAction + "; base-uri 'none'; frame-ancestors 'none'"
}

func (s *Server) cabeceras(next http.Handler) http.Handler {
	csp := contentSecurityPolicy(s.cfg.PublicURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		if esInterstitialCapacidad(r.URL.Path) || mencionaCapacidadURL(r.URL.RawQuery) {
			h.Set("Referrer-Policy", "no-referrer")
		} else {
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") && !strings.HasPrefix(r.URL.Path, "/plantillas/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func esInterstitialCapacidad(ruta string) bool {
	return ruta == "/verificar" || ruta == "/restablecer" || ruta == "/cuenta/correo/confirmar"
}

func mencionaParametro(raw, nombre string) bool {
	for _, parte := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		clave, _, _ := strings.Cut(parte, "=")
		decodificada, err := url.QueryUnescape(clave)
		if err == nil && decodificada == nombre {
			return true
		}
	}
	return false
}

func mencionaCapacidadURL(rawQuery string) bool {
	return mencionaParametro(rawQuery, "token_hash") || mencionaParametro(rawQuery, "token")
}

// sinCapacidadesEnURL es la última defensa dentro del borde HTTP de la app.
// Las plantillas nuevas usan fragmentos, que el navegador nunca envía. Un
// enlace antiguo o manipulado se redirige sin el secreto y debe volver a
// emitirse: copiarlo a Location repetiría la exposición en metadatos HTTP.
func (s *Server) sinCapacidadesEnURL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mencionaCapacidadURL(r.URL.RawQuery) {
			next.ServeHTTP(w, r)
			return
		}
		limpia := *r.URL
		valores, err := url.ParseQuery(limpia.RawQuery)
		if err != nil {
			limpia.RawQuery = ""
		} else {
			valores.Del("token_hash")
			valores.Del("token")
			limpia.RawQuery = valores.Encode()
		}
		limpia.Fragment = ""
		http.Redirect(w, r, limpia.RequestURI(), http.StatusSeeOther)
	})
}

func (s *Server) recuperando(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("pánico en %s %q: %v", r.Method, rutaLogHTTP(r), rec)
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
			if !s.origenFormularioValido(r) {
				s.errorPagina(w, r, http.StatusForbidden, "The form expired", "Go back, reload the page and try again.")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				s.errorPagina(w, r, http.StatusBadRequest, "Bad request", "The form could not be read.")
				return
			}
			if !s.ses.CSRFValido(r, sesionDe(r)) {
				s.errorPagina(w, r, http.StatusForbidden, "The form expired", "Go back, reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// campoPostUnico evita que un portador duplicado dependa del orden elegido por
// net/http. Sólo el cuerpo puede aportar capacidades: nunca la query.
func campoPostUnico(r *http.Request, nombre string) (string, bool) {
	if r.PostForm == nil {
		if err := r.ParseForm(); err != nil {
			return "", false
		}
	}
	valores := r.PostForm[nombre]
	if len(valores) != 1 || valores[0] == "" {
		return "", false
	}
	return valores[0], true
}

// Los formularios sólo se envían desde el origen configurado, nunca desde un
// hermano autorizado para /api/session. No se confía en Host ni en el proxy.
// Sin Origin se exige Referer del mismo origen; si faltan ambos se rechaza.
func (s *Server) origenFormularioValido(r *http.Request) bool {
	if origenes := r.Header.Values("Origin"); len(origenes) != 0 {
		if len(origenes) != 1 {
			return false
		}
		u, err := url.Parse(origenes[0])
		return err == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
			!strings.Contains(origenes[0], "#") && s.mismoOrigenFormulario(u)
	}
	referencias := r.Header.Values("Referer")
	if len(referencias) != 1 {
		return false
	}
	u, err := url.Parse(referencias[0])
	return err == nil && u.Fragment == "" && !strings.Contains(referencias[0], "#") && s.mismoOrigenFormulario(u)
}

func (s *Server) mismoOrigenFormulario(u *url.URL) bool {
	propio := s.cfg.PublicURL
	host := func(v *url.URL) string {
		if ip, err := netip.ParseAddr(v.Hostname()); err == nil {
			return ip.String()
		}
		return strings.ToLower(v.Hostname())
	}
	puerto := func(v *url.URL) string {
		if p := v.Port(); p != "" {
			return p
		}
		if v.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return u.User == nil && u.Opaque == "" && u.Scheme == propio.Scheme &&
		host(u) == host(propio) && puerto(u) == puerto(propio)
}

// ── Render ─────────────────────────────────────────────────────────────────

func (s *Server) render(w http.ResponseWriter, r *http.Request, pagina, titulo string, datos map[string]any, status int) {
	if datos == nil {
		datos = map[string]any{}
	}
	a := sesionDe(r)
	datos["Title"] = titulo
	datos["AssetVersion"] = web.AssetVersion()
	datos["CSRF"] = s.ses.CSRF(w, r, a)
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
	if contieneCaracterProhibido(raw) {
		return "/"
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || urlContieneCaracterProhibido(u) {
		return "/"
	}
	if u.IsAbs() {
		if u.Host == "" {
			return "/"
		}
		if u.Scheme == s.cfg.PublicURL.Scheme && u.Host == s.cfg.PublicURL.Host {
			// Un retorno al mismo origen se reduce a una ruta local. El fragmento
			// se descarta igual que hacía RequestURI.
			u = &url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
			if u.Path == "" {
				u.Path = "/"
			}
		} else if u.Scheme == "https" && s.hostDeCasa(u.Hostname()) {
			return u.String()
		} else {
			return "/"
		}
	}
	if u.Host != "" || u.Scheme != "" {
		return "/"
	}

	u.Path = path.Clean(u.Path)
	u.RawPath = ""
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return u.String()
}

func contieneCaracterProhibido(valor string) bool {
	for _, b := range []byte(valor) {
		if b == '\\' || b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func urlContieneCaracterProhibido(u *url.URL) bool {
	if contieneCaracterProhibido(u.Path) || contieneCaracterProhibido(u.Fragment) {
		return true
	}
	query, err := url.QueryUnescape(u.RawQuery)
	return err != nil || contieneCaracterProhibido(query)
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

// requiereAutoridadAdmin abre la frontera linealizable de una mutación. A
// diferencia de requiereAdmin, la membresía se relee después de bloquear al
// actor y a todos los destinos, y esos bloqueos sobreviven hasta Cerrar.
func (s *Server) requiereAutoridadAdmin(w http.ResponseWriter, r *http.Request, objetivos ...string) (*session.Actual, *store.AutoridadAdmin) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return nil, nil
	}
	autoridad, err := s.st.AutorizarAdmin(r.Context(), a.UserID, s.cfg.AdminGroup, objetivos...)
	if errors.Is(err, store.ErrAdministradorRevocado) {
		s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "This page is for administrators.")
		return nil, nil
	}
	if err != nil {
		log.Printf("autoridad administrativa de %s: %v", a.UserID, err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Could not authorize the change", "Try again.")
		return nil, nil
	}
	// El middleware pudo cargar la sesión justo antes de una revocación. Se
	// vuelve a leer bajo el bloqueo del actor y, además, se exige que la fila
	// haya nacido después de su última generación administrativa. Así una
	// limpieza fallida seguida de una reconcesión tampoco revive la petición.
	if a.ID != "" {
		fila, err := s.st.Sesion(r.Context(), a.ID)
		if errors.Is(err, store.ErrNoExiste) || err == nil && (fila.UserID != a.UserID ||
			autoridad.Generacion() > 0 && !fila.Creada.After(autoridad.Actualizada())) {
			autoridad.Cerrar()
			s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "This administrative session is no longer valid.")
			return nil, nil
		}
		if err != nil {
			autoridad.Cerrar()
			log.Printf("revalidar sesión administrativa de %s: %v", a.UserID, err)
			s.errorPagina(w, r, http.StatusInternalServerError, "Could not authorize the change", "Try again.")
			return nil, nil
		}
	}
	return a, autoridad
}

// ipDe sólo acepta la cabecera elegida de un proxy explícito que la sobrescribe.
// Toda identidad se normaliza antes de formar la clave del limitador.
func (s *Server) ipDe(r *http.Request) (string, bool) {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	peer := remote.Addr().WithZone("").Unmap()
	trusted := false
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return peer.String(), true
	}
	values := r.Header.Values(s.cfg.ClientIPHeader)
	if len(values) != 1 {
		return "", false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || ip.Zone() != "" {
		return "", false
	}
	return ip.Unmap().String(), true
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
	ip, ok := s.ipDe(r)
	if !ok {
		s.errorPagina(w, r, http.StatusBadRequest, "Bad request", "The client address could not be determined.")
		return true
	}
	if s.limitador.permite(accion+"|"+ip, max, porMinuto) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	s.errorPagina(w, r, http.StatusTooManyRequests, "Too many attempts", "Wait a minute and try again.")
	return true
}
