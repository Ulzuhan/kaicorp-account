package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
)

// mensajeRevisaCorreo es el mismo texto para «nuevo», «ya existía» y «no
// existe»: quien mira el formulario no puede averiguar qué correos tienen cuenta.
const mensajeRevisaCorreo = "If that address can receive email, a message is on its way. Open the link in it to continue."

func correoValido(s string) (string, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", false
	}
	return s, true
}

// ── Entrar ─────────────────────────────────────────────────────────────────

func (s *Server) entrarGET(w http.ResponseWriter, r *http.Request) {
	if sesionDe(r) != nil {
		http.Redirect(w, r, s.nextSeguro(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.render(w, r, "entrar.html", "Sign in", map[string]any{"Next": s.nextSeguro(r.URL.Query().Get("next"))}, http.StatusOK)
}

func (s *Server) entrarPOST(w http.ResponseWriter, r *http.Request) {
	if s.frena(w, r, "entrar", 10, 10) {
		return
	}
	next := s.nextSeguro(r.PostFormValue("next"))
	email, ok := correoValido(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	falla := func(msg string) {
		s.render(w, r, "entrar.html", "Sign in", map[string]any{"Next": next, "Email": r.PostFormValue("email"), "Error": msg}, http.StatusUnauthorized)
	}
	if !ok || password == "" {
		falla("Wrong email or password.")
		return
	}
	gs, err := s.gt.Login(r.Context(), email, password)
	if err != nil {
		if errors.Is(err, gotrue.ErrInvalidLogin) || errors.Is(err, gotrue.ErrEmailNotConfirm) || errors.Is(err, gotrue.ErrUnauthorized) {
			// No se distingue «contraseña mal» de «correo sin confirmar»: decirlo
			// sería confirmar que la cuenta existe.
			falla("Wrong email or password, or the address has not been confirmed yet.")
			return
		}
		falla(mensajeGoTrue(err))
		return
	}
	recordar := r.PostFormValue("remember") == "1"
	if gs.User.HasVerifiedFactor() {
		// Segundo factor: los tokens aal1 no se convierten en sesión de la app.
		// Van sellados en una cookie de cinco minutos hasta que llegue el código.
		s.ponerPendienteMFA(w, gs, next, recordar)
		http.Redirect(w, r, "/factor", http.StatusSeeOther)
		return
	}
	if _, err := s.ses.Crear(r.Context(), w, r, gs, "aal1", recordar); err != nil {
		log.Printf("crear sesión: %v", err)
		falla("Could not start the session. Try again.")
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ── Segundo factor al entrar ───────────────────────────────────────────────

const cookieMFA = "account_mfa"

type pendienteMFA struct {
	Access   string `json:"a"`
	Refresh  string `json:"r"`
	Next     string `json:"n"`
	Hasta    int64  `json:"h"`
	Recordar bool   `json:"k,omitempty"`
}

func (s *Server) ponerPendienteMFA(w http.ResponseWriter, gs *gotrue.Session, next string, recordar bool) {
	p := pendienteMFA{Access: gs.AccessToken, Refresh: gs.RefreshToken, Next: next, Hasta: time.Now().Add(5 * time.Minute).Unix(), Recordar: recordar}
	b, _ := json.Marshal(p)
	sellado, err := s.ses.Sellar(string(b))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieMFA, Value: sellado, Path: "/factor", MaxAge: 300, HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
}

func (s *Server) leerPendienteMFA(r *http.Request) *pendienteMFA {
	c, err := r.Cookie(cookieMFA)
	if err != nil {
		return nil
	}
	txt, err := s.ses.Abrir(c.Value)
	if err != nil {
		return nil
	}
	var p pendienteMFA
	if json.Unmarshal([]byte(txt), &p) != nil || time.Now().Unix() > p.Hasta {
		return nil
	}
	return &p
}

func (s *Server) borrarPendienteMFA(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieMFA, Value: "", Path: "/factor", MaxAge: -1, HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
}

func (s *Server) factorGET(w http.ResponseWriter, r *http.Request) {
	p := s.leerPendienteMFA(r)
	if p == nil {
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	u, err := s.gt.Me(r.Context(), p.Access)
	if err != nil {
		s.borrarPendienteMFA(w)
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	var factorID string
	for _, f := range u.Factors {
		if f.Status == "verified" && f.FactorType == "totp" {
			factorID = f.ID
			break
		}
	}
	if factorID == "" {
		// Tiene factor verificado pero no TOTP (webauthn, aún sin pantalla aquí).
		s.borrarPendienteMFA(w)
		s.errorPagina(w, r, http.StatusNotImplemented, "Second factor", "Your account uses a security key, which this page cannot ask for yet. Ask an administrator to reset your factors.")
		return
	}
	ch, err := s.gt.ChallengeFactor(r.Context(), p.Access, factorID)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Second factor", mensajeGoTrue(err))
		return
	}
	s.render(w, r, "factor.html", "Second factor", map[string]any{"Next": p.Next, "FactorID": factorID, "ChallengeID": ch.ID}, http.StatusOK)
}

func (s *Server) factorPOST(w http.ResponseWriter, r *http.Request) {
	if s.frena(w, r, "factor", 10, 10) {
		return
	}
	p := s.leerPendienteMFA(r)
	if p == nil {
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	gs, err := s.gt.VerifyFactor(r.Context(), p.Access, r.PostFormValue("factor_id"), r.PostFormValue("challenge_id"), code)
	if err != nil {
		// Reto nuevo para el siguiente intento.
		ch, cerr := s.gt.ChallengeFactor(r.Context(), p.Access, r.PostFormValue("factor_id"))
		chID := ""
		if cerr == nil {
			chID = ch.ID
		}
		s.render(w, r, "factor.html", "Second factor", map[string]any{"Next": p.Next, "FactorID": r.PostFormValue("factor_id"), "ChallengeID": chID, "Error": mensajeGoTrue(err)}, http.StatusUnauthorized)
		return
	}
	s.borrarPendienteMFA(w)
	if _, err := s.ses.Crear(r.Context(), w, r, gs, "aal2", p.Recordar); err != nil {
		log.Printf("crear sesión aal2: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Sign in", "Could not start the session. Try again.")
		return
	}
	http.Redirect(w, r, s.nextSeguro(p.Next), http.StatusSeeOther)
}

// ── Registro ───────────────────────────────────────────────────────────────

func (s *Server) registroGET(w http.ResponseWriter, r *http.Request) {
	if sesionDe(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "registro.html", "Create an account", map[string]any{"Next": s.nextSeguro(r.URL.Query().Get("next"))}, http.StatusOK)
}

func (s *Server) registroPOST(w http.ResponseWriter, r *http.Request) {
	if s.frena(w, r, "registro", 5, 3) {
		return
	}
	next := s.nextSeguro(r.PostFormValue("next"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	email, okEmail := correoValido(r.PostFormValue("email"))
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	falla := func(msg string) {
		s.render(w, r, "registro.html", "Create an account", map[string]any{"Next": next, "Name": name, "Email": r.PostFormValue("email"), "Error": msg}, http.StatusBadRequest)
	}
	switch {
	case name == "" || len(name) > 80:
		falla("Tell us your name (up to 80 characters).")
		return
	case !okEmail:
		falla("That does not look like an email address.")
		return
	case len(p1) < 12:
		falla("Use a password of 12 characters or more.")
		return
	case p1 != p2:
		falla("The two passwords do not match.")
		return
	}
	// A dónde manda el enlace del correo tras confirmar: una ruta de aquí, o la
	// URL de la casa de la que vino (GoTrue exige que esté en su lista blanca).
	redirectTo := s.cfg.PublicURL.String() + next
	if strings.HasPrefix(next, "https://") {
		redirectTo = next
	}
	if _, err := s.gt.Signup(r.Context(), email, p1, name, redirectTo); err != nil {
		if errors.Is(err, gotrue.ErrWeakPassword) || errors.Is(err, gotrue.ErrSignupDisabled) {
			falla(mensajeGoTrue(err))
			return
		}
		// Cualquier otro error se tapa, INCLUIDO el 429: GoTrue lo devuelve al
		// repetir un correo que existe y está sin confirmar (no reenvía antes de
		// un minuto), y para un correo nuevo devuelve 200. Enseñar la diferencia
		// sería decir qué correos tienen cuenta. Se vio en la prueba del 09-09.
		log.Printf("signup: %v", err)
	}
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo}, http.StatusOK)
}

// ── Verificar (confirmación, invitación, cambio de correo, enlace mágico) ──

func (s *Server) verificar(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	typ, hash := q.Get("type"), q.Get("token_hash")
	switch typ {
	case "signup", "invite", "email_change", "magiclink", "email":
	default:
		s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This link is not one we sent.")
		return
	}
	if hash == "" {
		s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This link is incomplete.")
		return
	}
	if s.frena(w, r, "verificar", 10, 5) {
		return
	}
	gs, err := s.gt.VerifyTokenHash(r.Context(), typ, hash)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", mensajeGoTrue(err)+" You can sign in and ask for a new one, or create the account again.")
		return
	}
	// Una cuenta recién confirmada no tiene factores; si los tuviera (cambio de
	// correo de una cuenta con TOTP), pasa por el factor como al entrar.
	if gs.User.HasVerifiedFactor() {
		s.ponerPendienteMFA(w, gs, s.nextSeguro(q.Get("next")), false)
		http.Redirect(w, r, "/factor", http.StatusSeeOther)
		return
	}
	if _, err := s.ses.Crear(r.Context(), w, r, gs, "aal1", false); err != nil {
		log.Printf("crear sesión tras verificar: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Verified", "Your address is confirmed, but the session could not start. Sign in.")
		return
	}
	if typ == "invite" {
		// Quien llega por invitación no ha elegido contraseña: sin ésta no
		// podría volver a entrar. A Seguridad, que es donde se pone.
		s.ponerFlash(w, "Welcome. Choose a password below so you can sign in next time; your tools are already waiting under Your tools.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if typ == "signup" {
		s.ponerFlash(w, "Your address is confirmed. Welcome.")
	}
	http.Redirect(w, r, s.nextSeguro(q.Get("next")), http.StatusSeeOther)
}

// ── Recuperar contraseña ───────────────────────────────────────────────────

func (s *Server) recuperarGET(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "recuperar.html", "Reset your password", nil, http.StatusOK)
}

func (s *Server) recuperarPOST(w http.ResponseWriter, r *http.Request) {
	if s.frena(w, r, "recuperar", 5, 2) {
		return
	}
	email, ok := correoValido(r.PostFormValue("email"))
	if !ok {
		s.render(w, r, "recuperar.html", "Reset your password", map[string]any{"Error": "That does not look like an email address."}, http.StatusBadRequest)
		return
	}
	if err := s.gt.Recover(r.Context(), email, s.cfg.PublicURL.String()+"/restablecer"); err != nil {
		// Se tapa todo, también el 429: sólo lo devuelve para correos que
		// existen, así que enseñarlo sería enumerar. El freno por IP de arriba
		// ya limita el abuso.
		log.Printf("recover: %v", err)
	}
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo}, http.StatusOK)
}

func (s *Server) restablecerGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if hash := q.Get("token_hash"); hash != "" {
		if s.frena(w, r, "verificar", 10, 5) {
			return
		}
		gs, err := s.gt.VerifyTokenHash(r.Context(), "recovery", hash)
		if err != nil {
			s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", mensajeGoTrue(err))
			return
		}
		if gs.User.HasVerifiedFactor() {
			s.ponerPendienteMFA(w, gs, "/restablecer", false)
			http.Redirect(w, r, "/factor", http.StatusSeeOther)
			return
		}
		if _, err := s.ses.Crear(r.Context(), w, r, gs, "aal1", false); err != nil {
			s.errorPagina(w, r, http.StatusInternalServerError, "Reset", "Could not start the session. Try the link again.")
			return
		}
		http.Redirect(w, r, "/restablecer", http.StatusSeeOther)
		return
	}
	if s.requiereSesion(w, r) == nil {
		return
	}
	s.render(w, r, "restablecer.html", "Choose a new password", nil, http.StatusOK)
}

func (s *Server) restablecerPOST(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if len(p1) < 12 || p1 != p2 {
		s.render(w, r, "restablecer.html", "Choose a new password", map[string]any{"Error": "Use 12 characters or more, and type it twice the same."}, http.StatusBadRequest)
		return
	}
	if _, err := s.gt.UpdateUser(r.Context(), a.Token(), p1, "", ""); err != nil {
		s.render(w, r, "restablecer.html", "Choose a new password", map[string]any{"Error": mensajeGoTrue(err)}, http.StatusBadRequest)
		return
	}
	s.ponerFlash(w, "Your password is changed.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── Salir ──────────────────────────────────────────────────────────────────

func (s *Server) salir(w http.ResponseWriter, r *http.Request) {
	s.ses.Cerrar(r.Context(), w, sesionDe(r))
	s.borrarPendienteMFA(w)
	http.Redirect(w, r, s.nextSeguro(r.PostFormValue("next")), http.StatusSeeOther)
}

// salirGET es la página de confirmación: existe para que la web pública pueda
// enlazar «Sign out» con un simple enlace. Cerrar la sesión sigue siendo un
// POST con CSRF; un GET que cerrase sesiones sería un blanco fácil.
func (s *Server) salirGET(w http.ResponseWriter, r *http.Request) {
	if sesionDe(r) == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "salir.html", "Sign out", map[string]any{"Next": s.nextSeguro(r.URL.Query().Get("next"))}, http.StatusOK)
}

// enlaceEntrar construye /entrar?next= para una ruta.
func enlaceEntrar(next string) string { return "/entrar?next=" + url.QueryEscape(next) }
