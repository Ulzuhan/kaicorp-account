package httpapi

import (
	"context"
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
	datos, err := s.datosFactor(r.Context(), p)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Second factor", mensajeGoTrue(err))
		return
	}
	if datos == nil {
		s.borrarPendienteMFA(w)
		s.errorPagina(w, r, http.StatusNotImplemented, "Second factor", "Your account has a second factor of a kind this page cannot ask for. Ask an administrator to reset your factors.")
		return
	}
	s.render(w, r, "factor.html", "Second factor", datos, http.StatusOK)
}

// datosFactor prepara la página del segundo factor: un reto TOTP si hay
// autenticador, y un reto de entrada por cada passkey activa (cada una lleva su
// credencial en allowCredentials, así que un reto por factor). Devuelve nil sin
// error si la cuenta no tiene ningún factor que esta página sepa pedir.
func (s *Server) datosFactor(ctx context.Context, p *pendienteMFA) (map[string]any, error) {
	u, err := s.gt.Me(ctx, p.Access)
	if err != nil {
		return nil, err
	}
	datos := map[string]any{"Next": p.Next}
	var passkeys []*passkeyPendiente
	rpID, origins := s.rp()
	for _, f := range u.Factors {
		if f.Status != "verified" {
			continue
		}
		switch f.FactorType {
		case "totp":
			if _, ya := datos["FactorID"]; ya {
				continue
			}
			ch, err := s.gt.ChallengeFactor(ctx, p.Access, f.ID)
			if err != nil {
				return nil, err
			}
			datos["FactorID"], datos["ChallengeID"] = f.ID, ch.ID
		case "webauthn":
			ch, err := s.gt.ChallengeWebAuthn(ctx, p.Access, f.ID, "request", rpID, origins)
			if err != nil {
				return nil, err
			}
			passkeys = append(passkeys, &passkeyPendiente{FactorID: f.ID, ChallengeID: ch.ID, Options: string(ch.Options), Nombre: f.FriendlyName})
		}
	}
	if len(passkeys) > 0 {
		datos["Passkeys"] = passkeys
	}
	if _, ok := datos["FactorID"]; !ok && len(passkeys) == 0 {
		return nil, nil
	}
	return datos, nil
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
	var gs *gotrue.Session
	var err error
	if cred := strings.TrimSpace(r.PostFormValue("credential")); cred != "" {
		// Passkey: la credencial firmada que devolvió el navegador.
		if len(cred) > 32<<10 || !json.Valid([]byte(cred)) {
			err = errors.New("credencial inválida")
		} else {
			rpID, origins := s.rp()
			gs, err = s.gt.VerifyWebAuthn(r.Context(), p.Access, r.PostFormValue("factor_id"), r.PostFormValue("challenge_id"), "request", rpID, origins, json.RawMessage(cred))
		}
	} else {
		gs, err = s.gt.VerifyFactor(r.Context(), p.Access, r.PostFormValue("factor_id"), r.PostFormValue("challenge_id"), strings.TrimSpace(r.PostFormValue("code")))
	}
	if err != nil {
		// Retos nuevos para el siguiente intento: los usados ya no valen.
		datos, derr := s.datosFactor(r.Context(), p)
		if derr != nil || datos == nil {
			s.errorPagina(w, r, http.StatusBadGateway, "Second factor", "The second factor could not be checked. Sign in again.")
			return
		}
		datos["Error"] = "That did not work: " + mensajeGoTrue(err) + " Try again."
		s.render(w, r, "factor.html", "Second factor", datos, http.StatusUnauthorized)
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
		// Ya tiene cuenta y sesión: a donde iba (la web, el consentimiento), no a la portada.
		http.Redirect(w, r, s.nextSeguro(r.URL.Query().Get("next")), http.StatusSeeOther)
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
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
}

// ── Reenviar la confirmación ───────────────────────────────────────────────
// Quien se registró y no encuentra el correo no tiene por qué registrarse otra
// vez (GoTrue respondería 429 y la app lo taparía). GoTrue contesta igual
// exista o no la cuenta, y esta app también: «check your inbox».

func (s *Server) reenviarGET(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "reenviar.html", "Send the confirmation again", map[string]any{"Email": r.URL.Query().Get("email")}, http.StatusOK)
}

func (s *Server) reenviarPOST(w http.ResponseWriter, r *http.Request) {
	if s.frena(w, r, "reenviar", 3, 1) {
		return
	}
	email, ok := correoValido(r.PostFormValue("email"))
	if !ok {
		s.render(w, r, "reenviar.html", "Send the confirmation again", map[string]any{"Error": "That does not look like an email address."}, http.StatusBadRequest)
		return
	}
	if err := s.gt.Resend(r.Context(), "signup", email); err != nil {
		log.Printf("reenviar confirmación: %v", err) // se tapa: decirlo delataría cuentas
	}
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
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
	if gs.Parcial() {
		// Cambio de correo seguro: GoTrue ha aceptado uno de los dos enlaces y
		// espera el otro. No hay sesión que abrir ni nada que cambiar todavía.
		s.render(w, r, "correo.html", "One confirmed, one to go", map[string]any{"Mensaje": "This link is accepted. The change happens when you also open the link we sent to your other address: the old one if this was the new, the new one if this was the old."}, http.StatusOK)
		return
	}
	if typ == "email_change" {
		// Las dos confirmaciones hechas: el correo ya es el nuevo en GoTrue. Las
		// sesiones de esta app guardan el correo de cuando nacieron; se ponen al día.
		if err := s.st.ActualizarCorreoSesiones(r.Context(), gs.User.ID, gs.User.Email); err != nil {
			log.Printf("actualizar correo en sesiones de %s: %v", gs.User.ID, err)
		}
		s.ponerFlash(w, "Your email is now "+gs.User.Email+". Use it to sign in from now on.")
		q.Set("next", "/cuenta")
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
	next := s.nextSeguro(q.Get("next"))
	if typ == "signup" {
		s.ponerFlash(w, "Your address is confirmed. Welcome. Ask for the tools you need below; a person reads the first request.")
		// Quien se registró desde la web pública vuelve aquí, a sus herramientas,
		// no a la página de la web: acaba de nacer sin ninguna y el siguiente
		// paso es pedir una. Si venía de una herramienta (next interno hacia el
		// consentimiento), sigue su camino.
		if strings.HasPrefix(next, "https://") {
			next = "/"
		}
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
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
		// Sin sesión no hay nada que cerrar: de vuelta a donde estaba (la web),
		// no a la portada de la cuenta.
		http.Redirect(w, r, s.nextSeguro(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.render(w, r, "salir.html", "Sign out", map[string]any{"Next": s.nextSeguro(r.URL.Query().Get("next"))}, http.StatusOK)
}

// enlaceEntrar construye /entrar?next= para una ruta.
func enlaceEntrar(next string) string { return "/entrar?next=" + url.QueryEscape(next) }
