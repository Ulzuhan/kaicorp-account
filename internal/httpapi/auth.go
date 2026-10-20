package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

// mensajeRevisaCorreo es el mismo texto para «nuevo», «ya existía» y «no
// existe»: quien mira el formulario no puede averiguar qué correos tienen cuenta.
const mensajeRevisaCorreo = "If that address can receive email, a message is on its way. Open the link in it to continue."

const rutaPasswordRegistro = "/registro/password"

// passwordPendienteDesconocida crea la credencial que GoTrue exige al dar de
// alta la identidad pendiente. Nadie la elige ni la recibe: sólo existe para
// que no haya una contraseña reutilizable antes de demostrar el buzón.
func passwordPendienteDesconocida() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// El prefijo satisface las clases habituales de GoTrue y los 192 bits
	// aleatorios mantienen la credencial fuera del alcance de quien registra.
	return "Aa1!" + hex.EncodeToString(b), nil
}

// rotarPasswordPendiente instala una credencial desconocida al aceptar una
// invitación. La escritura administrativa no depende de la política opcional
// que exige la contraseña actual y cierra todas las sesiones del proveedor;
// por eso se entra inmediatamente con el secreto nuevo antes de seguir.
func (s *Server) bloquearRotacionNoProbada(_ context.Context, userID string, causa error) error {
	if userID == "" {
		return fmt.Errorf("rotación no probada sin identidad que bloquear: %w", causa)
	}
	ctxSeguridad, cancelar := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelar()
	errBloqueo := s.gt.AdminBanUser(ctxSeguridad, userID, "876000h")
	if errBloqueo != nil {
		errBloqueo = fmt.Errorf("bloquear tras rotación no probada: %w", errBloqueo)
	}
	var errSesiones error
	if s.st != nil {
		errSesiones = s.st.RevocarSesiones(ctxSeguridad, userID)
		if errSesiones != nil {
			errSesiones = fmt.Errorf("revocar sesiones tras rotación no probada: %w", errSesiones)
		}
	}
	if errBloqueo == nil && errSesiones == nil {
		return fmt.Errorf("rotación no probada; cuenta bloqueada y sesiones revocadas: %w", causa)
	}
	return errors.Join(causa, errBloqueo, errSesiones)
}

func (s *Server) cambiarPasswordAdministrativa(ctx context.Context, userID, password string) (*gotrue.User, int64, error) {
	var usuario *gotrue.User
	cambiar := func() error {
		var err error
		usuario, err = s.gt.AdminUpdatePassword(ctx, userID, password)
		return err
	}
	var generacion int64
	var err error
	if s.st == nil { // Sólo los servidores unitarios sin base llegan aquí.
		err = cambiar()
	} else {
		generacion, err = s.st.CambiarCredencialAdministrativa(ctx, userID, cambiar)
	}
	if usuario != nil || err != nil {
		s.invalidarCapacidadesPassword(userID)
	}
	if err == nil && (usuario == nil || usuario.ID == "" || usuario.ID != userID) {
		err = errors.New("la rotación devolvió otra identidad")
	}
	if err != nil {
		return usuario, generacion, s.bloquearRotacionNoProbada(ctx, userID, err)
	}
	return usuario, generacion, nil
}

func (s *Server) rotarPasswordPendiente(ctx context.Context, gs *gotrue.Session) (string, int64, error) {
	if gs == nil || gs.User.ID == "" || gs.User.Email == "" {
		return "", 0, errors.New("sesión pendiente incompleta")
	}
	p, err := passwordPendienteDesconocida()
	if err != nil {
		return "", 0, s.bloquearRotacionNoProbada(ctx, gs.User.ID, err)
	}
	_, generacion, err := s.cambiarPasswordAdministrativa(ctx, gs.User.ID, p)
	if err != nil {
		return "", 0, err
	}
	// `p` acaba de generarlo el servidor y nunca estuvo bajo control de quien
	// llama. Esta comprobación de la rotación no es un intento humano y no puede
	// usarse para adivinar contraseñas, por eso no consume su presupuesto.
	nueva, err := s.gt.Login(ctx, gs.User.Email, p)
	if err != nil {
		return "", 0, s.bloquearRotacionNoProbada(ctx, gs.User.ID, err)
	}
	if nueva == nil || nueva.User.ID == "" || nueva.User.ID != gs.User.ID {
		return "", 0, s.bloquearRotacionNoProbada(ctx, gs.User.ID, errors.New("la sesión rotada devolvió otra identidad"))
	}
	*gs = *nueva
	return p, generacion, nil
}

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

// prepararPendienteExistente sustituye una contraseña de alta antigua antes
// de que GoTrue emita otro correo. El lookup nunca cambia la respuesta pública:
// sólo evita que un re-registro o reenvío confirme una credencial elegida por
// quien prerregistró el buzón con una versión anterior.
func (s *Server) prepararPendienteExistente(ctx context.Context, email, password string) (bool, error) {
	if s.st == nil { // Sólo los servidores unitarios sin base llegan aquí.
		return true, nil
	}
	u, err := s.st.UsuarioPorCorreo(ctx, email)
	if errors.Is(err, store.ErrNoExiste) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if u.Confirmada {
		return true, nil
	}
	// confirmation_token es compartido por signup e invite, mientras
	// invited_at es histórico. Emitir signup sobre una invitación pendiente
	// haría indistinguible el propósito actual antes de /verify. La invitación
	// conserva su enlace y sólo un reenvío administrativo puede rotarlo.
	if u.Invitada != nil {
		return false, nil
	}
	_, _, err = s.cambiarPasswordAdministrativa(ctx, u.ID, password)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) redireccionRegistro(intent, next string) string {
	u := *s.cfg.PublicURL
	u.Path = "/verificar"
	u.RawQuery = url.Values{"setup": {intent}, "next": {s.nextSeguro(next)}}.Encode()
	u.Fragment = ""
	return u.String()
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
	gs, err, respondido := s.verificarPassword(w, r, email, password, "")
	if respondido {
		return
	}
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
		s.ponerPendienteMFA(w, gs, next, recordar, "")
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

const (
	cookieMFA            = "__Host-account_mfa"
	cookieMFADevelopment = "account_mfa"
)

type pendienteMFA struct {
	Access    string            `json:"a"`
	Refresh   string            `json:"r"`
	Next      string            `json:"n"`
	Hasta     int64             `json:"h"`
	Recordar  bool              `json:"k,omitempty"`
	Proposito propositoPassword `json:"p,omitempty"`
	UserID    string            `json:"u"`
	Email     string            `json:"e"`
	Nombre    string            `json:"m,omitempty"`
	// Emitido liga el sobre a la credencial anterior al factor. La verificación
	// no puede sustituirlo por el iat más reciente de la respuesta aal2.
	Emitido          int64 `json:"i,omitempty"`
	Generacion       int64 `json:"g,omitempty"`
	GeneracionLigada bool  `json:"l,omitempty"`
	// PasswordActual viaja cifrada sólo durante el alta y durante cinco
	// minutos, igual que los tokens del proveedor de este mismo sobre.
	PasswordActual string `json:"w,omitempty"`
}

func (s *Server) ponerPendienteMFA(w http.ResponseWriter, gs *gotrue.Session, next string, recordar bool, proposito propositoPassword) {
	s.ponerPendienteMFAConPassword(w, gs, next, recordar, proposito, "")
}

func (s *Server) ponerPendienteMFAConPassword(w http.ResponseWriter, gs *gotrue.Session, next string, recordar bool, proposito propositoPassword, passwordActual string) {
	s.ponerPendienteMFAConAutoridad(w, gs, next, recordar, proposito, passwordActual, session.EmitidoDe(gs.AccessToken), 0, false)
}

func (s *Server) ponerPendienteMFAConAutoridad(w http.ResponseWriter, gs *gotrue.Session, next string, recordar bool, proposito propositoPassword, passwordActual string, emitido, generacion int64, ligada bool) {
	p := pendienteMFA{Access: gs.AccessToken, Refresh: gs.RefreshToken, Next: next, Hasta: time.Now().Add(5 * time.Minute).Unix(), Recordar: recordar,
		Proposito: proposito, UserID: gs.User.ID, Email: gs.User.Email, Nombre: gs.User.Name(), Emitido: emitido,
		Generacion: generacion, GeneracionLigada: ligada, PasswordActual: passwordActual}
	b, _ := json.Marshal(p)
	sellado, err := s.ses.Sellar(string(b))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.nombreCookieMFA(), Value: sellado, Path: "/", MaxAge: 300,
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	if s.ses.Secure() {
		s.expirarCookieMFALegada(w)
	}
}

func (s *Server) leerPendienteMFA(r *http.Request) *pendienteMFA {
	cookies := r.CookiesNamed(s.nombreCookieMFA())
	if len(cookies) != 1 {
		return nil
	}
	c := cookies[0]
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
	http.SetCookie(w, &http.Cookie{Name: s.nombreCookieMFA(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	if s.ses.Secure() {
		s.expirarCookieMFALegada(w)
	}
}

func (s *Server) nombreCookieMFA() string {
	if s.ses.Secure() {
		return cookieMFA
	}
	return cookieMFADevelopment
}

func (s *Server) expirarCookieMFALegada(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieMFADevelopment, Value: "", Path: "/factor", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) factorGET(w http.ResponseWriter, r *http.Request) {
	p := s.leerPendienteMFA(r)
	if p == nil {
		s.borrarPendienteMFA(w)
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
		s.borrarPendienteMFA(w)
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	if s.st != nil {
		if err := s.st.ComprobarCredencial(r.Context(), p.UserID, p.Emitido, generacionEsperada(p.Generacion, p.GeneracionLigada)); err != nil {
			s.borrarPendienteMFA(w)
			if errors.Is(err, store.ErrCredencialAnterior) {
				s.errorPagina(w, r, http.StatusUnauthorized, "Second factor", "This sign-in or recovery began before the latest password change. Start again.")
			} else {
				log.Printf("comprobar credencial MFA: %v", err)
				s.errorPagina(w, r, http.StatusInternalServerError, "Second factor", "The credential could not be checked. Start again.")
			}
			return
		}
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
	if gs.User.ID == "" {
		gs.User.ID, gs.User.Email = p.UserID, p.Email
		if p.Nombre != "" {
			gs.User.UserMetadata = map[string]any{"name": p.Nombre}
		}
	}
	if gs.User.ID == "" || gs.User.ID != p.UserID {
		s.errorPagina(w, r, http.StatusBadGateway, "Second factor", "The verified identity did not match. Start again.")
		return
	}
	if p.Proposito == propositoRecuperacion {
		if err := s.emitirCapacidadPasswordEnAutoridad(w, gs, "aal2", propositoRecuperacion, p.Emitido, p.Generacion, p.GeneracionLigada); err != nil {
			log.Printf("crear capacidad de recuperación: %v", err)
			s.errorPagina(w, r, http.StatusInternalServerError, "Reset", "Could not finish the recovery. Ask for a new link.")
			return
		}
		http.Redirect(w, r, "/restablecer", http.StatusSeeOther)
		return
	}
	if p.Proposito == propositoRegistro || p.Proposito == propositoInvitacion {
		var err error
		if p.Proposito == propositoInvitacion {
			err = s.emitirCapacidadInvitacionEnAutoridad(w, gs, "aal2", p.Next, p.PasswordActual, p.Emitido, p.Generacion, p.GeneracionLigada)
		} else {
			err = s.emitirCapacidadRegistroEnAutoridad(w, gs, "aal2", p.Next, p.PasswordActual, p.Emitido, p.Generacion, p.GeneracionLigada)
		}
		if err != nil {
			_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
			log.Printf("crear capacidad de alta tras MFA: %v", err)
			s.errorPagina(w, r, http.StatusInternalServerError, "Create account", "Your address is confirmed, but password setup could not start. Reset the password from the sign-in page.")
			return
		}
		http.Redirect(w, r, rutaPasswordRegistro, http.StatusSeeOther)
		return
	}
	if _, err := s.ses.CrearEnEmision(r.Context(), w, r, gs, "aal2", p.Recordar, p.Emitido); err != nil {
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
	}
	password, err := passwordPendienteDesconocida()
	if err != nil {
		log.Printf("crear contraseña pendiente: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Create account", "The account could not be prepared. Try again.")
		return
	}
	intent, err := s.emitirIntencionRegistro(email, password)
	if err != nil {
		log.Printf("crear intención de registro: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Create account", "The account could not be prepared. Try again.")
		return
	}
	preparada, err := s.prepararPendienteExistente(r.Context(), email, password)
	if err != nil {
		// No se pide un correo nuevo si no se pudo invalidar primero una
		// credencial pendiente antigua. Hacia fuera sigue siendo indistinguible.
		log.Printf("preparar registro pendiente: %v", err)
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	if !preparada {
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	redirectTo := s.redireccionRegistro(intent, next)
	if _, err := s.gt.Signup(r.Context(), email, password, name, redirectTo); err != nil {
		// Cualquier error se tapa, INCLUIDOS weak_password, signup_disabled y el
		// 429: el orden de validación de GoTrue puede variar, así que exponer uno
		// de ellos permitiría distinguirlo de la respuesta falsa para una cuenta
		// existente. El freno por IP de arriba sigue limitando el abuso.
		// GoTrue devuelve 429 al
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
	password, err := passwordPendienteDesconocida()
	if err != nil {
		log.Printf("crear contraseña para reenvío: %v", err)
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	intent, err := s.emitirIntencionRegistro(email, password)
	if err != nil {
		log.Printf("crear intención para reenvío: %v", err)
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	preparada, err := s.prepararPendienteExistente(r.Context(), email, password)
	if err != nil {
		log.Printf("preparar reenvío pendiente: %v", err)
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	if !preparada {
		s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
		return
	}
	if err := s.gt.Resend(r.Context(), "signup", email, s.redireccionRegistro(intent, "/")); err != nil {
		log.Printf("reenviar confirmación: %v", err) // se tapa: decirlo delataría cuentas
	}
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo, "Email": email}, http.StatusOK)
}

// ── Verificar (confirmación, invitación, cambio de correo, enlace mágico) ──

func (s *Server) verificar(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	typ := q.Get("type")
	if !tipoEnlaceValido(typ, false) {
		s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This link is not one we sent.")
		return
	}
	setupIntent := q.Get("setup")
	if typ == "signup" && !s.intencionRegistroDisponible(setupIntent) {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This confirmation predates secure password setup. Create the account again to receive a new link.")
		return
	}
	inviteIntent := q.Get("invite")
	if typ == "invite" && !s.intencionInvitacionDisponible(inviteIntent) {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This invitation is missing its secure purpose proof. Ask an administrator to resend it.")
		return
	}
	s.confirmarEnlace(w, r, typ, q.Get("next"), "", setupIntent, inviteIntent)
}

func tipoEnlaceValido(typ string, incluirRecuperacion bool) bool {
	switch typ {
	case "signup", "invite", "email_change":
		return true
	case "recovery":
		return incluirRecuperacion
	default:
		return false
	}
}

func vidaEnlaceCorreo(typ string) time.Duration {
	switch typ {
	case "recovery":
		return vidaIntencionRecuperacion
	case "signup":
		return vidaIntencionRegistro
	case "invite":
		return vidaIntencionInvitacion
	case "email_change":
		return 24 * time.Hour
	default:
		return 0
	}
}

// confirmarEnlace presenta sólo metadatos no canjeables. El navegador copia la
// capacidad desde el fragmento al formulario y borra el fragmento de su entrada
// de historial; el servidor no puede ni debe recibirla durante este GET.
func (s *Server) confirmarEnlace(w http.ResponseWriter, r *http.Request, typ, next, recoveryIntent, setupIntent, inviteIntent string) {
	if typ == "recovery" {
		next = "/restablecer"
	} else {
		next = s.nextSeguro(next)
	}
	s.render(w, r, "enlace.html", "Confirm this email link", map[string]any{
		"Tipo":           typ,
		"Next":           next,
		"CambioCorreo":   typ == "email_change",
		"Recuperacion":   typ == "recovery",
		"RecoveryIntent": recoveryIntent,
		"SetupIntent":    setupIntent,
		"InviteIntent":   inviteIntent,
	}, http.StatusOK)
}

func (s *Server) verificarPOST(w http.ResponseWriter, r *http.Request) {
	typ, tipoUnico := campoPostUnico(r, "type")
	if !tipoUnico || !tipoEnlaceValido(typ, true) {
		s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This link is not one we sent.")
		return
	}
	hash, ok := campoPostUnico(r, "token_hash")
	if !ok {
		s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This link is incomplete.")
		return
	}
	emailCampo, emailUnico := campoPostUnico(r, "email")
	email, ok := correoValido(emailCampo)
	if !emailUnico || !ok {
		s.errorPagina(w, r, http.StatusBadRequest, "Check the address", "Type the email address this link was sent to.")
		return
	}
	if s.frena(w, r, "verificar", 10, 5) {
		return
	}
	var passwordRegistro string
	var recuperacion *intencionRecuperacion
	var recuperacionMFA *intencionRecuperacionMFA
	if typ == "signup" {
		intent, unico := campoPostUnico(r, "setup_intent")
		var valida bool
		passwordRegistro, valida = s.validarIntencionRegistro(intent, email)
		if !unico || !valida {
			s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This confirmation was not prepared for secure password setup, has expired, or belongs to another address. Create the account again.")
			return
		}
	}
	if typ == "invite" {
		intent, unico := campoPostUnico(r, "invite_intent")
		if !unico || !s.validarIntencionInvitacion(intent, email) {
			s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This invitation was not prepared for this address, has expired, or belongs to another purpose. Ask an administrator to resend it.")
			return
		}
	}
	if typ == "recovery" {
		intent, unico := campoPostUnico(r, "recovery_intent")
		var valida, validaMFA bool
		recuperacionMFA, validaMFA = s.leerIntencionRecuperacionMFA(r, intent)
		if validaMFA {
			valida = strings.EqualFold(recuperacionMFA.Email, email)
		} else {
			recuperacion, valida = s.intencionRecuperacionValidada(intent, email)
		}
		if !unico || !valida {
			s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This recovery link was not requested here, has expired, or was already used. Ask for a new one.")
			return
		}
		if recuperacion != nil && recuperacion.GeneracionLigada {
			if s.st == nil {
				s.errorPagina(w, r, http.StatusInternalServerError, "The link does not work", "The recovery credential could not be checked. Ask for a new link.")
				return
			}
			if err := s.st.ComprobarCredencial(r.Context(), recuperacion.UserID, 0, generacionEsperada(recuperacion.Generacion, true)); err != nil {
				if !errors.Is(err, store.ErrCredencialAnterior) {
					log.Printf("comprobar generación de recuperación: %v", err)
					s.errorPagina(w, r, http.StatusInternalServerError, "The link does not work", "The recovery credential could not be checked. Ask for a new link.")
					return
				}
				s.errorPagina(w, r, http.StatusUnauthorized, "The link does not work", "This recovery began before the latest password change. Ask for a new link.")
				return
			}
		}
	}

	// El hash de un uso se liga aquí, todavía sin consumir, con el propósito,
	// buzón y usuario que GoTrue guardó al emitirlo. Los sobres de signup y
	// recovery siguen añadiendo sus invariantes propias; no sustituyen esta
	// comprobación en producción.
	var enlace *store.EnlaceCorreoPendiente
	var err error
	if s.resolverEnlaceCorreo != nil {
		enlace, err = s.resolverEnlaceCorreo(r.Context(), typ, hash)
		if errors.Is(err, store.ErrNoExiste) {
			s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This email link is no longer pending. Ask for a new one.")
			return
		}
		if err != nil {
			log.Printf("resolver vínculo previo de enlace %s: %v", typ, err)
			s.errorPagina(w, r, http.StatusInternalServerError, "The link does not work", "The email link could not be checked. Ask for a new one.")
			return
		}
	} else {
		// Sólo los servidores unitarios sin Store llegan aquí. Signup y recovery
		// ya traen un sobre sellado; invite y email_change fallan cerrados si una
		// prueba no instala explícitamente el estado pendiente del proveedor.
		enlace = &store.EnlaceCorreoPendiente{Destinatario: email, EmailFinal: email, Hasta: time.Now().Add(vidaEnlaceCorreo(typ))}
		switch {
		case typ == "signup":
		case typ == "recovery" && recuperacionMFA != nil:
			enlace.UserID = recuperacionMFA.UserID
		case typ == "recovery" && recuperacion != nil:
			enlace.UserID = recuperacion.UserID
		default:
			s.errorPagina(w, r, http.StatusInternalServerError, "The link does not work", "The email link could not be checked. Ask for a new one.")
			return
		}
	}
	defer enlace.Cerrar()
	destinatario, destinatarioOK := correoValido(enlace.Destinatario)
	emailFinal, finalOK := correoValido(enlace.EmailFinal)
	if (enlace.UserID == "" && s.resolverEnlaceCorreo != nil) || !destinatarioOK || !finalOK || enlace.Hasta.IsZero() {
		log.Printf("vínculo pendiente incompleto para enlace %s", typ)
		s.errorPagina(w, r, http.StatusInternalServerError, "The link does not work", "The email link could not be checked. Ask for a new one.")
		return
	}
	if !time.Now().Before(enlace.Hasta) {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This email link has expired. Ask for a new one.")
		return
	}
	if destinatario != email {
		s.errorPagina(w, r, http.StatusBadRequest, "The address does not match", "The address you entered does not match this link. The link was not used; check the address and try again.")
		return
	}
	if (recuperacion != nil && recuperacion.GeneracionLigada && enlace.UserID != recuperacion.UserID) ||
		(recuperacionMFA != nil && enlace.UserID != recuperacionMFA.UserID) {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not match", "This link belongs to a different recovery request. Ask for a new one.")
		return
	}
	gs, err := s.gt.VerifyTokenHash(r.Context(), typ, hash)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", mensajeGoTrue(err)+" You can sign in and ask for a new one, or create the account again.")
		return
	}
	if gs.Parcial() {
		if typ != "email_change" {
			s.errorPagina(w, r, http.StatusBadGateway, "The link does not work", "The identity service returned an incomplete response. Ask for a new email.")
			return
		}
		// Cambio de correo seguro: GoTrue ha aceptado uno de los dos enlaces y
		// espera el otro. No hay sesión que abrir ni nada que cambiar todavía.
		s.render(w, r, "correo.html", "One confirmed, one to go", map[string]any{"Mensaje": "This link is accepted. The change happens when you also open the link we sent to your other address: the old one if this was the new, the new one if this was the old."}, http.StatusOK)
		return
	}
	proveedorEmail, ok := correoValido(gs.User.Email)
	if !ok || proveedorEmail != emailFinal || (enlace.UserID != "" && gs.User.ID != enlace.UserID) {
		if typ == "invite" {
			// GoTrue ya consumió el enlace y confirmó la cuenta. Aunque la
			// persona se equivocara al escribir el correo, la invitación queda
			// cerrada con una credencial que nadie conoce.
			var remedio error
			if ok {
				_, _, remedio = s.rotarPasswordPendiente(r.Context(), gs)
			} else {
				remedio = s.bloquearRotacionNoProbada(r.Context(), gs.User.ID, errors.New("correo inválido tras confirmar"))
			}
			if remedio != nil {
				log.Printf("cerrar alta confirmada con correo distinto: %v", remedio)
			}
		}
		if gs.AccessToken != "" {
			if err := s.gt.Logout(r.Context(), gs.AccessToken, "local"); err != nil {
				log.Printf("cerrar sesión de enlace con correo distinto: %v", err)
			}
		}
		s.errorPagina(w, r, http.StatusBadRequest, "The address does not match", "The identity returned by this link does not match its pending record. No account access was created; request a new email and try again.")
		return
	}
	if typ == "recovery" {
		if recuperacionMFA != nil {
			if gs.User.ID != recuperacionMFA.UserID {
				_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
				s.errorPagina(w, r, http.StatusBadRequest, "The address does not match", "The account in this link does not match the MFA recovery request. Start the change again.")
				return
			}
			anterior, err := s.completarRecuperacionMFA(r.Context(), recuperacionMFA, gs)
			if err != nil {
				_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
				log.Printf("confirmar recuperación MFA: %v", err)
				s.errorPagina(w, r, http.StatusBadRequest, "The link does not work", "This MFA recovery proof no longer matches the pending change. Start the change again.")
				return
			}
			if anterior != "" && anterior != gs.AccessToken {
				_ = s.gt.Logout(r.Context(), anterior, "local")
			}
			s.ponerFlash(w, "Mailbox recovery accepted. You may now remove the final factor.")
			http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
			return
		}
		if recuperacion.GeneracionLigada && gs.User.ID != recuperacion.UserID {
			_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
			s.errorPagina(w, r, http.StatusBadRequest, "The address does not match", "The account in this link does not match the recovery request. Ask for a new link.")
			return
		}
		if gs.User.HasVerifiedFactor() {
			s.ponerPendienteMFAConAutoridad(w, gs, "/restablecer", false, propositoRecuperacion, "", emitidoSesion(gs), recuperacion.Generacion, recuperacion.GeneracionLigada)
			http.Redirect(w, r, "/factor", http.StatusSeeOther)
			return
		}
		if err := s.emitirCapacidadPasswordEnAutoridad(w, gs, "aal1", propositoRecuperacion, emitidoSesion(gs), recuperacion.Generacion, recuperacion.GeneracionLigada); err != nil {
			log.Printf("crear capacidad de recuperación: %v", err)
			s.errorPagina(w, r, http.StatusInternalServerError, "Reset", "Could not prepare the reset. Ask for a new link and try again.")
			return
		}
		http.Redirect(w, r, "/restablecer", http.StatusSeeOther)
		return
	}
	next := s.nextSeguro(r.PostFormValue("next"))
	if typ == "signup" || typ == "invite" {
		// El alta pública trae la credencial aleatoria en su sobre sellado; la
		// invitación la instala ahora. En ambos casos sólo se entrega autoridad
		// acotada para elegir la contraseña final.
		if typ == "invite" {
			next = "/cuenta"
		} else if strings.HasPrefix(next, "https://") {
			next = "/"
		}
		passwordActual := passwordRegistro
		propositoAlta := propositoRegistro
		var generacion int64
		generacionLigada := false
		if typ == "invite" {
			propositoAlta = propositoInvitacion
			var err error
			passwordActual, generacion, err = s.rotarPasswordPendiente(r.Context(), gs)
			if err != nil {
				if gs.AccessToken != "" {
					_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
				}
				log.Printf("rotar contraseña pendiente: %v", err)
				s.errorPagina(w, r, http.StatusBadGateway, "Create account", "Your address is confirmed, but password setup could not start. Reset the password from the sign-in page.")
				return
			}
			generacionLigada = s.st != nil
		}
		if gs.User.HasVerifiedFactor() {
			s.ponerPendienteMFAConAutoridad(w, gs, next, false, propositoAlta, passwordActual, emitidoSesion(gs), generacion, generacionLigada)
			http.Redirect(w, r, "/factor", http.StatusSeeOther)
			return
		}
		if propositoAlta == propositoInvitacion {
			err = s.emitirCapacidadInvitacionEnAutoridad(w, gs, "aal1", next, passwordActual, emitidoSesion(gs), generacion, generacionLigada)
		} else {
			err = s.emitirCapacidadRegistroEnAutoridad(w, gs, "aal1", next, passwordActual, emitidoSesion(gs), generacion, generacionLigada)
		}
		if err != nil {
			_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
			log.Printf("crear capacidad de alta: %v", err)
			s.errorPagina(w, r, http.StatusInternalServerError, "Create account", "Your address is confirmed, but password setup could not start. Reset the password from the sign-in page.")
			return
		}
		http.Redirect(w, r, rutaPasswordRegistro, http.StatusSeeOther)
		return
	}
	if typ == "email_change" {
		// Las dos confirmaciones hechas: el correo ya es el nuevo en GoTrue. Las
		// sesiones de esta app guardan el correo de cuando nacieron; se ponen al día.
		if err := s.st.ActualizarCorreoSesiones(r.Context(), gs.User.ID, gs.User.Email); err != nil {
			log.Printf("actualizar correo en sesiones de %s: %v", gs.User.ID, err)
		}
		s.ponerFlash(w, "Your email is now "+gs.User.Email+". Use it to sign in from now on.")
		next = "/cuenta"
	}
	// Una cuenta recién confirmada no tiene factores; si los tuviera (cambio de
	// correo de una cuenta con TOTP), pasa por el factor como al entrar.
	if gs.User.HasVerifiedFactor() {
		s.ponerPendienteMFA(w, gs, next, false, "")
		http.Redirect(w, r, "/factor", http.StatusSeeOther)
		return
	}
	if _, err := s.ses.Crear(r.Context(), w, r, gs, "aal1", false); err != nil {
		log.Printf("crear sesión tras verificar: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Verified", "Your address is confirmed, but the session could not start. Sign in.")
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ── Contraseña final del registro ─────────────────────────────────────────

func (s *Server) propositoCapacidadAlta(r *http.Request) (propositoPassword, bool) {
	var encontrado propositoPassword
	for _, candidato := range []propositoPassword{propositoRegistro, propositoInvitacion} {
		nombre, _ := s.datosCookiePassword(candidato)
		cookies := r.CookiesNamed(nombre)
		if len(cookies) == 0 {
			continue
		}
		if len(cookies) != 1 || encontrado != "" || !s.capacidadPasswordDisponible(r, candidato, "") {
			return "", false
		}
		encontrado = candidato
	}
	return encontrado, encontrado != ""
}

func (s *Server) registroPasswordGET(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.propositoCapacidadAlta(r); !ok {
		http.Redirect(w, r, "/recuperar", http.StatusSeeOther)
		return
	}
	s.render(w, r, "registro-password.html", "Choose your password", nil, http.StatusOK)
}

func (s *Server) registroPasswordPOST(w http.ResponseWriter, r *http.Request) {
	proposito, ok := s.propositoCapacidadAlta(r)
	if !ok {
		http.Redirect(w, r, "/recuperar", http.StatusSeeOther)
		return
	}
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if len(p1) < 12 || p1 != p2 {
		s.render(w, r, "registro-password.html", "Choose your password", map[string]any{"Error": "Use 12 characters or more, and type it twice the same."}, http.StatusBadRequest)
		return
	}
	id, capacidad, ok := s.reclamarCapacidadPassword(r, proposito, "")
	if !ok {
		http.Redirect(w, r, "/recuperar", http.StatusSeeOther)
		return
	}
	u, generacion, err := s.cambiarPassword(r.Context(), capacidad.proveedor.User.ID, capacidad.emitido,
		generacionEsperada(capacidad.generacion, capacidad.generacionLigada),
		capacidad.proveedor.AccessToken, p1, capacidad.passwordActual, "")
	if err != nil {
		if falloPasswordReintentable(err) {
			s.liberarCapacidadPassword(capacidad)
		} else {
			s.descartarCapacidadPassword(w, id, capacidad)
		}
		s.render(w, r, "registro-password.html", "Choose your password", map[string]any{"Error": mensajeGoTrue(err)}, http.StatusBadRequest)
		return
	}
	if u == nil || u.ID == "" || u.ID != capacidad.proveedor.User.ID {
		s.descartarCapacidadPassword(w, id, capacidad)
		_ = s.gt.Logout(r.Context(), capacidad.proveedor.AccessToken, "local")
		s.errorPagina(w, r, http.StatusBadGateway, "Create account", "The password changed, but the confirmed identity did not match. Sign in with the new password.")
		return
	}
	capacidad.proveedor.User = *u
	if proposito == propositoInvitacion {
		// No promover a sesión normal el bearer que autorizó el paso previo.
		// GoTrue rota también el refresh token y conserva el nivel MFA de esta
		// misma sesión de proveedor.
		anterior := capacidad.proveedor.AccessToken
		rotada, err := s.gt.Refresh(r.Context(), capacidad.proveedor.RefreshToken)
		if err != nil || rotada == nil || rotada.AccessToken == "" || rotada.AccessToken == anterior || rotada.RefreshToken == "" || rotada.User.ID != u.ID {
			s.descartarCapacidadPassword(w, id, capacidad)
			_ = s.gt.Logout(r.Context(), anterior, "local")
			s.errorPagina(w, r, http.StatusBadGateway, "Create account", "The password was saved, but the session bearer could not be rotated. Sign in with the new password.")
			return
		}
		capacidad.proveedor = *rotada
	}
	// La capacidad conserva la sesión interna de GoTrue que ya superó el
	// enlace y, si procedía, MFA. Cierra primero el resto de sesiones del
	// proveedor: todavía no existe ningún portador normal de la aplicación
	// que pueda sobrevivir a un fallo de esa limpieza.
	if err := s.gt.Logout(r.Context(), capacidad.proveedor.AccessToken, "others"); err != nil {
		s.descartarCapacidadPassword(w, id, capacidad)
		_ = s.gt.Logout(r.Context(), capacidad.proveedor.AccessToken, "local")
		s.errorPagina(w, r, http.StatusBadGateway, "Create account", "The password was saved, but every provider session could not be closed. Sign in with the new password and try closing other sessions again.")
		return
	}
	if generacion > 0 {
		_, err = s.ses.CrearUnicaEnGeneracionYEmision(r.Context(), w, r, &capacidad.proveedor, capacidad.aal, false, generacion, capacidad.emitido)
	} else {
		_, err = s.ses.CrearUnicaEnEmision(r.Context(), w, r, &capacidad.proveedor, capacidad.aal, false, capacidad.emitido)
	}
	if err != nil {
		s.descartarCapacidadPassword(w, id, capacidad)
		_ = s.gt.Logout(r.Context(), capacidad.proveedor.AccessToken, "local")
		s.errorPagina(w, r, http.StatusInternalServerError, "Create account", "The password was saved, but the session could not start. Sign in with the new password.")
		return
	}
	s.descartarCapacidadPassword(w, id, capacidad)
	s.ponerFlash(w, "Your address is confirmed and your password is saved. Welcome. Ask for the tools you need below; a person reads the first request.")
	http.Redirect(w, r, s.nextSeguro(capacidad.next), http.StatusSeeOther)
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
	intent, err := s.emitirIntencionRecuperacion(r.Context(), email)
	if err != nil {
		log.Printf("crear intención de recuperación: %v", err)
		s.errorPagina(w, r, http.StatusInternalServerError, "Reset", "The recovery could not be prepared. Try again.")
		return
	}
	redirectTo := s.cfg.PublicURL.String() + "/restablecer?intent=" + url.QueryEscape(intent)
	if err := s.gt.Recover(r.Context(), email, redirectTo); err != nil {
		// Se tapa todo, también el 429: sólo lo devuelve para correos que
		// existen, así que enseñarlo sería enumerar. El freno por IP de arriba
		// ya limita el abuso.
		log.Printf("recover: %v", err)
	}
	s.render(w, r, "correo.html", "Check your inbox", map[string]any{"Mensaje": mensajeRevisaCorreo}, http.StatusOK)
}

func (s *Server) restablecerGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if intent := q.Get("intent"); intent != "" {
		_, mfaValida := s.leerIntencionRecuperacionMFA(r, intent)
		if !mfaValida && !s.intencionRecuperacionDisponible(intent) {
			s.errorPagina(w, r, http.StatusBadRequest, "Invalid link", "This recovery link was not requested here, has expired, or was already used. Ask for a new one.")
			return
		}
		s.confirmarEnlace(w, r, "recovery", "/restablecer", intent, "", "")
		return
	}
	if !s.capacidadPasswordDisponible(r, propositoRecuperacion, "") {
		http.Redirect(w, r, "/recuperar", http.StatusSeeOther)
		return
	}
	s.render(w, r, "restablecer.html", "Choose a new password", nil, http.StatusOK)
}

func (s *Server) restablecerPOST(w http.ResponseWriter, r *http.Request) {
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if len(p1) < 12 || p1 != p2 {
		s.render(w, r, "restablecer.html", "Choose a new password", map[string]any{"Error": "Use 12 characters or more, and type it twice the same."}, http.StatusBadRequest)
		return
	}
	id, capacidad, ok := s.reclamarCapacidadPassword(r, propositoRecuperacion, "")
	if !ok {
		http.Redirect(w, r, "/recuperar", http.StatusSeeOther)
		return
	}
	u, generacion, err := s.cambiarPassword(r.Context(), capacidad.proveedor.User.ID, capacidad.emitido,
		generacionEsperada(capacidad.generacion, capacidad.generacionLigada),
		capacidad.proveedor.AccessToken, p1, "", "")
	if err != nil {
		if falloPasswordReintentable(err) {
			s.liberarCapacidadPassword(capacidad)
		} else {
			s.descartarCapacidadPassword(w, id, capacidad)
		}
		s.render(w, r, "restablecer.html", "Choose a new password", map[string]any{"Error": mensajeGoTrue(err)}, http.StatusBadRequest)
		return
	}
	if u != nil && u.ID == capacidad.proveedor.User.ID {
		capacidad.proveedor.User = *u
	}
	var a *session.Actual
	if generacion > 0 {
		a, err = s.ses.CrearUnicaEnGeneracionYEmision(r.Context(), w, r, &capacidad.proveedor, capacidad.aal, false, generacion, capacidad.emitido)
	} else {
		a, err = s.ses.CrearUnicaEnEmision(r.Context(), w, r, &capacidad.proveedor, capacidad.aal, false, capacidad.emitido)
	}
	if err != nil {
		s.descartarCapacidadPassword(w, id, capacidad)
		_ = s.gt.Logout(r.Context(), capacidad.proveedor.AccessToken, "local")
		s.errorPagina(w, r, http.StatusInternalServerError, "Reset", "The password changed, but the session could not start. Sign in with the new password.")
		return
	}
	if err := s.ses.CerrarOtrasProveedor(r.Context(), a); err != nil {
		s.descartarCapacidadPassword(w, id, capacidad)
		s.ses.Cerrar(r.Context(), w, a)
		s.errorPagina(w, r, http.StatusBadGateway, "Reset", "The password changed, but every provider session could not be closed. Sign in with the new password and try closing other sessions again.")
		return
	}
	s.descartarCapacidadPassword(w, id, capacidad)
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
