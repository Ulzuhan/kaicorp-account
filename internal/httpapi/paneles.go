package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/correo"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

// ── Portada: tus herramientas ──────────────────────────────────────────────

type herramientaVista struct {
	store.Grupo
	Miembro   bool
	Pendiente bool
	EsRol     bool
}

// grupoVista es un grupo tal y como lo enseña la administración: los roles no
// abren ninguna herramienta y no llevan cliente.
type grupoVista struct {
	store.Grupo
	EsRol         bool
	ClienteNombre string
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	a := sesionDe(r)
	if a == nil {
		s.render(w, r, "home.html", "", nil, http.StatusOK)
		return
	}
	grupos, err := s.st.Grupos(r.Context())
	if err != nil {
		s.errorPagina(w, r, http.StatusServiceUnavailable, "Temporarily unavailable", "Could not read the list of tools.")
		return
	}
	miembro := map[string]bool{}
	for _, g := range s.membresias(r.Context(), a.UserID) {
		miembro[g] = true
	}
	pendiente := map[string]bool{}
	if sols, err := s.st.SolicitudesDe(r.Context(), a.UserID); err == nil {
		for _, x := range sols {
			if x.Estado == "pendiente" {
				pendiente[x.Grupo] = true
			}
		}
	}
	var hs []herramientaVista
	concedidas, esperando := 0, 0
	for _, g := range grupos {
		esRol := g.Tipo == store.TipoGrupoRol
		if esRol && !miembro[g.Nombre] {
			continue // los roles sólo se enseñan a quien los tiene
		}
		h := herramientaVista{Grupo: g, Miembro: miembro[g.Nombre], Pendiente: pendiente[g.Nombre], EsRol: esRol}
		if h.Miembro {
			concedidas++
		} else if h.Pendiente {
			esperando++
		}
		hs = append(hs, h)
	}
	s.render(w, r, "home.html", "Your tools", map[string]any{"Herramientas": hs, "Concedidas": concedidas, "Esperando": esperando}, http.StatusOK)
}

// ── Solicitar acceso ───────────────────────────────────────────────────────

func (s *Server) solicitar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	nombre := r.PathValue("grupo")
	g, decision, err := s.st.SolicitarAcceso(r.Context(), a.UserID, nombre, s.cfg.AdminGroup)
	if err != nil {
		if errors.Is(err, store.ErrNoExiste) {
			s.errorPagina(w, r, http.StatusNotFound, "Unknown tool", "There is no tool with that name.")
		} else {
			s.errorPagina(w, r, http.StatusServiceUnavailable, "Try again", "Could not record the request.")
		}
		return
	}
	next := s.nextSeguro(r.PostFormValue("next"))
	switch decision {
	case policy.Automatica:
		s.ponerFlash(w, g.Titulo+": access granted. You already had an approved account, so no one needs to read this one.")
	case policy.Pendiente:
		s.ponerFlash(w, g.Titulo+": request sent. A person reads the first one; you will get access once it is approved.")
	default:
		s.ponerFlash(w, g.Titulo+" is by invitation only.")
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ── Consentimiento OAuth ───────────────────────────────────────────────────
//
// El orden importa y no es el que sugiere la API de GoTrue: primero se mira en
// la base QUÉ cliente pide la autorización y si la persona pertenece a su
// grupo; sólo entonces se piden los detalles a GoTrue, porque esa llamada
// aprueba sola cuando ya hay un grant previo.

func (s *Server) consentGET(w http.ResponseWriter, r *http.Request) {
	// Lo que no depende de quién mira, antes de pedirle que entre: sin
	// autorización no hay nada que autorizar, y una autorización caducada no
	// merece un login para descubrirlo después.
	aid := r.URL.Query().Get("authorization_id")
	if aid == "" {
		s.errorPagina(w, r, http.StatusBadRequest, "Nothing to authorize", "This page is where a tool sends you to sign in. Open the tool and use its sign-in button.")
		return
	}
	clienteID, err := s.st.ClienteDeAutorizacion(r.Context(), aid)
	if err != nil {
		s.errorPagina(w, r, http.StatusGone, "This sign-in has expired", "Go back to the tool and try again.")
		return
	}
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	g, err := s.st.GrupoDeCliente(r.Context(), clienteID)
	if err != nil {
		log.Printf("consent: cliente %s sin grupo", clienteID)
		s.errorPagina(w, r, http.StatusForbidden, "Not available", "This tool is not open to anyone yet.")
		return
	}
	if !policy.PuedeEntrar(g.Nombre, s.membresias(r.Context(), a.UserID)) {
		pendiente := false
		if sols, err := s.st.SolicitudesDe(r.Context(), a.UserID); err == nil {
			for _, x := range sols {
				if x.Grupo == g.Nombre && x.Estado == "pendiente" {
					pendiente = true
				}
			}
		}
		s.render(w, r, "sin-acceso.html", g.Titulo, map[string]any{"Grupo": g, "Pendiente": pendiente, "Next": r.URL.RequestURI()}, http.StatusForbidden)
		return
	}
	auth, err := s.gt.GetAuthorization(r.Context(), a.Token(), aid)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Sign-in", mensajeGoTrue(err))
		return
	}
	if auth.AutoApproved() {
		if !s.consentSiguePermitido(w, r, a.UserID, clienteID) {
			return
		}
		http.Redirect(w, r, auth.RedirectURL, http.StatusSeeOther)
		return
	}
	s.render(w, r, "consent.html", "Sign in to "+auth.Client.Name, map[string]any{
		"Client": auth.Client, "Scopes": describirScopes(auth.Scopes()), "AuthorizationID": aid,
	}, http.StatusOK)
}

func describirScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		switch sc {
		case "openid":
			out = append(out, "Your account identifier")
		case "email":
			out = append(out, "Your email address")
		case "profile":
			out = append(out, "Your name")
		case "phone":
			out = append(out, "Your phone number")
		default:
			out = append(out, sc)
		}
	}
	return out
}

func (s *Server) consentPOST(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	aid := r.PostFormValue("authorization_id")
	action := r.PostFormValue("action")
	if action != "approve" && action != "deny" {
		action = "deny"
	}
	var clienteID string
	if action == "approve" {
		// La política otra vez, por si cambió entre pintar y pulsar.
		var err error
		clienteID, err = s.st.ClienteDeAutorizacion(r.Context(), aid)
		if err != nil {
			s.errorPagina(w, r, http.StatusGone, "This sign-in has expired", "Go back to the tool and try again.")
			return
		}
		g, err := s.st.GrupoDeCliente(r.Context(), clienteID)
		if err != nil || !policy.PuedeEntrar(g.Nombre, s.membresias(r.Context(), a.UserID)) {
			s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "Your account does not have access to this tool.")
			return
		}
	}
	dest, err := s.gt.Consent(r.Context(), a.Token(), aid, action)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Sign-in", mensajeGoTrue(err))
		return
	}
	if action == "approve" && !s.consentSiguePermitido(w, r, a.UserID, clienteID) {
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// No entrega un código que se emitió antes de revocar pero cuya respuesta
// llegó después. Las guardas de la base impiden las emisiones posteriores.
func (s *Server) consentSiguePermitido(w http.ResponseWriter, r *http.Request, userID, clienteID string) bool {
	g, err := s.st.GrupoDeCliente(r.Context(), clienteID)
	if err == nil {
		var miembro bool
		miembro, err = s.st.EsMiembro(r.Context(), userID, g.Nombre)
		if err == nil && miembro {
			return true
		}
	}
	s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "Your account does not have access to this tool.")
	return false
}

// ── Seguridad de la cuenta ─────────────────────────────────────────────────

type enrolamiento struct {
	factor      *gotrue.EnrolledFactor
	passkey     *passkeyPendiente
	userID      string
	sessionID   string
	autoridadID string
	factorID    string
	challengeID string
	hasta       time.Time
}

// passkeyPendiente es un reto WebAuthn abierto: el factor existe en GoTrue y
// espera la credencial del navegador. Options es el JSON de GoTrue tal cual,
// para el atributo data-options que lee passkey.js. Nombre sólo al entrar, para
// distinguir varias passkeys.
type passkeyPendiente struct {
	FactorID    string
	ChallengeID string
	Options     string
	Nombre      string
}

// rp devuelve el RP ID (el host público) y el origen para WebAuthn: la passkey
// queda atada a account.<dominio>, que es donde se crea y donde se usa.
func (s *Server) rp() (string, []string) {
	return s.cfg.PublicURL.Hostname(), []string{s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host}
}

func (s *Server) cuenta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	datos := map[string]any{}
	if u, err := s.gt.Me(r.Context(), a.Token()); err == nil {
		datos["Factores"] = u.Factors
		if n := u.Name(); n != "" {
			a.Nombre = n
		}
	} else {
		datos["Error"] = mensajeGoTrue(err)
	}
	if gs, err := s.gt.Grants(r.Context(), a.Token()); err == nil {
		for i := range gs {
			if t, err := time.Parse(time.RFC3339Nano, gs[i].GrantedAt); err == nil {
				gs[i].GrantedAt = t.Format("2006-01-02")
			}
		}
		datos["Grants"] = gs
	}
	if ss, err := s.st.SesionesDe(r.Context(), a.UserID); err == nil {
		datos["Sesiones"] = ss
	}
	if mfa := s.vistaMFA(r, a); mfa != nil {
		datos["MFA"] = mfa
	}
	if v, ok := s.enrolando.Load(a.ID); ok {
		e := v.(enrolamiento)
		if time.Now().Before(e.hasta) {
			if e.passkey != nil {
				datos["Passkey"] = e.passkey
			} else {
				datos["Enrolando"] = e.factor
				datos["EnrolandoChallenge"] = e.challengeID
				// html/template convierte una URL data: en "#ZgotmplZ" salvo que
				// llegue marcada como segura; el QR viene de GoTrue y va en base64.
				datos["EnrolandoQR"] = template.URL(e.factor.QRDataURL())
			}
		} else {
			s.enrolando.Delete(a.ID)
		}
	}
	s.render(w, r, "cuenta.html", "Security", datos, http.StatusOK)
}

func (s *Server) cuentaNombre(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 80 {
		s.ponerFlash(w, "The name has to be between 1 and 80 characters.")
	} else if _, err := s.gt.UpdateUser(r.Context(), a.Token(), name, ""); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.ponerFlash(w, "Name saved.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

const (
	vidaCambioCorreo    = 15 * time.Minute
	mensajeCambioCorreo = "If the request can proceed, private next-step instructions are on their way. The account keeps its current email until the required mailbox confirmations are complete."
)

type cambioCorreoPendiente struct {
	UserID string
	Email  string
	Hasta  time.Time
}

func claveCambioCorreo(token string) (string, bool) {
	if len(token) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(token); err != nil {
		return "", false
	}
	suma := sha256.Sum256([]byte(token))
	return hex.EncodeToString(suma[:]), true
}

func (s *Server) responderCambioCorreo(w http.ResponseWriter, r *http.Request) {
	s.ponerFlash(w, mensajeCambioCorreo)
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

// cuentaCorreo abre una prueba preliminar en el buzón propuesto sin consultar
// a GoTrue. Así ni la respuesta HTTP ni el buzón actual distinguen si la
// dirección ya pertenece a otra cuenta. GoTrue sólo ve la petición después de
// que el mismo usuario demuestra acceso al buzón propuesto; entonces conserva
// su confirmación final obligatoria en ambos buzones.
func (s *Server) cuentaCorreo(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	email, ok := correoValido(r.PostFormValue("email"))
	switch {
	case !ok:
		s.ponerFlash(w, "That does not look like an email address.")
	case strings.EqualFold(email, a.Email):
		s.ponerFlash(w, "That is already the email of this account.")
	case s.frena(w, r, "cambio-correo", 3, 0.3):
		return
	default:
		token, err := identificadorCapacidad()
		if err != nil {
			log.Printf("preparar cambio de correo para %s: no se pudo crear la capacidad", a.UserID)
		} else {
			clave, _ := claveCambioCorreo(token)
			pendiente := &cambioCorreoPendiente{UserID: a.UserID, Email: email, Hasta: time.Now().Add(vidaCambioCorreo)}
			s.cambiosCorreo.Store(clave, pendiente)
			time.AfterFunc(vidaCambioCorreo, func() { s.cambiosCorreo.CompareAndDelete(clave, pendiente) })
			s.enviarPruebaCambioCorreo(a.UserID, a.Email, email, token)
		}
		s.ponerFlash(w, mensajeCambioCorreo)
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) enviarPruebaCambioCorreo(userID, actual, propuesta, token string) {
	if s.correo == nil {
		log.Printf("cambio de correo para %s: correo de la app no configurado", userID)
		return
	}
	confirmar := *s.cfg.PublicURL
	confirmar.Path = strings.TrimRight(confirmar.Path, "/") + "/cuenta/correo/confirmar"
	confirmar.RawQuery = ""
	confirmar.Fragment = url.Values{"token": {token}}.Encode()
	cuenta := *s.cfg.PublicURL
	cuenta.Path = strings.TrimRight(cuenta.Path, "/") + "/cuenta"
	cuenta.RawQuery, cuenta.Fragment = "", ""
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := s.correo.EnviarCambioCorreo(ctx, actual, propuesta, correo.CambioCorreo{Cuenta: cuenta.String(), Confirmar: confirmar.String()}); err != nil {
			log.Printf("cambio de correo para %s: falló el envío privado", userID)
		}
	}()
}

// El GET sólo presenta el formulario: no busca ni consume la capacidad y nunca
// consulta al proveedor. El POST protegido por sesión, origen y CSRF es la
// única transición con efecto.
func (s *Server) cuentaCorreoConfirmarGET(w http.ResponseWriter, r *http.Request) {
	if s.requiereSesion(w, r) == nil {
		return
	}
	s.render(w, r, "confirmar-correo.html", "Confirm email change", nil, http.StatusOK)
}

func (s *Server) cuentaCorreoConfirmarPOST(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	token, unico := campoPostUnico(r, "token")
	clave, ok := claveCambioCorreo(token)
	if !unico || !ok {
		s.responderCambioCorreo(w, r)
		return
	}
	v, ok := s.cambiosCorreo.Load(clave)
	if !ok {
		s.responderCambioCorreo(w, r)
		return
	}
	pendiente, ok := v.(*cambioCorreoPendiente)
	if !ok || pendiente.UserID != a.UserID || !time.Now().Before(pendiente.Hasta) {
		if ok && !time.Now().Before(pendiente.Hasta) {
			s.cambiosCorreo.CompareAndDelete(clave, pendiente)
		}
		s.responderCambioCorreo(w, r)
		return
	}
	if !s.cambiosCorreo.CompareAndDelete(clave, pendiente) {
		s.responderCambioCorreo(w, r)
		return
	}
	if _, err := s.gt.UpdateUser(r.Context(), a.Token(), "", pendiente.Email); err != nil {
		var ge *gotrue.Error
		if errors.As(err, &ge) {
			log.Printf("confirmar cambio de correo para %s: status=%d code=%q msg=%q", a.UserID, ge.Status, ge.ErrorCode, ge.Msg)
		} else {
			log.Printf("confirmar cambio de correo para %s: %q", a.UserID, err.Error())
		}
	}
	s.responderCambioCorreo(w, r)
}

func (s *Server) cuentaPassword(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if len(p1) < 12 || p1 != p2 {
		s.ponerFlash(w, "Use 12 characters or more, and type it twice the same.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}

	actual := r.PostFormValue("current_password")
	if actual == "" {
		s.ponerFlash(w, "Type your current password to change it.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	prueba, err, respondido := s.verificarPassword(w, r, a.Email, actual, a.UserID)
	if respondido {
		return
	}
	if err != nil {
		s.ponerFlash(w, "The current password is not correct.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	conservarPrueba := false
	defer func() {
		if !conservarPrueba {
			_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		}
	}()
	if prueba.AccessToken == "" || prueba.User.ID == "" || prueba.User.ID != a.UserID {
		s.ponerFlash(w, "The current password is not correct.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	token := prueba.AccessToken
	if a.EsAAL2() {
		// La prueba fresca es la contraseña; se conserva el bearer aal2 para
		// que el proveedor no rebaje una cuenta con segundo factor.
		token = a.Token()
	}
	_, generacion, err := s.cambiarPassword(r.Context(), a.UserID, session.EmitidoDe(prueba.AccessToken), nil, token, p1, actual, "")
	if err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if a.EsAAL2() {
		if generacion > 0 {
			err = s.ses.RotarPortadorEnGeneracion(r.Context(), w, a, generacion)
		} else {
			err = s.ses.RotarPortador(r.Context(), w, a)
		}
	} else {
		if generacion > 0 {
			err = s.ses.ReautenticarEnGeneracion(r.Context(), w, a, prueba, generacion)
		} else {
			err = s.ses.Reautenticar(r.Context(), w, a, prueba)
		}
		conservarPrueba = err == nil
	}
	if err != nil {
		s.ses.Cerrar(r.Context(), w, a)
		s.errorPagina(w, r, http.StatusInternalServerError, "Password", "The password changed, but the session could not be renewed. Sign in with the new password.")
		return
	}
	if err := s.ses.CerrarOtrasProveedor(r.Context(), a); err != nil {
		s.ses.Cerrar(r.Context(), w, a)
		s.errorPagina(w, r, http.StatusBadGateway, "Password", "The password changed, but every provider session could not be closed. Sign in with the new password and try closing other sessions again.")
		return
	}
	s.ponerFlash(w, "Password changed.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorAlta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, a)
	if !ok {
		s.ponerFlash(w, "Confirm your current password before adding a factor.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.mu.Lock()
	if !autoridad.Autorizada || autoridad.Proposito != propositoMFAAlta || !time.Now().Before(autoridad.Hasta) {
		autoridad.mu.Unlock()
		s.descartarAutoridadMFA(w, id, autoridad, true)
		s.ponerFlash(w, "The recent-authentication proof expired. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if autoridad.EnUso {
		autoridad.mu.Unlock()
		s.ponerFlash(w, "A factor enrollment is already in progress.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.EnUso = true
	defer autoridad.mu.Unlock()
	desbloquear := s.bloquearMFA(a.UserID)
	defer desbloquear()
	if !s.sesionMFASigueViva(r.Context(), a) {
		token := autoridad.Proveedor.AccessToken
		s.autoridadesMFA.CompareAndDelete(id, autoridad)
		s.ponerCookieAutoridadMFA(w, "", -1)
		if token != "" {
			_ = s.gt.Logout(r.Context(), token, "local")
		}
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	f, err := s.gt.EnrollTOTP(r.Context(), a.Token(), "Authenticator app", "KaiCorp Labs")
	if err != nil {
		autoridad.EnUso = false
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		ch, challengeErr := s.gt.ChallengeFactor(r.Context(), a.Token(), f.ID)
		if challengeErr != nil {
			_ = s.gt.DeleteFactor(r.Context(), a.Token(), f.ID)
			autoridad.EnUso = false
			s.ponerFlash(w, mensajeGoTrue(challengeErr))
		} else {
			s.enrolando.Store(a.ID, enrolamiento{factor: f, userID: a.UserID, sessionID: a.ID, autoridadID: id,
				factorID: f.ID, challengeID: ch.ID, hasta: autoridad.Hasta})
		}
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorVerificar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, a)
	v, pendienteOK := s.enrolando.Load(a.ID)
	pendiente, tipoOK := v.(enrolamiento)
	if !ok || !pendienteOK || !tipoOK {
		s.ponerFlash(w, "This factor enrollment was not started by this session, or it expired.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.mu.Lock()
	defer autoridad.mu.Unlock()
	if !autoridad.Autorizada || autoridad.Proposito != propositoMFAAlta || !autoridad.EnUso || autoridad.Consumida || pendiente.userID != a.UserID ||
		pendiente.sessionID != a.ID || pendiente.autoridadID != id || pendiente.factorID != r.PostFormValue("factor_id") ||
		pendiente.challengeID != r.PostFormValue("challenge_id") || !time.Now().Before(pendiente.hasta) {
		s.ponerFlash(w, "This factor challenge does not belong to the pending enrollment. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.Consumida = true
	desbloquear := s.bloquearMFA(a.UserID)
	defer desbloquear()
	if !s.sesionMFASigueViva(r.Context(), a) {
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	gs, err := s.gt.VerifyFactor(r.Context(), a.Token(), pendiente.factorID, pendiente.challengeID, strings.TrimSpace(r.PostFormValue("code")))
	if err != nil {
		if !rechazoMutacionMFA(err) {
			log.Printf("resultado ambiguo al verificar TOTP: %v", err)
			s.enrolando.Delete(a.ID)
			s.autoridadesMFA.CompareAndDelete(id, autoridad)
			s.ponerCookieAutoridadMFA(w, "", -1)
			s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The factor result was uncertain, so every session was closed. Sign in again.")
			return
		}
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if gs == nil || gs.AccessToken == "" {
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The factor was verified without a usable identity, so every session was closed. Sign in again.")
		return
	}
	if gs.User.ID == "" {
		u, comprobarErr := s.gt.Me(r.Context(), gs.AccessToken)
		if comprobarErr == nil {
			gs.User = *u
		} else {
			err = comprobarErr
		}
	}
	if err != nil || gs.User.ID != a.UserID {
		_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The verified factor did not belong to this account, so every session was closed. Sign in again.")
		return
	}
	s.enrolando.Delete(a.ID)
	s.autoridadesMFA.CompareAndDelete(id, autoridad)
	s.ponerCookieAutoridadMFA(w, "", -1)
	if err := s.ses.ReautenticarComo(r.Context(), w, a, gs, "aal2"); err != nil {
		log.Printf("promover sesión aal2: %v", err)
		s.errorCierreCambioMFA(w, r, a, http.StatusServiceUnavailable, "Sign in again", "Your factor was verified, but the session could not be renewed, so every session was closed. Sign in again.")
		return
	}
	if err := s.ses.CerrarOtrasProveedor(r.Context(), a); err != nil {
		log.Printf("cerrar sesiones tras alta MFA: %v", err)
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The factor was added, but closing the other provider sessions failed, so every session was revoked locally. Sign in again.")
		return
	}
	s.ponerFlash(w, "Second factor active. From now on, signing in asks for a code.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

// passkeyAlta crea el factor y abre el reto de alta; la credencial la crea el
// navegador en la página de Seguridad (passkey.js) y llega a passkeyVerificar.
func (s *Server) passkeyAlta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, a)
	if !ok {
		s.ponerFlash(w, "Confirm your current password before adding a factor.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.mu.Lock()
	if !autoridad.Autorizada || autoridad.Proposito != propositoMFAAlta || !time.Now().Before(autoridad.Hasta) {
		autoridad.mu.Unlock()
		s.descartarAutoridadMFA(w, id, autoridad, true)
		s.ponerFlash(w, "The recent-authentication proof expired. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if autoridad.EnUso {
		autoridad.mu.Unlock()
		s.ponerFlash(w, "A factor enrollment is already in progress.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.EnUso = true
	defer autoridad.mu.Unlock()
	desbloquear := s.bloquearMFA(a.UserID)
	defer desbloquear()
	if !s.sesionMFASigueViva(r.Context(), a) {
		token := autoridad.Proveedor.AccessToken
		s.autoridadesMFA.CompareAndDelete(id, autoridad)
		s.ponerCookieAutoridadMFA(w, "", -1)
		if token != "" {
			_ = s.gt.Logout(r.Context(), token, "local")
		}
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	nombre := strings.TrimSpace(r.PostFormValue("name"))
	if nombre == "" {
		nombre = "Passkey"
	}
	if len(nombre) > 60 {
		nombre = nombre[:60]
	}
	f, err := s.gt.EnrollWebAuthn(r.Context(), a.Token(), nombre)
	if err != nil {
		autoridad.EnUso = false
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	rpID, origins := s.rp()
	ch, err := s.gt.ChallengeWebAuthn(r.Context(), a.Token(), f.ID, "create", rpID, origins)
	if err != nil {
		_ = s.gt.DeleteFactor(r.Context(), a.Token(), f.ID)
		autoridad.EnUso = false
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	s.enrolando.Store(a.ID, enrolamiento{passkey: &passkeyPendiente{FactorID: f.ID, ChallengeID: ch.ID, Options: string(ch.Options)},
		userID: a.UserID, sessionID: a.ID, autoridadID: id, factorID: f.ID, challengeID: ch.ID, hasta: autoridad.Hasta})
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

// passkeyVerificar recibe la credencial que creó el navegador y la verifica en
// GoTrue: el factor pasa a verified y la sesión de la app a aal2.
func (s *Server) passkeyVerificar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, a)
	v, pendienteOK := s.enrolando.Load(a.ID)
	pendiente, tipoOK := v.(enrolamiento)
	if !ok || !pendienteOK || !tipoOK || pendiente.passkey == nil {
		s.ponerFlash(w, "This passkey enrollment was not started by this session, or it expired.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.mu.Lock()
	defer autoridad.mu.Unlock()
	if !autoridad.Autorizada || autoridad.Proposito != propositoMFAAlta || !autoridad.EnUso || autoridad.Consumida || pendiente.userID != a.UserID ||
		pendiente.sessionID != a.ID || pendiente.autoridadID != id || pendiente.factorID != r.PostFormValue("factor_id") ||
		pendiente.challengeID != r.PostFormValue("challenge_id") || !time.Now().Before(pendiente.hasta) {
		s.ponerFlash(w, "This passkey challenge does not belong to the pending enrollment. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.Consumida = true
	cred := strings.TrimSpace(r.PostFormValue("credential"))
	if cred == "" || len(cred) > 32<<10 || !json.Valid([]byte(cred)) {
		s.ponerFlash(w, "The browser did not return a passkey. Try again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	rpID, origins := s.rp()
	desbloquear := s.bloquearMFA(a.UserID)
	defer desbloquear()
	if !s.sesionMFASigueViva(r.Context(), a) {
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	gs, err := s.gt.VerifyWebAuthn(r.Context(), a.Token(), pendiente.factorID, pendiente.challengeID, "create", rpID, origins, json.RawMessage(cred))
	if err != nil {
		if !rechazoMutacionMFA(err) {
			log.Printf("resultado ambiguo al verificar passkey: %v", err)
			s.enrolando.Delete(a.ID)
			s.autoridadesMFA.CompareAndDelete(id, autoridad)
			s.ponerCookieAutoridadMFA(w, "", -1)
			s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The passkey result was uncertain, so every session was closed. Sign in again.")
			return
		}
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if gs == nil || gs.AccessToken == "" {
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The passkey was verified without a usable identity, so every session was closed. Sign in again.")
		return
	}
	if gs.User.ID == "" {
		u, comprobarErr := s.gt.Me(r.Context(), gs.AccessToken)
		if comprobarErr == nil {
			gs.User = *u
		} else {
			err = comprobarErr
		}
	}
	if err != nil || gs.User.ID != a.UserID {
		_ = s.gt.Logout(r.Context(), gs.AccessToken, "local")
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The verified passkey did not belong to this account, so every session was closed. Sign in again.")
		return
	}
	s.enrolando.Delete(a.ID)
	s.autoridadesMFA.CompareAndDelete(id, autoridad)
	s.ponerCookieAutoridadMFA(w, "", -1)
	if err := s.ses.ReautenticarComo(r.Context(), w, a, gs, "aal2"); err != nil {
		log.Printf("promover sesión aal2 tras passkey: %v", err)
		s.errorCierreCambioMFA(w, r, a, http.StatusServiceUnavailable, "Sign in again", "Your passkey was verified, but the session could not be renewed, so every session was closed. Sign in again.")
		return
	}
	if err := s.ses.CerrarOtrasProveedor(r.Context(), a); err != nil {
		log.Printf("cerrar sesiones tras alta de passkey: %v", err)
		s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The passkey was added, but closing the other provider sessions failed, so every session was revoked locally. Sign in again.")
		return
	}
	s.ponerFlash(w, "Passkey added. From now on, signing in asks for it.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorBorrar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	factorID := r.PostFormValue("factor_id")
	// Cancelar exactamente el factor aún no verificado creado por esta misma
	// sesión revierte el alta pendiente; no convierte el endpoint en un borrado
	// general y sigue limitado por la ventana de la prueba reciente.
	if v, pendienteOK := s.enrolando.Load(a.ID); pendienteOK {
		p, tipoOK := v.(enrolamiento)
		if tipoOK && p.sessionID == a.ID && p.userID == a.UserID && p.factorID == factorID && time.Now().Before(p.hasta) {
			desbloquear := s.bloquearMFA(a.UserID)
			defer desbloquear()
			if !s.sesionMFASigueViva(r.Context(), a) {
				http.Redirect(w, r, "/entrar", http.StatusSeeOther)
				return
			}
			if err := s.gt.DeleteFactor(r.Context(), a.Token(), factorID); err != nil {
				s.ponerFlash(w, mensajeGoTrue(err))
			} else {
				s.enrolando.CompareAndDelete(a.ID, p)
				if v, ok := s.autoridadesMFA.Load(p.autoridadID); ok {
					if autoridad, tipoOK := v.(*autoridadMFA); tipoOK {
						s.descartarAutoridadMFA(w, p.autoridadID, autoridad, true)
					}
				}
				s.ponerCookieAutoridadMFA(w, "", -1)
				s.ponerFlash(w, "Factor enrollment cancelled.")
			}
			http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
			return
		}
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, a)
	if !ok {
		s.ponerFlash(w, "Confirm your current password before removing a factor.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.mu.Lock()
	defer autoridad.mu.Unlock()
	if !autoridad.Autorizada || autoridad.Consumida || !time.Now().Before(autoridad.Hasta) ||
		(autoridad.Proposito != propositoMFABorrar || autoridad.FactorObjetivo != factorID) {
		s.ponerFlash(w, "The recent-authentication proof does not authorize removing that factor.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.Consumida = true
	desbloquear := s.bloquearMFA(a.UserID)
	defer desbloquear()
	if !s.sesionMFASigueViva(r.Context(), a) {
		http.Redirect(w, r, "/entrar", http.StatusSeeOther)
		return
	}
	u, err := s.gt.Me(r.Context(), a.Token())
	if err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	objetivo, existe := factorPorID(u.Factors, factorID)
	verificados := factoresVerificados(u.Factors)
	if !existe || (objetivo.Status == "verified" && len(verificados) == 1 && autoridad.Metodo != "recovery") ||
		(objetivo.Status == "verified" && len(verificados) > 1 && autoridad.Metodo != "factor") {
		s.ponerFlash(w, "The factor state changed. Authorize its removal again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if err := s.gt.DeleteFactor(r.Context(), a.Token(), factorID); err != nil {
		s.autoridadesMFA.CompareAndDelete(id, autoridad)
		s.ponerCookieAutoridadMFA(w, "", -1)
		if !rechazoMutacionMFA(err) {
			log.Printf("resultado ambiguo al borrar factor MFA: %v", err)
			s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The factor result was uncertain, so every session was closed. Sign in again.")
			return
		}
		if autoridad.Proveedor.AccessToken != "" {
			_ = s.gt.Logout(r.Context(), autoridad.Proveedor.AccessToken, "local")
		}
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.enrolando.Delete(a.ID)
		s.autoridadesMFA.CompareAndDelete(id, autoridad)
		s.ponerCookieAutoridadMFA(w, "", -1)
		aal := "aal1"
		if (objetivo.Status != "verified" && len(verificados) > 0) || (objetivo.Status == "verified" && len(verificados) > 1) {
			aal = "aal2"
		}
		if err := s.ses.ReautenticarComo(r.Context(), w, a, &autoridad.Proveedor, aal); err != nil {
			log.Printf("rotar sesión tras borrar MFA: %v", err)
			s.errorCierreCambioMFA(w, r, a, http.StatusServiceUnavailable, "Sign in again", "The factor was removed, but the session could not be renewed, so every session was closed. Sign in again.")
			return
		}
		if err := s.ses.CerrarOtrasProveedor(r.Context(), a); err != nil {
			log.Printf("cerrar sesiones tras borrar MFA: %v", err)
			s.errorCierreCambioMFA(w, r, a, http.StatusBadGateway, "Sign in again", "The factor was removed, but closing the other provider sessions failed, so every session was revoked locally. Sign in again.")
			return
		}
		s.ponerFlash(w, "Factor removed.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) grantRevocar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	if err := s.gt.RevokeGrant(r.Context(), a.Token(), r.PostFormValue("client_id")); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.ponerFlash(w, "Signed out of that tool. It will ask you again next time.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) sesionesCerrar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	if err := s.ses.CerrarOtras(r.Context(), a); err != nil {
		s.ponerFlash(w, "Some sessions could not be closed. Try again.")
	} else {
		s.ponerFlash(w, "Every other session is closed.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

// ── Administración ─────────────────────────────────────────────────────────

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	datos := map[string]any{"IsAdmin": true, "Q": strings.TrimSpace(r.URL.Query().Get("q"))}
	if xs, err := s.st.SolicitudesPendientes(r.Context()); err == nil {
		datos["Pendientes"] = xs
	} else {
		datos["Error"] = "Could not read the requests."
	}
	if us, err := s.st.Usuarios(r.Context(), datos["Q"].(string), 50); err == nil {
		datos["Usuarios"] = us
	}
	// Los clientes por nombre: la tabla de grupos enseña «Pixelforge», no un
	// UUID, y sabe si a un grupo le falta el cliente que abre su herramienta.
	nombres := map[string]string{}
	if cs, err := s.st.Clientes(r.Context()); err == nil {
		datos["Clientes"] = cs
		for _, c := range cs {
			nombres[c.ID] = c.Nombre
		}
	}
	vinculados, herramientas := 0, 0
	if gs, err := s.st.Grupos(r.Context()); err == nil {
		var vistas []grupoVista
		for _, g := range gs {
			v := grupoVista{Grupo: g, EsRol: g.Tipo == store.TipoGrupoRol, ClienteNombre: nombres[g.ClienteID]}
			if !v.EsRol {
				herramientas++
				if g.ClienteID != "" {
					vinculados++
				}
			}
			vistas = append(vistas, v)
		}
		datos["Grupos"] = vistas
	}
	datos["Vinculados"] = vinculados
	datos["Herramientas"] = herramientas
	s.render(w, r, "admin.html", "Administration", datos, http.StatusOK)
}

func (s *Server) adminCuenta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	u, err := s.st.UsuarioPorID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.errorPagina(w, r, http.StatusNotFound, "No such account", "There is no account with that id.")
		return
	}
	datos := map[string]any{"IsAdmin": true, "Cuenta": u}
	// Cuánto hace que se le invitó, en palabras. La plantilla no sabe restar
	// fechas y el dato en crudo no dice nada: lo que quien administra necesita
	// saber de un vistazo es si el enlace que esa persona tiene es de esta
	// semana o de hace un mes. No se afirma si ha caducado —el plazo lo fija
	// GoTrue con GOTRUE_MAILER_OTP_EXP y esta app sólo exige una copia exacta
	// para comprobarlo al canjear; una etiqueta que se
	// desincronizara mentiría—; reenviar es inofensivo en cualquier caso.
	if !u.Confirmada && u.Invitada != nil {
		datos["InvitadaHace"] = enPalabras(time.Since(*u.Invitada))
	}
	datos["Membresias"], _ = s.st.MembresiasDe(r.Context(), u.ID)
	datos["Solicitudes"], _ = s.st.SolicitudesDe(r.Context(), u.ID)
	datos["Grupos"], _ = s.st.Grupos(r.Context())
	s.render(w, r, "admin-cuenta.html", u.Email, datos, http.StatusOK)
}

func (s *Server) adminSolicitud(w http.ResponseWriter, r *http.Request) {
	// La lectura inicial evita enseñar solicitudes a una sesión ordinaria; la
	// autoridad efectiva se vuelve a decidir bajo actor+destino después.
	if s.requiereAdmin(w, r) == nil {
		return
	}
	x, err := s.st.Solicitud(r.Context(), r.PostFormValue("id"))
	if err != nil {
		s.ponerFlash(w, "That request no longer exists.")
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	a, autoridad := s.requiereAutoridadAdmin(w, r, x.UserID)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	switch r.PostFormValue("decision") {
	case "aprobar":
		if err := autoridad.Conceder(r.Context(), x.UserID, x.Grupo, a.Email); err == nil {
			if err := autoridad.ResolverSolicitud(r.Context(), x.UserID, x.ID, "aprobada", a.Email); err != nil {
				log.Printf("resolver aprobación %s: %v", x.ID, err)
				s.ponerFlash(w, "Access was granted, but the request could not be closed. Retry it.")
			} else if err := autoridad.Verificar(r.Context()); err != nil {
				s.ponerFlash(w, x.Email+" can now use "+x.Grupo+". The notification was not sent.")
			} else {
				s.ponerFlash(w, x.Email+" can now use "+x.Grupo+"."+s.avisarAcceso(r.Context(), x.UserID, x.Grupo))
			}
		} else {
			log.Printf("aprobar %s/%s: %v", x.UserID, x.Grupo, err)
			s.ponerFlash(w, "Could not grant the access.")
		}
	case "rechazar":
		if err := autoridad.ResolverSolicitud(r.Context(), x.UserID, x.ID, "rechazada", a.Email); err != nil {
			log.Printf("rechazar solicitud %s: %v", x.ID, err)
			s.ponerFlash(w, "Could not reject the request.")
		} else {
			s.ponerFlash(w, "Request from "+x.Email+" rejected.")
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminVincular(w http.ResponseWriter, r *http.Request) {
	_, autoridad := s.requiereAutoridadAdmin(w, r)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	grupo, cliente := r.PostFormValue("grupo"), r.PostFormValue("cliente_id")
	if err := autoridad.VincularCliente(r.Context(), grupo, cliente); err != nil {
		log.Printf("vincular: %v", err)
		s.ponerFlash(w, "Could not change the client.")
	} else if cliente == "" {
		s.ponerFlash(w, grupo+": client unlinked. Nobody can sign in to that tool until one is linked again.")
	} else {
		s.ponerFlash(w, grupo+": client linked. Members of the group can sign in to the tool.")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminConceder(w http.ResponseWriter, r *http.Request) {
	uid, grupo := r.PostFormValue("user_id"), r.PostFormValue("grupo")
	a, autoridad := s.requiereAutoridadAdmin(w, r, uid)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	if err := autoridad.Conceder(r.Context(), uid, grupo, a.Email); errors.Is(err, store.ErrAutoconcesionAdmin) {
		s.ponerFlash(w, "You cannot grant administration to yourself.")
	} else if err != nil {
		log.Printf("conceder %s/%s: %v", uid, grupo, err)
		s.ponerFlash(w, "Could not grant the membership.")
	} else if err := autoridad.Verificar(r.Context()); err != nil {
		s.ponerFlash(w, "Granted "+grupo+". The notification was not sent.")
	} else {
		s.ponerFlash(w, "Granted "+grupo+"."+s.avisarAcceso(r.Context(), uid, grupo))
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

func (s *Server) adminRevocar(w http.ResponseWriter, r *http.Request) {
	uid, grupo := r.PostFormValue("user_id"), r.PostFormValue("grupo")
	_, autoridad := s.requiereAutoridadAdmin(w, r, uid)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	if autoridad.EsActor(r.Context(), uid) && grupo == s.cfg.AdminGroup {
		s.ponerFlash(w, "You cannot remove your own administration.")
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	if err := autoridad.Revocar(r.Context(), uid, grupo); err != nil {
		log.Printf("revocar %s/%s: %v", uid, grupo, err)
		s.ponerFlash(w, "Could not revoke.")
	} else {
		if grupo == s.cfg.AdminGroup {
			s.ponerFlash(w, "Revoked "+grupo+" and closed every session of that administrator.")
		} else {
			s.ponerFlash(w, "Revoked "+grupo+". The tool's sessions end within its cookie lifetime.")
		}
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

func (s *Server) adminCerrarSesiones(w http.ResponseWriter, r *http.Request) {
	uid := r.PostFormValue("user_id")
	_, autoridad := s.requiereAutoridadAdmin(w, r, uid)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	if err := autoridad.RevocarSesiones(r.Context(), uid); err != nil {
		log.Printf("cerrar sesiones %s: %v", uid, err)
		s.ponerFlash(w, "Could not close every session. Retry the operation.")
	} else {
		s.ponerFlash(w, "Every session of that account is closed.")
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

// adminReenviarInvitacion vuelve a mandar el correo de invitación a quien no lo
// ha aceptado. GoTrue conserva su id, su fecha de alta y las membresías ya
// concedidas: sólo cambia el enlace, que vuelve a valer lo que diga
// GOTRUE_MAILER_OTP_EXP y su copia comprobada ACCOUNT_EMAIL_LINK_TTL_SECONDS.
//
// POR QUÉ EXISTE: esto ya se podía hacer —escribir otra vez la misma dirección
// en el formulario de invitar reenvía—, pero nada en el panel lo decía, así que
// en la práctica no existía: el 12-09 hubo cuatro personas con la invitación
// caducada y quien administra no tenía forma de saber que repetirla bastaba. Una
// capacidad que no se puede descubrir no es una capacidad.
// enPalabras redondea una duración a lo que diría una persona: «today»,
// «2 days ago», «3 weeks ago». Sin minutos ni segundos, que para una invitación
// no significan nada.
func enPalabras(d time.Duration) string {
	switch dias := int(d.Hours() / 24); {
	case d < 24*time.Hour:
		return "today"
	case dias == 1:
		return "yesterday"
	case dias < 14:
		return fmt.Sprintf("%d days ago", dias)
	case dias < 60:
		return fmt.Sprintf("%d weeks ago", dias/7)
	default:
		return fmt.Sprintf("%d months ago", dias/30)
	}
}

func (s *Server) adminReenviarInvitacion(w http.ResponseWriter, r *http.Request) {
	uid := r.PostFormValue("user_id")
	_, autoridad := s.requiereAutoridadAdmin(w, r, uid)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	volver := func(msg string) {
		s.ponerFlash(w, msg)
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
	}
	u, err := s.st.UsuarioPorID(r.Context(), uid)
	if err != nil {
		volver("That account no longer exists.")
		return
	}
	// Reenviar a quien ya entró no tiene sentido y GoTrue lo rechazaría: su
	// invitación se consumió al confirmar. Se para aquí para poder decir por qué.
	if u.Confirmada {
		volver(u.Email + " has already accepted. There is nothing to resend.")
		return
	}
	if err := autoridad.VerificarEfecto(r.Context(), uid); err != nil {
		volver("Your administration changed before the invitation could be sent. Try again.")
		return
	}
	redirectTo, err := RedireccionInvitacion(s.cfg.PublicURL, s.ses, u.Email)
	if err != nil {
		log.Printf("preparar reenvío de invitación a %s: %v", u.Email, err)
		volver("The invitation could not be prepared. Try again.")
		return
	}
	if _, err := s.gt.AdminInvite(r.Context(), u.Email, redirectTo); err != nil {
		log.Printf("reenviar invitación a %s: %v", u.Email, err)
		volver(mensajeGoTrue(err))
		return
	}
	volver("Invitation sent again to " + u.Email + ". Their memberships are untouched.")
}

func (s *Server) adminBloquear(w http.ResponseWriter, r *http.Request) {
	uid := r.PostFormValue("user_id")
	_, autoridad := s.requiereAutoridadAdmin(w, r, uid)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	if autoridad.EsActor(r.Context(), uid) {
		s.ponerFlash(w, "You cannot block yourself.")
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	duracion := "876000h"
	if r.PostFormValue("accion") == "desbloquear" {
		duracion = "none"
	}
	if duracion == "none" {
		if err := autoridad.VerificarEfecto(r.Context(), uid); err != nil {
			s.ponerFlash(w, "Your administration changed before the account could be unblocked.")
		} else if err := s.gt.AdminBanUser(r.Context(), uid, duracion); err != nil {
			s.ponerFlash(w, mensajeGoTrue(err))
		} else {
			s.ponerFlash(w, "Account unblocked.")
		}
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	errAutoridad := autoridad.VerificarEfecto(r.Context(), uid)
	var errBloqueo, errSesiones error
	if errAutoridad == nil {
		errBloqueo = s.gt.AdminBanUser(r.Context(), uid, duracion)
		if err := autoridad.VerificarEfecto(r.Context(), uid); err != nil {
			errAutoridad = err
		} else {
			errSesiones = autoridad.RevocarSesiones(r.Context(), uid)
		}
	}
	if err := errors.Join(errAutoridad, errBloqueo, errSesiones); err != nil {
		log.Printf("bloquear y cerrar sesiones %s: %v", uid, err)
		s.ponerFlash(w, "The account could not be fully blocked and signed out. Retry the operation.")
	} else {
		s.ponerFlash(w, "Account blocked and signed out everywhere.")
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

// ── Plantillas de correo para GoTrue y salud ───────────────────────────────

var plantillasPermitidas = map[string]bool{
	"confirmacion.html": true, "recuperacion.html": true, "cambio-correo.html": true,
	"invitacion.html": true, "magic.html": true, "reautenticacion.html": true,
}

// plantilla sirve las plantillas de correo tal cual: GoTrue las pide por HTTP
// (GOTRUE_MAILER_TEMPLATES_*) desde la red interna y las procesa él.
func (s *Server) plantilla(w http.ResponseWriter, r *http.Request) {
	nombre := r.PathValue("nombre")
	if !plantillasPermitidas[nombre] {
		http.NotFound(w, r)
		return
	}
	b, err := webPlantilla(nombre)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextoBreve(r)
	defer cancel()
	estado := map[string]any{"ok": true}
	code := http.StatusOK
	if err := s.st.Ping(ctx); err != nil {
		estado["ok"], estado["db"] = false, "down"
		code = http.StatusServiceUnavailable
	}
	if err := s.gt.Health(ctx); err != nil {
		estado["ok"], estado["gotrue"] = false, "down"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(estado)
}

// avisarAcceso manda el correo de «tu acceso está listo» tras conceder una
// herramienta a mano (aprobar una solicitud o conceder desde la ficha). Los
// roles no llevan aviso (no abren nada), las concesiones automáticas tampoco
// (la persona está delante y lo ve). Devuelve el remate para el aviso del
// panel: quien aprueba sabe si el correo salió.
func (s *Server) avisarAcceso(ctx context.Context, userID, grupo string) string {
	g, err := s.st.Grupo(ctx, grupo)
	if err != nil || g.Tipo != store.TipoGrupoHerramienta || g.URL == "" {
		return ""
	}
	if s.correo == nil {
		return " (no email: sending is not configured)"
	}
	u, err := s.st.UsuarioPorID(ctx, userID)
	if err != nil {
		return " (no email: could not read the account)"
	}
	if err := s.correo.EnviarAcceso(ctx, u.Email, correo.Acceso{Nombre: nombreDe(u), Herramienta: g.Titulo, URL: g.URL, Cuenta: s.cfg.PublicURL.String() + "/"}); err != nil {
		log.Printf("aviso de acceso a %s (%s): %v", u.Email, grupo, err)
		return " The email could not be sent; tell them yourself."
	}
	return " They have been told by email."
}

func nombreDe(u *store.Usuario) string {
	if u.Nombre != "" {
		return u.Nombre
	}
	return u.Email
}

// ── Invitar ────────────────────────────────────────────────────────────────

// adminInvitar trae a alguien por invitación: GoTrue crea la cuenta y manda el
// correo con el enlace para elegir contraseña; las herramientas marcadas se
// conceden ya, para que al llegar no tenga que pedir nada ni esperar a nadie.
// Invitar otra vez a quien aún no ha aceptado reenvía el enlace sobre la misma
// cuenta (mismo id, así que el remapeo de datos que hubiera sigue valiendo).
func (s *Server) adminInvitar(w http.ResponseWriter, r *http.Request) {
	a, autoridad := s.requiereAutoridadAdmin(w, r)
	if autoridad == nil {
		return
	}
	defer autoridad.Cerrar()
	volver := func(msg string) {
		s.ponerFlash(w, msg)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
	email, ok := correoValido(r.PostFormValue("email"))
	if !ok {
		volver("That does not look like an email address.")
		return
	}
	const maxGruposInvitacion = 32
	seleccionados := r.Form["grupo"]
	if len(seleccionados) > maxGruposInvitacion {
		volver("Choose at most 32 groups.")
		return
	}
	unicos := make(map[string]bool, len(seleccionados))
	nombres := make([]string, 0, len(seleccionados))
	for _, nombre := range seleccionados {
		if !unicos[nombre] {
			unicos[nombre] = true
			nombres = append(nombres, nombre)
		}
	}
	if len(nombres) > maxGruposInvitacion {
		volver("Choose at most 32 groups.")
		return
	}
	sort.Strings(nombres)
	var grupos []*store.Grupo
	for _, nombre := range nombres {
		g, err := s.st.Grupo(r.Context(), nombre)
		if err != nil {
			volver("Unknown group: " + nombre + ".")
			return
		}
		grupos = append(grupos, g)
	}
	if err := autoridad.Verificar(r.Context()); err != nil {
		volver("Your administration changed before the invitation could be sent. Try again.")
		return
	}
	generacion := autoridad.Generacion()
	redirectTo, err := RedireccionInvitacion(s.cfg.PublicURL, s.ses, email)
	if err != nil {
		log.Printf("preparar invitación a %s: %v", email, err)
		volver("The invitation could not be prepared. Try again.")
		return
	}
	u, err := s.gt.AdminInvite(r.Context(), email, redirectTo)
	if err != nil {
		var ge *gotrue.Error
		if errors.As(err, &ge) && ge.Status == http.StatusUnprocessableEntity {
			volver(email + " already has an account. Grant the tools from their page instead.")
			return
		}
		log.Printf("invitar %s: %v", email, err)
		volver("The invitation could not be sent. It has been logged.")
		return
	}
	// El efecto remoto ya terminó bajo el bloqueo del actor. Para conocer el
	// nuevo id hay que abrir una segunda fase actor+destino; conserva la
	// generación original, de modo que revocar y volver a conceder no la revive.
	autoridad.Cerrar()
	autoridadDestino, err := s.st.AutorizarAdminEnGeneracion(r.Context(), a.UserID, s.cfg.AdminGroup, generacion, u.ID)
	if errors.Is(err, store.ErrAdministradorRevocado) {
		volver("Invitation sent to " + email + ", but no memberships were granted because your administration changed.")
		return
	}
	if err != nil {
		log.Printf("invitar %s, reautorizar membresías: %v", email, err)
		volver("Invitation sent to " + email + ", but its memberships could not be granted.")
		return
	}
	defer autoridadDestino.Cerrar()
	var titulos []string
	for _, g := range grupos {
		if err := autoridadDestino.Conceder(r.Context(), u.ID, g.Nombre, a.Email); err != nil {
			log.Printf("invitar %s, conceder %s: %v", email, g.Nombre, err)
			continue
		}
		titulos = append(titulos, g.Titulo)
	}
	msg := "Invitation sent to " + email + "."
	if len(titulos) > 0 {
		msg += " On arrival they can use " + strings.Join(titulos, ", ") + "."
	}
	msg += " If the link expires before they use it, invite them again from here: it re-sends to the same account."
	s.ponerFlash(w, msg)
	http.Redirect(w, r, "/admin?q="+url.QueryEscape(email), http.StatusSeeOther)
}
