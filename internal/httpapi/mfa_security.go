package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

const vidaAutoridadMFA = 5 * time.Minute
const propositoIntencionRecuperacionMFA = "account-mfa-final-removal-v1"

const (
	cookieAutoridadMFA            = "__Host-account_mfa_change"
	cookieAutoridadMFADevelopment = "account_mfa_change"
	cookieAutoridadMFALegacy      = "__Secure-account_mfa_change"
)

type propositoMFA string

const (
	propositoMFAAlta   propositoMFA = "enroll"
	propositoMFABorrar propositoMFA = "delete"
)

// retoAutoridadMFA es una afirmación de un factor que ya estaba verificado
// antes de empezar la mutación. Nunca contiene el factor nuevo.
type retoAutoridadMFA struct {
	FactorID    string
	ChallengeID string
	Options     string
	Nombre      string
	Tipo        string
}

// autoridadMFA es la concesión reciente, de un uso y sólo en memoria. Queda
// ligada a persona, portador de sesión, propósito y, al borrar, factor exacto.
// proveedor es la sesión nacida de la contraseña y, si corresponde, elevada
// por un factor anterior o por la prueba de buzón para retirar el último.
type autoridadMFA struct {
	mu             sync.Mutex
	ID             string
	UserID         string
	SessionID      string
	Proposito      propositoMFA
	FactorObjetivo string
	Proveedor      gotrue.Session
	Hasta          time.Time
	Metodo         string
	Autorizada     bool
	EsperandoBuzon bool
	EnUso          bool
	Consumida      bool
	TOTP           *retoAutoridadMFA
	Passkeys       []*retoAutoridadMFA
}

type vistaAutoridadMFA struct {
	Proposito      propositoMFA
	FactorObjetivo string
	Autorizada     bool
	EsperandoBuzon bool
	TOTP           *retoAutoridadMFA
	Passkeys       []*retoAutoridadMFA
}

type intencionRecuperacionMFA struct {
	Proposito   string `json:"p"`
	AutoridadID string `json:"a"`
	UserID      string `json:"u"`
	SessionID   string `json:"s"`
	FactorID    string `json:"f"`
	Email       string `json:"e"`
	Hasta       int64  `json:"h"`
}

func (s *Server) bloquearMFA(userID string) func() {
	v, _ := s.bloqueosMFA.LoadOrStore(userID, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Server) sesionMFASigueViva(ctx context.Context, actual *session.Actual) bool {
	if s.st == nil {
		return true
	}
	x, err := s.st.Sesion(ctx, actual.ID)
	return err == nil && x.UserID == actual.UserID
}

func (s *Server) fallarCierreCambioMFA(ctx context.Context, w http.ResponseWriter, actual *session.Actual) error {
	var err error
	if s.st != nil {
		err = s.st.RevocarSesiones(ctx, actual.UserID)
	}
	// Borra siempre la cookie presentada. Cerrar es además un último intento
	// acotado sobre la sesión actual si la limpieza durable devolvió error.
	s.ses.Cerrar(ctx, w, actual)
	return err
}

func (s *Server) errorCierreCambioMFA(w http.ResponseWriter, r *http.Request, actual *session.Actual, estado int, titulo, detalleConfirmado string) {
	detalle := detalleConfirmado
	if err := s.fallarCierreCambioMFA(r.Context(), w, actual); err != nil {
		log.Printf("revocación de seguridad tras cambio MFA incierto: %v", err)
		detalle = "Session cleanup did not finish and must be retried by an administrator. Do not assume the other sessions are closed."
	}
	s.errorPagina(w, r, estado, titulo, detalle)
}

func (s *Server) nombreCookieAutoridadMFA() string {
	if s.ses.Secure() {
		return cookieAutoridadMFA
	}
	return cookieAutoridadMFADevelopment
}

func (s *Server) ponerCookieAutoridadMFA(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.nombreCookieAutoridadMFA(), Value: id, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteStrictMode})
	if s.ses.Secure() {
		http.SetCookie(w, &http.Cookie{Name: cookieAutoridadMFALegacy, Value: "", Path: "/cuenta", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
}

func (s *Server) idCookieAutoridadMFA(r *http.Request) (string, bool) {
	cookies := r.CookiesNamed(s.nombreCookieAutoridadMFA())
	if len(cookies) != 1 {
		return "", false
	}
	valor := cookies[0].Value
	if len(valor) != 64 {
		return "", false
	}
	return valor, true
}

func (s *Server) guardarAutoridadMFA(w http.ResponseWriter, a *autoridadMFA) {
	s.autoridadesMFA.Store(a.ID, a)
	s.ponerCookieAutoridadMFA(w, a.ID, int(time.Until(a.Hasta).Seconds()))
	time.AfterFunc(time.Until(a.Hasta), func() {
		if !s.autoridadesMFA.CompareAndDelete(a.ID, a) {
			return
		}
		a.mu.Lock()
		token := a.Proveedor.AccessToken
		a.mu.Unlock()
		if token != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.gt.Logout(ctx, token, "local")
		}
	})
}

func (s *Server) descartarAutoridadMFA(w http.ResponseWriter, id string, a *autoridadMFA, cerrarPrueba bool) {
	s.autoridadesMFA.CompareAndDelete(id, a)
	s.ponerCookieAutoridadMFA(w, "", -1)
	var token string
	if cerrarPrueba && a != nil {
		a.mu.Lock()
		token = a.Proveedor.AccessToken
		a.mu.Unlock()
	}
	if token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.gt.Logout(ctx, token, "local")
	}
}

func (s *Server) cargarAutoridadMFA(r *http.Request, actual *session.Actual) (string, *autoridadMFA, bool) {
	if actual == nil {
		return "", nil, false
	}
	id, ok := s.idCookieAutoridadMFA(r)
	if !ok {
		return "", nil, false
	}
	v, ok := s.autoridadesMFA.Load(id)
	if !ok {
		return "", nil, false
	}
	a, ok := v.(*autoridadMFA)
	if !ok {
		s.autoridadesMFA.Delete(id)
		return "", nil, false
	}
	a.mu.Lock()
	valida := a.ID == id && a.UserID == actual.UserID && a.SessionID == actual.ID && time.Now().Before(a.Hasta)
	a.mu.Unlock()
	if !valida {
		return "", nil, false
	}
	return id, a, true
}

func (s *Server) vistaMFA(r *http.Request, actual *session.Actual) *vistaAutoridadMFA {
	_, a, ok := s.cargarAutoridadMFA(r, actual)
	if !ok {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return &vistaAutoridadMFA{Proposito: a.Proposito, FactorObjetivo: a.FactorObjetivo, Autorizada: a.Autorizada,
		EsperandoBuzon: a.EsperandoBuzon, TOTP: a.TOTP, Passkeys: append([]*retoAutoridadMFA(nil), a.Passkeys...)}
}

func factoresVerificados(factores []gotrue.Factor) []gotrue.Factor {
	var out []gotrue.Factor
	for _, f := range factores {
		if f.Status == "verified" {
			out = append(out, f)
		}
	}
	return out
}

// rechazoMutacionMFA distingue una negativa explícita del proveedor de un
// resultado ambiguo (timeout, conexión rota, 5xx o respuesta ilegible). Sólo
// una negativa 4xx permite asumir que la mutación no llegó a confirmarse.
func rechazoMutacionMFA(err error) bool {
	var ge *gotrue.Error
	return errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500
}

func factorPorID(factores []gotrue.Factor, id string) (gotrue.Factor, bool) {
	for _, f := range factores {
		if f.ID == id {
			return f, true
		}
	}
	return gotrue.Factor{}, false
}

func (s *Server) prepararRetosAutoridadMFA(ctx context.Context, token, excluir string, factores []gotrue.Factor) (*retoAutoridadMFA, []*retoAutoridadMFA, int, error) {
	var totp *retoAutoridadMFA
	var passkeys []*retoAutoridadMFA
	verificados := 0
	rpID, origins := s.rp()
	for _, f := range factores {
		if f.Status != "verified" || f.ID == excluir {
			continue
		}
		verificados++
		switch f.FactorType {
		case "totp":
			if totp != nil {
				continue
			}
			ch, err := s.gt.ChallengeFactor(ctx, token, f.ID)
			if err != nil {
				return nil, nil, verificados, err
			}
			totp = &retoAutoridadMFA{FactorID: f.ID, ChallengeID: ch.ID, Nombre: f.FriendlyName, Tipo: "totp"}
		case "webauthn":
			ch, err := s.gt.ChallengeWebAuthn(ctx, token, f.ID, "request", rpID, origins)
			if err != nil {
				return nil, nil, verificados, err
			}
			passkeys = append(passkeys, &retoAutoridadMFA{FactorID: f.ID, ChallengeID: ch.ID, Options: string(ch.Options), Nombre: f.FriendlyName, Tipo: "webauthn"})
		}
	}
	return totp, passkeys, verificados, nil
}

func (s *Server) mfaAutorizar(w http.ResponseWriter, r *http.Request) {
	actual := s.requiereSesion(w, r)
	if actual == nil {
		return
	}
	if s.frena(w, r, "mfa-autorizar", 6, 2) {
		return
	}
	proposito := propositoMFA(r.PostFormValue("purpose"))
	factorID := strings.TrimSpace(r.PostFormValue("factor_id"))
	if proposito != propositoMFAAlta && proposito != propositoMFABorrar || proposito == propositoMFABorrar && factorID == "" {
		s.ponerFlash(w, "That MFA change is not valid.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if id, anterior, ok := s.cargarAutoridadMFA(r, actual); ok {
		s.descartarAutoridadMFA(w, id, anterior, true)
	}

	id, err := identificadorCapacidad()
	if err != nil {
		s.errorPagina(w, r, http.StatusInternalServerError, "Security", "The MFA change could not be prepared. Try again.")
		return
	}
	autoridad := &autoridadMFA{ID: id, UserID: actual.UserID, SessionID: actual.ID, Proposito: proposito,
		FactorObjetivo: factorID, Hasta: time.Now().Add(vidaAutoridadMFA)}

	password := r.PostFormValue("current_password")
	if password == "" {
		s.ponerFlash(w, "Type your current password to authorize this MFA change.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	prueba, err, respondido := s.verificarPassword(w, r, actual.Email, password, actual.UserID)
	if respondido {
		return
	}
	if err != nil || prueba == nil || prueba.AccessToken == "" || prueba.User.ID != actual.UserID {
		s.ponerFlash(w, "The current password is not correct.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	usuario, err := s.gt.Me(r.Context(), prueba.AccessToken)
	if err != nil || usuario.ID != actual.UserID {
		_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		s.ponerFlash(w, "The recent identity proof could not be checked. Try again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	prueba.User = *usuario
	autoridad.Proveedor = *prueba

	objetivo, existeObjetivo := factorPorID(usuario.Factors, factorID)
	if proposito == propositoMFABorrar && !existeObjetivo {
		_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		s.ponerFlash(w, "That factor no longer exists. Reload the page.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	excluir := ""
	if proposito == propositoMFABorrar {
		excluir = factorID
	}
	totp, passkeys, candidatos, err := s.prepararRetosAutoridadMFA(r.Context(), prueba.AccessToken, excluir, usuario.Factors)
	if err != nil {
		_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	verificados := factoresVerificados(usuario.Factors)
	if candidatos > 0 {
		if totp == nil && len(passkeys) == 0 {
			_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
			s.ponerFlash(w, "An existing factor must confirm this change, but its type is not supported here.")
			http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
			return
		}
		autoridad.TOTP, autoridad.Passkeys = totp, passkeys
		s.guardarAutoridadMFA(w, autoridad)
		s.ponerFlash(w, "Password accepted. Confirm with a different existing factor within five minutes.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if proposito == propositoMFAAlta && len(verificados) > 0 {
		_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		s.ponerFlash(w, "An existing factor must confirm this change, but none can be used here.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	if proposito == propositoMFABorrar && objetivo.Status == "verified" && len(verificados) == 1 {
		autoridad.EsperandoBuzon, autoridad.Metodo = true, "recovery"
		intent, err := s.emitirIntencionRecuperacionMFA(autoridad, actual.Email)
		if err != nil {
			_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
			s.errorPagina(w, r, http.StatusInternalServerError, "Security", "The recovery proof could not be prepared. Try again.")
			return
		}
		s.guardarAutoridadMFA(w, autoridad)
		redirectTo := s.cfg.PublicURL.String() + "/restablecer?intent=" + url.QueryEscape(intent)
		if err := s.gt.Recover(r.Context(), actual.Email, redirectTo); err != nil {
			s.descartarAutoridadMFA(w, id, autoridad, true)
			s.ponerFlash(w, "The recovery email could not be sent. Try again.")
			http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
			return
		}
		s.ponerFlash(w, "Password accepted. Open the email we sent in this same signed-in browser to authorize removing the final factor.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}

	autoridad.Autorizada, autoridad.Metodo = true, "password"
	s.guardarAutoridadMFA(w, autoridad)
	s.ponerFlash(w, "Password accepted. Complete this MFA change within five minutes.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) mfaConfirmar(w http.ResponseWriter, r *http.Request) {
	actual := s.requiereSesion(w, r)
	if actual == nil {
		return
	}
	id, autoridad, ok := s.cargarAutoridadMFA(r, actual)
	if !ok {
		s.ponerFlash(w, "The recent-authentication proof expired. Start the MFA change again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	factorID, challengeID := r.PostFormValue("factor_id"), r.PostFormValue("challenge_id")
	autoridad.mu.Lock()
	if autoridad.Autorizada || autoridad.EsperandoBuzon || autoridad.EnUso {
		autoridad.mu.Unlock()
		s.descartarAutoridadMFA(w, id, autoridad, true)
		s.ponerFlash(w, "The recent-authentication proof is no longer valid. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	var reto *retoAutoridadMFA
	if autoridad.TOTP != nil && autoridad.TOTP.FactorID == factorID && autoridad.TOTP.ChallengeID == challengeID {
		reto = autoridad.TOTP
	}
	for _, p := range autoridad.Passkeys {
		if p.FactorID == factorID && p.ChallengeID == challengeID {
			reto = p
			break
		}
	}
	if reto == nil || factorID == autoridad.FactorObjetivo {
		autoridad.mu.Unlock()
		s.descartarAutoridadMFA(w, id, autoridad, true)
		s.ponerFlash(w, "The factor challenge does not belong to this MFA change. Start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.EnUso = true
	accessAnterior := autoridad.Proveedor.AccessToken
	var gs *gotrue.Session
	var err error
	if reto.Tipo == "webauthn" {
		cred := strings.TrimSpace(r.PostFormValue("credential"))
		if cred == "" || len(cred) > 32<<10 || !json.Valid([]byte(cred)) {
			err = errors.New("credencial inválida")
		} else {
			rpID, origins := s.rp()
			gs, err = s.gt.VerifyWebAuthn(r.Context(), accessAnterior, reto.FactorID, reto.ChallengeID, "request", rpID, origins, json.RawMessage(cred))
		}
	} else {
		gs, err = s.gt.VerifyFactor(r.Context(), accessAnterior, reto.FactorID, reto.ChallengeID, strings.TrimSpace(r.PostFormValue("code")))
	}
	if err == nil && (gs == nil || gs.AccessToken == "") {
		err = errors.New("verificación sin sesión")
	}
	if err == nil && gs.User.ID == "" {
		var u *gotrue.User
		u, err = s.gt.Me(r.Context(), gs.AccessToken)
		if err == nil {
			gs.User = *u
		}
	}
	if err != nil || gs.User.ID != autoridad.UserID {
		autoridad.mu.Unlock()
		s.descartarAutoridadMFA(w, id, autoridad, true)
		s.ponerFlash(w, "That factor could not authorize the MFA change. Type the password and start again.")
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	autoridad.Proveedor = *gs
	autoridad.Metodo, autoridad.Autorizada, autoridad.EnUso = "factor", true, false
	autoridad.TOTP, autoridad.Passkeys = nil, nil
	autoridad.mu.Unlock()
	if accessAnterior != "" && accessAnterior != gs.AccessToken {
		_ = s.gt.Logout(r.Context(), accessAnterior, "local")
	}
	s.ponerFlash(w, "Recent authentication accepted. Complete the MFA change within five minutes.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) emitirIntencionRecuperacionMFA(a *autoridadMFA, email string) (string, error) {
	b, err := json.Marshal(intencionRecuperacionMFA{Proposito: propositoIntencionRecuperacionMFA, AutoridadID: a.ID,
		UserID: a.UserID, SessionID: a.SessionID, FactorID: a.FactorObjetivo, Email: email, Hasta: a.Hasta.Unix()})
	if err != nil {
		return "", err
	}
	return s.ses.Sellar(string(b))
}

func (s *Server) leerIntencionRecuperacionMFA(r *http.Request, sellada string) (*intencionRecuperacionMFA, bool) {
	txt, err := s.ses.Abrir(sellada)
	if err != nil {
		return nil, false
	}
	var i intencionRecuperacionMFA
	if json.Unmarshal([]byte(txt), &i) != nil || i.Proposito != propositoIntencionRecuperacionMFA || i.AutoridadID == "" ||
		i.UserID == "" || i.SessionID == "" || i.FactorID == "" || i.Email == "" || time.Now().Unix() > i.Hasta {
		return nil, false
	}
	actual := sesionDe(r)
	if actual == nil || actual.UserID != i.UserID || actual.ID != i.SessionID {
		return nil, false
	}
	v, ok := s.autoridadesMFA.Load(i.AutoridadID)
	if !ok {
		return nil, false
	}
	a, ok := v.(*autoridadMFA)
	if !ok {
		return nil, false
	}
	a.mu.Lock()
	valida := a.ID == i.AutoridadID && a.UserID == i.UserID && a.SessionID == i.SessionID && a.FactorObjetivo == i.FactorID &&
		a.Proposito == propositoMFABorrar && a.EsperandoBuzon && !a.Autorizada && time.Now().Before(a.Hasta)
	a.mu.Unlock()
	if !valida {
		return nil, false
	}
	return &i, true
}

func (s *Server) completarRecuperacionMFA(ctx context.Context, i *intencionRecuperacionMFA, gs *gotrue.Session) (string, error) {
	v, ok := s.autoridadesMFA.Load(i.AutoridadID)
	if !ok {
		return "", errors.New("autoridad MFA ausente")
	}
	a, ok := v.(*autoridadMFA)
	if !ok {
		return "", errors.New("autoridad MFA inválida")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.UserID != i.UserID || a.SessionID != i.SessionID || a.FactorObjetivo != i.FactorID || !a.EsperandoBuzon || a.Autorizada || !time.Now().Before(a.Hasta) {
		return "", errors.New("autoridad MFA caducada")
	}
	if gs == nil || gs.AccessToken == "" || gs.User.ID != i.UserID {
		return "", errors.New("recuperación MFA de otra identidad")
	}
	u, err := s.gt.Me(ctx, gs.AccessToken)
	if err != nil {
		return "", err
	}
	if u.ID != i.UserID {
		return "", errors.New("recuperación MFA comprobada para otra identidad")
	}
	verificados := factoresVerificados(u.Factors)
	if len(verificados) != 1 || verificados[0].ID != i.FactorID {
		return "", errors.New("el factor objetivo ya no es el último factor verificado")
	}
	anterior := a.Proveedor.AccessToken
	gs.User = *u
	a.Proveedor = *gs
	a.Autorizada, a.EsperandoBuzon, a.Metodo = true, false, "recovery"
	return anterior, nil
}
