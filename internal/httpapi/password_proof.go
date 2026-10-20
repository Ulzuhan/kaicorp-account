package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

const vidaCapacidadPassword = 5 * time.Minute

type propositoPassword string

const (
	propositoRecuperacion propositoPassword = "recovery"
	propositoInvitacion   propositoPassword = "invite"
	propositoRegistro     propositoPassword = "signup"
)

// capacidadPassword conserva, sólo en memoria y durante unos minutos, la
// autoridad obtenida de un enlace de recuperación, invitación o registro. El
// valor de la cookie es un identificador aleatorio; los tokens del proveedor
// nunca salen.
type capacidadPassword struct {
	mu        sync.Mutex
	proveedor gotrue.Session
	aal       string
	proposito propositoPassword
	next      string
	// passwordActual sólo existe en el alta: es la credencial aleatoria que
	// acaba de instalar el servidor y prueba el cambio final sin guardar nada
	// elegido por quien inició el registro.
	passwordActual string
	// emitido es el iat de la autoridad original. Si hubo MFA se conserva el
	// del sobre anterior al factor, no el de los tokens recién verificados.
	emitido          int64
	generacion       int64
	generacionLigada bool
	hasta            time.Time
	reclamada        bool
}

const (
	vidaIntencionRecuperacion = time.Hour
	vidaIntencionRegistro     = 24 * time.Hour
	vidaIntencionInvitacion   = 24 * time.Hour
)

const propositoIntencionRecuperacion = "account-recovery-intent-v1"
const propositoIntencionRegistro = "account-signup-intent-v1"
const propositoIntencionInvitacion = "account-invite-intent-v1"

type intencionRecuperacion struct {
	Proposito        string `json:"p"`
	Email            string `json:"e"`
	UserID           string `json:"u,omitempty"`
	Generacion       int64  `json:"g,omitempty"`
	GeneracionLigada bool   `json:"l,omitempty"`
	Hasta            int64  `json:"h"`
}

type intencionRegistro struct {
	Proposito string `json:"p"`
	Email     string `json:"e"`
	Password  string `json:"w"`
	Hasta     int64  `json:"h"`
}

type intencionInvitacion struct {
	Proposito string `json:"p"`
	Email     string `json:"e"`
	Hasta     int64  `json:"h"`
}

// RedireccionInvitacion prepara la prueba de propósito que viaja únicamente en
// el correo del proveedor. También la usa la CLI: todas las invitaciones deben
// llegar a /verificar con el mismo sobre, con independencia de quién las emita.
func RedireccionInvitacion(publicURL *url.URL, ses *session.Manager, email string) (string, error) {
	email, valida := correoValido(email)
	if publicURL == nil || ses == nil || !valida {
		return "", errors.New("intención de invitación incompleta")
	}
	b, err := json.Marshal(intencionInvitacion{
		Proposito: propositoIntencionInvitacion,
		Email:     email,
		Hasta:     time.Now().Add(vidaIntencionInvitacion).Unix(),
	})
	if err != nil {
		return "", err
	}
	intent, err := ses.Sellar(string(b))
	if err != nil {
		return "", err
	}
	u := *publicURL
	u.Path = "/verificar"
	u.RawQuery = url.Values{"invite": {intent}}.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func (s *Server) leerIntencionInvitacion(sellada string) (*intencionInvitacion, bool) {
	txt, err := s.ses.Abrir(sellada)
	if err != nil {
		return nil, false
	}
	var i intencionInvitacion
	if json.Unmarshal([]byte(txt), &i) != nil || i.Proposito != propositoIntencionInvitacion || i.Email == "" || time.Now().Unix() > i.Hasta {
		return nil, false
	}
	return &i, true
}

func (s *Server) intencionInvitacionDisponible(sellada string) bool {
	_, ok := s.leerIntencionInvitacion(sellada)
	return ok
}

func (s *Server) validarIntencionInvitacion(sellada, email string) bool {
	i, ok := s.leerIntencionInvitacion(sellada)
	return ok && i.Email == email
}

// emitirIntencionRegistro lleva hasta el buzón, cifrada y autenticada, la
// credencial aleatoria instalada antes de mandar la confirmación. Exigir este
// sobre antes de canjear el hash vuelve inertes los enlaces emitidos por
// versiones antiguas que aún podían conservar una contraseña elegida por otro.
func (s *Server) emitirIntencionRegistro(email, password string) (string, error) {
	if email == "" || len(password) < 52 {
		return "", errors.New("intención de registro incompleta")
	}
	b, err := json.Marshal(intencionRegistro{
		Proposito: propositoIntencionRegistro,
		Email:     email,
		Password:  password,
		Hasta:     time.Now().Add(vidaIntencionRegistro).Unix(),
	})
	if err != nil {
		return "", err
	}
	return s.ses.Sellar(string(b))
}

func (s *Server) leerIntencionRegistro(sellada string) (*intencionRegistro, bool) {
	txt, err := s.ses.Abrir(sellada)
	if err != nil {
		return nil, false
	}
	var i intencionRegistro
	if json.Unmarshal([]byte(txt), &i) != nil || i.Proposito != propositoIntencionRegistro || i.Email == "" || len(i.Password) < 52 || time.Now().Unix() > i.Hasta {
		return nil, false
	}
	return &i, true
}

func (s *Server) intencionRegistroDisponible(sellada string) bool {
	_, ok := s.leerIntencionRegistro(sellada)
	return ok
}

func (s *Server) validarIntencionRegistro(sellada, email string) (string, bool) {
	i, ok := s.leerIntencionRegistro(sellada)
	if !ok || i.Email != email {
		return "", false
	}
	return i.Password, true
}

// emitirIntencionRecuperacion liga la petición hecha en /recuperar con el
// enlace que después vuelve del buzón. GoTrue comparte el mismo almacén para
// recovery y magiclink, así que el token del proveedor no demuestra por sí
// solo cuál de los dos propósitos lo emitió. El sobre cifrado es stateless:
// sobrevive reinicios y saltos de réplica mientras compartan la clave de sesión.
func (s *Server) emitirIntencionRecuperacion(ctx context.Context, email string) (string, error) {
	i := intencionRecuperacion{
		Proposito: propositoIntencionRecuperacion,
		Email:     email,
		Hasta:     time.Now().Add(vidaIntencionRecuperacion).Unix(),
	}
	if s.st != nil {
		u, err := s.st.UsuarioPorCorreo(ctx, email)
		if err != nil && !errors.Is(err, store.ErrNoExiste) {
			return "", err
		}
		if err == nil {
			generacion, err := s.st.GeneracionCredencial(ctx, u.ID)
			if err != nil {
				return "", err
			}
			i.UserID, i.Generacion, i.GeneracionLigada = u.ID, generacion, true
		}
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return s.ses.Sellar(string(b))
}

func (s *Server) leerIntencionRecuperacion(sellada string) (*intencionRecuperacion, bool) {
	txt, err := s.ses.Abrir(sellada)
	if err != nil {
		return nil, false
	}
	var i intencionRecuperacion
	if json.Unmarshal([]byte(txt), &i) != nil || i.Proposito != propositoIntencionRecuperacion || i.Email == "" ||
		(i.GeneracionLigada && i.UserID == "") || time.Now().Unix() > i.Hasta {
		return nil, false
	}
	return &i, true
}

func (s *Server) intencionRecuperacionDisponible(sellada string) bool {
	_, ok := s.leerIntencionRecuperacion(sellada)
	return ok
}

func (s *Server) validarIntencionRecuperacion(sellada, email string) bool {
	i, ok := s.leerIntencionRecuperacion(sellada)
	return ok && i.Email == email
}

func (s *Server) intencionRecuperacionValidada(sellada, email string) (*intencionRecuperacion, bool) {
	i, ok := s.leerIntencionRecuperacion(sellada)
	return i, ok && i.Email == email
}

func generacionEsperada(generacion int64, ligada bool) *int64 {
	if !ligada {
		return nil
	}
	return &generacion
}

func (s *Server) datosCookiePassword(proposito propositoPassword) (nombre, ruta string) {
	switch proposito {
	case propositoRecuperacion:
		nombre = "__Host-account_recovery"
	case propositoInvitacion:
		nombre = "__Host-account_password_setup"
	case propositoRegistro:
		nombre = "__Host-account_signup_setup"
	default:
		return "", ""
	}
	if !s.ses.Secure() {
		nombre = nombre[len("__Host-"):]
	}
	return nombre, "/"
}

func datosCookiePasswordLegada(proposito propositoPassword) (nombre, ruta string) {
	switch proposito {
	case propositoRecuperacion:
		return "__Secure-account_recovery", "/restablecer"
	case propositoInvitacion:
		return "__Secure-account_password_setup", "/cuenta"
	case propositoRegistro:
		return "__Secure-account_signup_setup", "/registro/password"
	default:
		return "", ""
	}
}

func (s *Server) expirarCookiePasswordLegada(w http.ResponseWriter, proposito propositoPassword) {
	nombre, ruta := datosCookiePasswordLegada(proposito)
	if nombre == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: nombre, Value: "", Path: ruta, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func identificadorCapacidad() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) emitirCapacidadPassword(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword) error {
	return s.emitirCapacidadPasswordConNextYAutoridad(w, gs, aal, proposito, "", "", emitidoSesion(gs), 0, false)
}

func (s *Server) emitirCapacidadRegistro(w http.ResponseWriter, gs *gotrue.Session, aal, next, passwordActual string) error {
	return s.emitirCapacidadRegistroEnEmision(w, gs, aal, next, passwordActual, emitidoSesion(gs))
}

func (s *Server) emitirCapacidadRegistroEnEmision(w http.ResponseWriter, gs *gotrue.Session, aal, next, passwordActual string, emitido int64) error {
	return s.emitirCapacidadRegistroEnAutoridad(w, gs, aal, next, passwordActual, emitido, 0, false)
}

func (s *Server) emitirCapacidadRegistroEnAutoridad(w http.ResponseWriter, gs *gotrue.Session, aal, next, passwordActual string, emitido, generacion int64, ligada bool) error {
	if passwordActual == "" {
		return errors.New("capacidad de registro sin credencial pendiente")
	}
	return s.emitirCapacidadPasswordConNextYAutoridad(w, gs, aal, propositoRegistro, s.nextSeguro(next), passwordActual, emitido, generacion, ligada)
}

func (s *Server) emitirCapacidadInvitacionEnAutoridad(w http.ResponseWriter, gs *gotrue.Session, aal, next, passwordActual string, emitido, generacion int64, ligada bool) error {
	if passwordActual == "" {
		return errors.New("capacidad de invitación sin credencial pendiente")
	}
	return s.emitirCapacidadPasswordConNextYAutoridad(w, gs, aal, propositoInvitacion, s.nextSeguro(next), passwordActual, emitido, generacion, ligada)
}

func (s *Server) emitirCapacidadPasswordConNext(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword, next string) error {
	return s.emitirCapacidadPasswordConNextYAutoridad(w, gs, aal, proposito, next, "", emitidoSesion(gs), 0, false)
}

func emitidoSesion(gs *gotrue.Session) int64 {
	if gs == nil {
		return 0
	}
	return session.EmitidoDe(gs.AccessToken)
}

func (s *Server) emitirCapacidadPasswordEnEmision(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword, emitido int64) error {
	return s.emitirCapacidadPasswordEnAutoridad(w, gs, aal, proposito, emitido, 0, false)
}

func (s *Server) emitirCapacidadPasswordEnAutoridad(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword, emitido, generacion int64, ligada bool) error {
	return s.emitirCapacidadPasswordConNextYAutoridad(w, gs, aal, proposito, "", "", emitido, generacion, ligada)
}

func (s *Server) emitirCapacidadPasswordConNextYAutoridad(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword, next, passwordActual string, emitido, generacion int64, ligada bool) error {
	if gs == nil || gs.AccessToken == "" || gs.User.ID == "" || (aal != "aal1" && aal != "aal2") {
		return errors.New("capacidad de contraseña incompleta")
	}
	if (proposito == propositoRegistro || proposito == propositoInvitacion) && passwordActual == "" {
		return errors.New("capacidad de alta sin credencial pendiente")
	}
	nombre, ruta := s.datosCookiePassword(proposito)
	if nombre == "" {
		return errors.New("propósito de contraseña inválido")
	}
	id, err := identificadorCapacidad()
	if err != nil {
		return err
	}
	c := &capacidadPassword{proveedor: *gs, aal: aal, proposito: proposito, next: next, passwordActual: passwordActual,
		emitido: emitido, generacion: generacion, generacionLigada: ligada, hasta: time.Now().Add(vidaCapacidadPassword)}
	s.capacidadesPassword.Store(id, c)
	time.AfterFunc(vidaCapacidadPassword, func() { s.capacidadesPassword.CompareAndDelete(id, c) })
	http.SetCookie(w, &http.Cookie{Name: nombre, Value: id, Path: ruta, MaxAge: int(vidaCapacidadPassword.Seconds()),
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	if s.ses.Secure() {
		s.expirarCookiePasswordLegada(w, proposito)
	}
	return nil
}

// invalidarCapacidadesPassword elimina incluso capacidades ya reclamadas. Si
// alguna petición conserva el puntero, el corte compartido la detendrá antes
// de que vuelva a alcanzar al proveedor.
func (s *Server) invalidarCapacidadesPassword(userID string) {
	s.capacidadesPassword.Range(func(id, valor any) bool {
		c, ok := valor.(*capacidadPassword)
		if !ok {
			s.capacidadesPassword.Delete(id)
			return true
		}
		c.mu.Lock()
		misma := c.proveedor.User.ID == userID
		if misma {
			c.reclamada = true
		}
		c.mu.Unlock()
		if misma {
			s.capacidadesPassword.CompareAndDelete(id, c)
		}
		return true
	})
}

// cambiarPassword serializa todas las escrituras de contraseña del usuario.
// emitido puede pertenecer a un token distinto del bearer usado ante GoTrue:
// una sesión aal2 se conserva para el PUT, pero la prueba fresca aporta el iat.
func (s *Server) cambiarPassword(ctx context.Context, userID string, emitido int64, generacion *int64, token, password, passwordActual, nonce string) (*gotrue.User, int64, error) {
	var usuario *gotrue.User
	invalidar := false
	cambiar := func() (bool, error) {
		var err error
		usuario, err = s.gt.UpdatePassword(ctx, token, password, passwordActual, nonce)
		invalidar = err == nil || !falloPasswordReintentable(err)
		return invalidar, err
	}
	if s.st == nil { // Sólo los servidores unitarios sin base llegan aquí.
		_, err := cambiar()
		if invalidar {
			s.invalidarCapacidadesPassword(userID)
		}
		return usuario, 0, err
	}
	nuevaGeneracion, err := s.st.CambiarCredencial(ctx, userID, emitido, generacion, cambiar)
	if nuevaGeneracion > 0 || invalidar {
		s.invalidarCapacidadesPassword(userID)
	}
	if invalidar && nuevaGeneracion == 0 {
		if err == nil {
			err = errors.New("el cambio remoto no pudo registrarse")
		}
		ctxSeguridad, cancelar := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelar()
		err = s.bloquearRotacionNoProbada(ctxSeguridad, userID, err)
	}
	return usuario, nuevaGeneracion, err
}

func (s *Server) idCookiePassword(r *http.Request, proposito propositoPassword) (string, bool) {
	nombre, _ := s.datosCookiePassword(proposito)
	if nombre == "" {
		return "", false
	}
	var valor string
	encontrada := false
	for _, c := range r.Cookies() {
		if c.Name != nombre {
			continue
		}
		if encontrada {
			return "", false
		}
		encontrada = true
		valor = c.Value
	}
	if len(valor) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(valor); err != nil {
		return "", false
	}
	return valor, true
}

func (s *Server) capacidadPasswordDisponible(r *http.Request, proposito propositoPassword, userID string) bool {
	id, ok := s.idCookiePassword(r, proposito)
	if !ok {
		return false
	}
	v, ok := s.capacidadesPassword.Load(id)
	if !ok {
		return false
	}
	c := v.(*capacidadPassword)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proposito != proposito || c.reclamada || !time.Now().Before(c.hasta) || (userID != "" && c.proveedor.User.ID != userID) {
		return false
	}
	return true
}

func (s *Server) reclamarCapacidadPassword(r *http.Request, proposito propositoPassword, userID string) (string, *capacidadPassword, bool) {
	id, ok := s.idCookiePassword(r, proposito)
	if !ok {
		return "", nil, false
	}
	v, ok := s.capacidadesPassword.Load(id)
	if !ok {
		return "", nil, false
	}
	c := v.(*capacidadPassword)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proposito != proposito || c.reclamada || !time.Now().Before(c.hasta) || (userID != "" && c.proveedor.User.ID != userID) {
		return "", nil, false
	}
	c.reclamada = true
	return id, c, true
}

func (s *Server) liberarCapacidadPassword(c *capacidadPassword) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.hasta) {
		c.reclamada = false
	}
}

func (s *Server) descartarCapacidadPassword(w http.ResponseWriter, id string, c *capacidadPassword) {
	s.capacidadesPassword.CompareAndDelete(id, c)
	nombre, ruta := s.datosCookiePassword(c.proposito)
	http.SetCookie(w, &http.Cookie{Name: nombre, Value: "", Path: ruta, MaxAge: -1,
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	if s.ses.Secure() {
		s.expirarCookiePasswordLegada(w, c.proposito)
	}
}

func falloPasswordReintentable(err error) bool {
	var ge *gotrue.Error
	return errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500
}
