package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
)

const vidaCapacidadPassword = 5 * time.Minute

type propositoPassword string

const (
	propositoRecuperacion propositoPassword = "recovery"
	propositoInvitacion   propositoPassword = "invite"
)

// capacidadPassword conserva, sólo en memoria y durante unos minutos, la
// autoridad obtenida de un enlace de recuperación o invitación. El valor de la
// cookie es un identificador aleatorio; los tokens del proveedor nunca salen.
type capacidadPassword struct {
	mu        sync.Mutex
	proveedor gotrue.Session
	aal       string
	proposito propositoPassword
	hasta     time.Time
	reclamada bool
}

func (s *Server) datosCookiePassword(proposito propositoPassword) (nombre, ruta string) {
	switch proposito {
	case propositoRecuperacion:
		nombre, ruta = "__Secure-account_recovery", "/restablecer"
	case propositoInvitacion:
		nombre, ruta = "__Secure-account_password_setup", "/cuenta"
	default:
		return "", ""
	}
	if !s.ses.Secure() {
		nombre = nombre[len("__Secure-"):]
	}
	return nombre, ruta
}

func identificadorCapacidad() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) emitirCapacidadPassword(w http.ResponseWriter, gs *gotrue.Session, aal string, proposito propositoPassword) error {
	if gs == nil || gs.AccessToken == "" || gs.User.ID == "" || (aal != "aal1" && aal != "aal2") {
		return errors.New("capacidad de contraseña incompleta")
	}
	nombre, ruta := s.datosCookiePassword(proposito)
	if nombre == "" {
		return errors.New("propósito de contraseña inválido")
	}
	id, err := identificadorCapacidad()
	if err != nil {
		return err
	}
	c := &capacidadPassword{proveedor: *gs, aal: aal, proposito: proposito, hasta: time.Now().Add(vidaCapacidadPassword)}
	s.capacidadesPassword.Store(id, c)
	time.AfterFunc(vidaCapacidadPassword, func() { s.capacidadesPassword.CompareAndDelete(id, c) })
	http.SetCookie(w, &http.Cookie{Name: nombre, Value: id, Path: ruta, MaxAge: int(vidaCapacidadPassword.Seconds()),
		HttpOnly: true, Secure: s.ses.Secure(), SameSite: http.SameSiteLaxMode})
	return nil
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
}

func falloPasswordReintentable(err error) bool {
	var ge *gotrue.Error
	return errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500
}
