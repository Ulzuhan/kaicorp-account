package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

const (
	ventanaPasswordLocal = 15 * time.Minute
	primerBackoffLocal   = 10
	maxIntentosLocal     = 1_000_000
)

type intentoPasswordLocal struct {
	intentos    int
	noAntes     time.Time
	actualizado time.Time
}

type sujetoPassword struct {
	tipo     string
	valor    string
	esperado string
}

func pausaPasswordLocal(intentos int) time.Duration {
	if intentos < primerBackoffLocal {
		return 0
	}
	exponente := intentos - primerBackoffLocal
	if exponente >= 6 {
		return time.Minute
	}
	return time.Second * time.Duration(1<<exponente)
}

// sujetoDePassword resuelve antes del proveedor una cuenta conocida a su ID
// estable. Los correos inexistentes usan sólo un digest y reciben exactamente
// el mismo presupuesto y las mismas respuestas públicas.
func (s *Server) sujetoDePassword(ctx context.Context, email, userID string) (sujetoPassword, error) {
	if userID != "" {
		return sujetoPassword{tipo: "usuario", valor: strings.ToLower(strings.TrimSpace(userID)), esperado: userID}, nil
	}
	if s.st != nil {
		u, err := s.st.UsuarioPorCorreo(ctx, email)
		if err == nil {
			return sujetoPassword{tipo: "usuario", valor: strings.ToLower(u.ID), esperado: u.ID}, nil
		}
		if !errors.Is(err, store.ErrNoExiste) {
			return sujetoPassword{}, err
		}
	}
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return sujetoPassword{tipo: "correo", valor: fmt.Sprintf("%x", digest)}, nil
}

func (s *Server) reservarPasswordLocal(tipo, sujeto, cliente string) time.Duration {
	s.intentosPasswordMu.Lock()
	defer s.intentosPasswordMu.Unlock()
	if s.intentosPasswordLocal == nil {
		s.intentosPasswordLocal = map[string]*intentoPasswordLocal{}
	}
	ahora := time.Now()
	claves := []string{tipo + "\x00" + sujeto + "\x00", tipo + "\x00" + sujeto + "\x00" + cliente}
	for clave, estado := range s.intentosPasswordLocal {
		if ahora.Sub(estado.actualizado) >= 24*time.Hour {
			delete(s.intentosPasswordLocal, clave)
		}
	}
	estados := make([]*intentoPasswordLocal, 0, len(claves))
	var espera time.Duration
	for _, clave := range claves {
		estado := s.intentosPasswordLocal[clave]
		if estado == nil {
			estado = &intentoPasswordLocal{}
			s.intentosPasswordLocal[clave] = estado
		}
		if ahora.Sub(estado.actualizado) >= ventanaPasswordLocal {
			estado.intentos = 0
			estado.noAntes = ahora
		}
		if restante := estado.noAntes.Sub(ahora); restante > espera {
			espera = restante
		}
		estados = append(estados, estado)
	}
	if espera > 0 {
		if espera > time.Minute {
			return time.Minute
		}
		return espera
	}
	for _, estado := range estados {
		if estado.intentos < maxIntentosLocal {
			estado.intentos++
		}
		estado.noAntes = ahora.Add(pausaPasswordLocal(estado.intentos))
		estado.actualizado = ahora
	}
	return 0
}

func (s *Server) reservarPassword(ctx context.Context, sujeto sujetoPassword, cliente string) (time.Duration, error) {
	if s.st != nil {
		return s.st.ReservarIntentoPassword(ctx, sujeto.tipo, sujeto.valor, cliente)
	}
	return s.reservarPasswordLocal(sujeto.tipo, sujeto.valor, cliente), nil
}

func (s *Server) acreditarPassword(ctx context.Context, sujeto sujetoPassword, cliente string) error {
	if s.st != nil {
		return s.st.AcreditarPassword(ctx, sujeto.tipo, sujeto.valor, cliente)
	}
	s.intentosPasswordMu.Lock()
	defer s.intentosPasswordMu.Unlock()
	delete(s.intentosPasswordLocal, sujeto.tipo+"\x00"+sujeto.valor+"\x00")
	delete(s.intentosPasswordLocal, sujeto.tipo+"\x00"+sujeto.valor+"\x00"+cliente)
	return nil
}

func (s *Server) limitePassword(w http.ResponseWriter, r *http.Request, espera time.Duration) {
	segundos := int64((espera + time.Second - 1) / time.Second)
	if segundos < 1 {
		segundos = 1
	}
	if segundos > 60 {
		segundos = 60
	}
	w.Header().Set("Retry-After", strconv.FormatInt(segundos, 10))
	s.errorPagina(w, r, http.StatusTooManyRequests, "Too many attempts", "Wait before trying again.")
}

func (s *Server) passwordNoDisponible(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("límite de contraseña: %v", err)
	s.errorPagina(w, r, http.StatusServiceUnavailable, "Try again later", "Password verification is temporarily unavailable.")
}

// verificarPassword es la única entrada para contraseñas introducidas por una
// persona. Reserva el presupuesto persistente antes de llamar a GoTrue. El
// bool indica que ya se escribió una respuesta HTTP y el caller debe parar.
func (s *Server) verificarPassword(w http.ResponseWriter, r *http.Request, email, password, userID string) (*gotrue.Session, error, bool) {
	cliente, ok := s.ipDe(r)
	if !ok {
		s.errorPagina(w, r, http.StatusBadRequest, "Bad request", "The client address could not be determined.")
		return nil, nil, true
	}
	sujeto, err := s.sujetoDePassword(r.Context(), email, userID)
	if err != nil {
		s.passwordNoDisponible(w, r, err)
		return nil, nil, true
	}
	espera, err := s.reservarPassword(r.Context(), sujeto, cliente)
	if err != nil {
		s.passwordNoDisponible(w, r, err)
		return nil, nil, true
	}
	if espera > 0 {
		s.limitePassword(w, r, espera)
		return nil, nil, true
	}

	prueba, err := s.gt.Login(r.Context(), email, password)
	if err != nil {
		return nil, err, false
	}
	if prueba == nil || prueba.AccessToken == "" || prueba.User.ID == "" || sujeto.esperado != "" && prueba.User.ID != sujeto.esperado {
		if prueba != nil && prueba.AccessToken != "" {
			_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		}
		return nil, gotrue.ErrInvalidLogin, false
	}
	if err := s.acreditarPassword(r.Context(), sujeto, cliente); err != nil {
		_ = s.gt.Logout(r.Context(), prueba.AccessToken, "local")
		s.passwordNoDisponible(w, r, err)
		return nil, nil, true
	}
	return prueba, nil, false
}
