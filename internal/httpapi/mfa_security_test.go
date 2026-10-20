package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

func prepararAltaMFADePrueba(s *Server, a *session.Actual, ruta string) *http.Cookie {
	id, _ := identificadorCapacidad()
	hasta := time.Now().Add(time.Minute)
	autoridad := &autoridadMFA{ID: id, UserID: a.UserID, SessionID: a.ID, Proposito: propositoMFAAlta,
		Hasta: hasta, Autorizada: true, EnUso: true, Metodo: "password"}
	s.autoridadesMFA.Store(id, autoridad)
	pendiente := enrolamiento{factor: &gotrue.EnrolledFactor{ID: "factor"}, userID: a.UserID, sessionID: a.ID,
		autoridadID: id, factorID: "factor", challengeID: "reto", hasta: hasta}
	if strings.Contains(ruta, "passkey") {
		pendiente.passkey = &passkeyPendiente{FactorID: "factor", ChallengeID: "reto", Options: `{}`}
	}
	s.enrolando.Store(a.ID, pendiente)
	return &http.Cookie{Name: s.nombreCookieAutoridadMFA(), Value: id, Path: "/", Secure: s.ses.Secure(), HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func cookiePorNombre(w *httptest.ResponseRecorder, nombre string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == nombre && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestMutacionesMFARechazanSesionYCSRFSolos(t *testing.T) {
	var mutaciones atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/factors") {
			mutaciones.Add(1)
			t.Errorf("la mutación llegó al proveedor: %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
			return
		}
		t.Errorf("llamada inesperada: %s", r.URL.Path)
		http.Error(w, "no", http.StatusInternalServerError)
	})
	_, cookie := sesionMFA(t, s, consentPersona, "aal1", 3600)
	casos := []struct {
		ruta string
		form url.Values
	}{
		{"/cuenta/factor/alta", url.Values{}},
		{"/cuenta/factor/verificar", url.Values{"factor_id": {"nuevo"}, "challenge_id": {"reto"}, "code": {"123456"}}},
		{"/cuenta/passkey/alta", url.Values{"name": {"Key"}}},
		{"/cuenta/passkey/verificar", url.Values{"factor_id": {"nuevo"}, "challenge_id": {"reto"}, "credential": {`{"id":"x"}`}}},
		{"/cuenta/factor/borrar", url.Values{"factor_id": {"factor"}}},
	}
	for _, tc := range casos {
		w := postMFA(t, s, cookie, tc.ruta, tc.form)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cuenta" {
			t.Fatalf("%s aceptó sesión+CSRF sin prueba reciente: %d %s", tc.ruta, w.Code, w.Body.String())
		}
	}
	if mutaciones.Load() != 0 {
		t.Fatalf("sesión+CSRF produjo %d mutaciones del proveedor", mutaciones.Load())
	}
}

func TestResultadoAmbiguoDeMutacionMFAFallaCerrado(t *testing.T) {
	for _, ruta := range []string{"/cuenta/factor/verificar", "/cuenta/passkey/verificar"} {
		t.Run(ruta, func(t *testing.T) {
			s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/user":
					_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
				case r.URL.Path == "/factors/factor/verify":
					_, _ = w.Write([]byte(`{"access_token":`))
				case r.URL.Path == "/logout":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
					http.Error(w, "no", http.StatusInternalServerError)
				}
			})
			a, cookie := sesionMFA(t, s, consentPersona, "aal1", 3600)
			otra, _ := sesionMFA(t, s, consentPersona, "aal2", 3600)
			autoridad := prepararAltaMFADePrueba(s, a, ruta)
			w := postMFA(t, s, cookie, ruta, url.Values{
				"factor_id": {"factor"}, "challenge_id": {"reto"}, "code": {"123456"}, "credential": {`{"id":"credencial"}`},
			}, autoridad)
			if w.Code != http.StatusBadGateway {
				t.Fatalf("el resultado ambiguo no falló cerrado: %d %s", w.Code, w.Body.String())
			}
			if _, err := s.st.Sesion(t.Context(), a.ID); err != store.ErrNoExiste {
				t.Fatalf("sobrevivió la sesión activa: %v", err)
			}
			if _, err := s.st.Sesion(t.Context(), otra.ID); err != store.ErrNoExiste {
				t.Fatalf("sobrevivió otra sesión: %v", err)
			}
		})
	}
}

func TestResultadoAmbiguoAlBorrarMFAFallaCerrado(t *testing.T) {
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user":
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Factors: []gotrue.Factor{
				{ID: "objetivo", FactorType: "totp", Status: "verified"},
				{ID: "prueba", FactorType: "totp", Status: "verified"},
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/factors/objetivo":
			http.Error(w, `{"code":500,"msg":"incierto"}`, http.StatusInternalServerError)
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusInternalServerError)
		}
	})
	a, cookie := sesionMFA(t, s, consentPersona, "aal2", 3600)
	otra, _ := sesionMFA(t, s, consentPersona, "aal2", 3600)
	id, _ := identificadorCapacidad()
	autoridad := &autoridadMFA{ID: id, UserID: a.UserID, SessionID: a.ID, Proposito: propositoMFABorrar,
		FactorObjetivo: "objetivo", Hasta: time.Now().Add(time.Minute), Metodo: "factor", Autorizada: true,
		Proveedor: gotrue.Session{AccessToken: "factor-aal2", RefreshToken: "refresh-factor", User: gotrue.User{ID: a.UserID}},
	}
	s.autoridadesMFA.Store(id, autoridad)
	cookieAutoridad := &http.Cookie{Name: s.nombreCookieAutoridadMFA(), Value: id, Path: "/", Secure: true, HttpOnly: true}
	w := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"objetivo"}}, cookieAutoridad)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("el borrado ambiguo no falló cerrado: %d %s", w.Code, w.Body.String())
	}
	for _, sesionID := range []string{a.ID, otra.ID} {
		if _, err := s.st.Sesion(t.Context(), sesionID); err != store.ErrNoExiste {
			t.Fatalf("sobrevivió la sesión %s: %v", sesionID, err)
		}
	}
}

func TestCancelacionPendienteEsExactaYNoExigeOtraPrueba(t *testing.T) {
	var borrados atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/factors/factor" {
			borrados.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
		http.Error(w, "no", http.StatusInternalServerError)
	})
	a, cookie := sesionMFA(t, s, consentPersona, "aal1", 3600)
	_ = prepararAltaMFADePrueba(s, a, "/cuenta/factor/verificar")
	if w := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"otro"}}); w.Code != http.StatusSeeOther || borrados.Load() != 0 {
		t.Fatalf("la cancelación alcanzó otro factor: %d borrados=%d", w.Code, borrados.Load())
	}
	if w := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"factor"}}); w.Code != http.StatusSeeOther || borrados.Load() != 1 {
		t.Fatalf("no se canceló el pendiente exacto: %d borrados=%d", w.Code, borrados.Load())
	}
}

func TestAltaMFAUsaEstadoServidorYRotaSesiones(t *testing.T) {
	var activa atomic.Bool
	var verificaciones atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "prueba-password", RefreshToken: "refresh-password", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/user":
			u := gotrue.User{ID: consentPersona, Email: "test@example.com"}
			if activa.Load() {
				u.Factors = []gotrue.Factor{{ID: "nuevo", FactorType: "totp", Status: "verified"}}
			}
			_ = json.NewEncoder(w).Encode(u)
		case r.Method == http.MethodPost && r.URL.Path == "/factors":
			_ = json.NewEncoder(w).Encode(gotrue.EnrolledFactor{ID: "nuevo", Type: "totp"})
		case r.URL.Path == "/factors/nuevo/challenge":
			_, _ = w.Write([]byte(`{"id":"reto-nuevo"}`))
		case r.URL.Path == "/factors/nuevo/verify":
			verificaciones.Add(1)
			activa.Store(true)
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "nuevo-aal2", RefreshToken: "nuevo-refresh", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusInternalServerError)
		}
	})
	actual, cookie := sesionMFA(t, s, consentPersona, "aal1", 3600)
	otra, _ := sesionMFA(t, s, consentPersona, "aal2", 3600)

	autorizada := postMFA(t, s, cookie, "/cuenta/mfa/autorizar", url.Values{"purpose": {"enroll"}, "current_password": {"correcta"}})
	cookieAutoridad := cookiePorNombre(autorizada, s.nombreCookieAutoridadMFA())
	if autorizada.Code != http.StatusSeeOther || cookieAutoridad == nil {
		t.Fatalf("no se emitió autoridad de alta: %d %s", autorizada.Code, autorizada.Body.String())
	}
	alta := postMFA(t, s, cookie, "/cuenta/factor/alta", url.Values{}, cookieAutoridad)
	if alta.Code != http.StatusSeeOther {
		t.Fatalf("no empezó el alta: %d %s", alta.Code, alta.Body.String())
	}
	pendienteV, ok := s.enrolando.Load(actual.ID)
	if !ok {
		t.Fatal("el alta no guardó estado pendiente")
	}
	pendiente := pendienteV.(enrolamiento)
	if pendiente.factorID != "nuevo" || pendiente.challengeID != "reto-nuevo" || pendiente.sessionID != actual.ID {
		t.Fatalf("estado pendiente mal ligado: %+v", pendiente)
	}

	sustituida := postMFA(t, s, cookie, "/cuenta/factor/verificar", url.Values{
		"factor_id": {"nuevo"}, "challenge_id": {"reto-ajeno"}, "code": {"123456"},
	}, cookieAutoridad)
	if sustituida.Code != http.StatusSeeOther || verificaciones.Load() != 0 {
		t.Fatalf("un reto sustituido alcanzó al proveedor: %d verificaciones=%d", sustituida.Code, verificaciones.Load())
	}

	verificada := postMFA(t, s, cookie, "/cuenta/factor/verificar", url.Values{
		"factor_id": {"nuevo"}, "challenge_id": {"reto-nuevo"}, "code": {"123456"},
	}, cookieAutoridad)
	nueva := cookieSesion(verificada)
	if verificada.Code != http.StatusSeeOther || verificaciones.Load() != 1 || nueva == nil || nueva.Value == cookie.Value {
		t.Fatalf("el alta legítima no rotó la sesión: %d verificaciones=%d cookie=%v", verificada.Code, verificaciones.Load(), nueva)
	}
	if cargada, err := cargarCookie(s, nueva); err != nil || cargada == nil || !cargada.EsAAL2() || cargada.Token() != "nuevo-aal2" {
		t.Fatalf("la sesión rotada no conserva la prueba aal2: %+v %v", cargada, err)
	}
	if _, err := s.st.Sesion(t.Context(), otra.ID); err != store.ErrNoExiste {
		t.Fatalf("el alta conservó otra sesión: %v", err)
	}
}

func TestBorradoMFAExigeFactorDistintoYObjetivoExacto(t *testing.T) {
	var mu sync.Mutex
	factores := []gotrue.Factor{{ID: "objetivo", FactorType: "totp", Status: "verified"}, {ID: "prueba", FactorType: "totp", Status: "verified"}}
	var verificaciones, borrados atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "password-aal1", RefreshToken: "refresh-password", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/user":
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com", Factors: append([]gotrue.Factor(nil), factores...)})
		case r.URL.Path == "/factors/prueba/challenge":
			_, _ = w.Write([]byte(`{"id":"reto-prueba"}`))
		case r.URL.Path == "/factors/prueba/verify":
			verificaciones.Add(1)
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "factor-aal2", RefreshToken: "refresh-factor", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com", Factors: append([]gotrue.Factor(nil), factores...)}})
		case r.Method == http.MethodDelete && r.URL.Path == "/factors/objetivo":
			borrados.Add(1)
			factores = factores[1:]
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusInternalServerError)
		}
	})
	actual, cookie := sesionMFA(t, s, consentPersona, "aal2", 3600)
	otra, _ := sesionMFA(t, s, consentPersona, "aal2", 3600)

	autorizar := func() *http.Cookie {
		w := postMFA(t, s, cookie, "/cuenta/mfa/autorizar", url.Values{
			"purpose": {"delete"}, "factor_id": {"objetivo"}, "current_password": {"correcta"},
		})
		c := cookiePorNombre(w, s.nombreCookieAutoridadMFA())
		if w.Code != http.StatusSeeOther || c == nil {
			t.Fatalf("no se abrió la prueba de borrado: %d %s", w.Code, w.Body.String())
		}
		return c
	}

	primera := autorizar()
	mal := postMFA(t, s, cookie, "/cuenta/mfa/confirmar", url.Values{
		"factor_id": {"objetivo"}, "challenge_id": {"reto-prueba"}, "code": {"123456"},
	}, primera)
	if mal.Code != http.StatusSeeOther || verificaciones.Load() != 0 {
		t.Fatalf("el factor objetivo se autorizó a sí mismo: %d verificaciones=%d", mal.Code, verificaciones.Load())
	}

	segunda := autorizar()
	confirmada := postMFA(t, s, cookie, "/cuenta/mfa/confirmar", url.Values{
		"factor_id": {"prueba"}, "challenge_id": {"reto-prueba"}, "code": {"123456"},
	}, segunda)
	if confirmada.Code != http.StatusSeeOther || verificaciones.Load() != 1 {
		t.Fatalf("el factor distinto no autorizó: %d verificaciones=%d", confirmada.Code, verificaciones.Load())
	}
	objetivoAjeno := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"prueba"}}, segunda)
	if objetivoAjeno.Code != http.StatusSeeOther || borrados.Load() != 0 {
		t.Fatalf("la concesión borró otro factor: %d borrados=%d", objetivoAjeno.Code, borrados.Load())
	}
	borrado := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"objetivo"}}, segunda)
	nueva := cookieSesion(borrado)
	if borrado.Code != http.StatusSeeOther || borrados.Load() != 1 || nueva == nil || nueva.Value == cookie.Value {
		t.Fatalf("el borrado legítimo no terminó: %d borrados=%d cookie=%v", borrado.Code, borrados.Load(), nueva)
	}
	if actual.ID == strings.Split(nueva.Value, ".")[1] {
		t.Fatal("el portador no rotó")
	}
	if cargada, err := cargarCookie(s, nueva); err != nil || cargada == nil || !cargada.EsAAL2() || cargada.Token() != "factor-aal2" {
		t.Fatalf("la sesión activa no quedó en aal2: %+v %v", cargada, err)
	}
	if _, err := s.st.Sesion(t.Context(), otra.ID); err != store.ErrNoExiste {
		t.Fatalf("el borrado conservó otra sesión: %v", err)
	}
}

func TestUltimoFactorExigeRecuperacionLigadaALaSesion(t *testing.T) {
	var mu sync.Mutex
	factorPresente := true
	var redirectRecuperacion string
	var borrados atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		factores := []gotrue.Factor(nil)
		if factorPresente {
			factores = []gotrue.Factor{{ID: "ultimo", FactorType: "totp", Status: "verified"}}
		}
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "password-aal1", RefreshToken: "refresh-password", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"}})
		case r.URL.Path == "/user":
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com", Factors: factores})
		case r.URL.Path == "/recover":
			redirectRecuperacion = r.URL.Query().Get("redirect_to")
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/verify":
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: "recovery-aal1", RefreshToken: "refresh-recovery", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com", Factors: factores}})
		case r.Method == http.MethodDelete && r.URL.Path == "/factors/ultimo":
			borrados.Add(1)
			factorPresente = false
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusInternalServerError)
		}
	})
	s.resolverEnlaceCorreo = func(_ context.Context, typ, hash string) (*store.EnlaceCorreoPendiente, error) {
		if typ != "recovery" || hash != "hash" {
			return nil, store.ErrNoExiste
		}
		return &store.EnlaceCorreoPendiente{UserID: consentPersona, Destinatario: "test@example.com", EmailFinal: "test@example.com", Hasta: time.Now().Add(time.Hour)}, nil
	}
	actual, cookie := sesionMFA(t, s, consentPersona, "aal2", 3600)
	_, cookieOtra := sesionMFA(t, s, consentPersona, "aal2", 3600)
	autorizada := postMFA(t, s, cookie, "/cuenta/mfa/autorizar", url.Values{
		"purpose": {"delete"}, "factor_id": {"ultimo"}, "current_password": {"correcta"},
	})
	cookieAutoridad := cookiePorNombre(autorizada, s.nombreCookieAutoridadMFA())
	if autorizada.Code != http.StatusSeeOther || cookieAutoridad == nil || redirectRecuperacion == "" {
		t.Fatalf("no se inició recuperación final: %d cookie=%v redirect=%q", autorizada.Code, cookieAutoridad, redirectRecuperacion)
	}
	if w := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"ultimo"}}, cookieAutoridad); w.Code != http.StatusSeeOther || borrados.Load() != 0 {
		t.Fatalf("la contraseña sola borró el último factor: %d borrados=%d", w.Code, borrados.Load())
	}
	u, err := url.Parse(redirectRecuperacion)
	if err != nil {
		t.Fatal(err)
	}
	intent := u.Query().Get("intent")
	if intent == "" {
		t.Fatal("el correo no quedó ligado a una intención MFA")
	}

	wrong := httptest.NewRequest(http.MethodGet, "/restablecer?intent="+url.QueryEscape(intent), nil)
	wrong.AddCookie(cookieOtra)
	ww := httptest.NewRecorder()
	s.Handler().ServeHTTP(ww, wrong)
	if ww.Code != http.StatusBadRequest {
		t.Fatalf("otra sesión abrió la recuperación: %d", ww.Code)
	}

	confirmada := postMFA(t, s, cookie, "/verificar", url.Values{
		"type": {"recovery"}, "token_hash": {"hash"}, "recovery_intent": {intent}, "email": {"test@example.com"},
	}, cookieAutoridad)
	if confirmada.Code != http.StatusSeeOther || confirmada.Header().Get("Location") != "/cuenta" {
		t.Fatalf("la recuperación no autorizó el borrado: %d %s", confirmada.Code, confirmada.Body.String())
	}
	borrado := postMFA(t, s, cookie, "/cuenta/factor/borrar", url.Values{"factor_id": {"ultimo"}}, cookieAutoridad)
	nueva := cookieSesion(borrado)
	if borrado.Code != http.StatusSeeOther || borrados.Load() != 1 || nueva == nil || nueva.Value == cookie.Value {
		t.Fatalf("la prueba de buzón no completó el borrado: %d borrados=%d cookie=%v", borrado.Code, borrados.Load(), nueva)
	}
	if cargada, err := cargarCookie(s, nueva); err != nil || cargada == nil || cargada.EsAAL2() || cargada.Token() != "recovery-aal1" {
		t.Fatalf("la sesión no quedó rotada en aal1: %+v %v", cargada, err)
	}
	if cargada, err := cargarCookie(s, cookieOtra); err != nil || cargada != nil {
		t.Fatalf("el cambio conservó otra sesión: %+v %v", cargada, err)
	}
	if actual.ID == strings.Split(nueva.Value, ".")[1] {
		t.Fatal("el portador activo no rotó")
	}
}

func TestCapacidadInvitacionNoAutorizaMFADesdeUnaSesion(t *testing.T) {
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: "test@example.com"})
			return
		}
		t.Errorf("la capacidad pre-auth autorizó MFA ante el proveedor: %s %s", r.Method, r.URL)
		http.Error(w, "no", http.StatusInternalServerError)
	})
	a, cookie := sesionMFA(t, s, consentPersona, "aal1", 3600)
	capacidad := httptest.NewRecorder()
	gs := &gotrue.Session{AccessToken: "invite", RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: a.UserID, Email: a.Email}}
	if err := s.emitirCapacidadInvitacionEnAutoridad(capacidad, gs, "aal1", "/cuenta", "Aa1!pendiente", 1, 0, false); err != nil {
		t.Fatal(err)
	}
	cookieInvitacion := cookiePorNombre(capacidad, "__Host-account_password_setup")
	w := postMFA(t, s, cookie, "/cuenta/mfa/autorizar", url.Values{"purpose": {"enroll"}}, cookieInvitacion)
	if cookiePorNombre(w, s.nombreCookieAutoridadMFA()) != nil {
		t.Fatal("la capacidad pre-auth autorizó un cambio MFA desde una sesión normal")
	}
}
