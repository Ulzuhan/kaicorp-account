package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

func servidorMFA(t *testing.T, proveedor http.HandlerFunc) *Server {
	t.Helper()
	st, _ := baseConsentimiento(t)
	falso := httptest.NewServer(proveedor)
	t.Cleanup(falso.Close)
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: u, AdminGroup: "rol"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sesionMFA(t *testing.T, s *Server, uid, aal string, segundos int) (*session.Actual, *http.Cookie) {
	t.Helper()
	gs := &gotrue.Session{AccessToken: "access-" + uid, RefreshToken: "refresh", ExpiresIn: segundos,
		User: gotrue.User{ID: uid, Email: "test@example.com"}}
	w := httptest.NewRecorder()
	a, err := s.ses.Crear(t.Context(), w, httptest.NewRequest(http.MethodGet, "/", nil), gs, aal, false)
	if err != nil {
		t.Fatal(err)
	}
	return a, cookieSesion(w)
}

func postMFA(t *testing.T, s *Server, cookie *http.Cookie, ruta string, form url.Values, extras ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	csrf := httptest.NewRecorder()
	form.Set(session.CSRFField, s.ses.CSRF(csrf, httptest.NewRequest(http.MethodGet, "/", nil), &session.Actual{ID: strings.Split(cookie.Value, ".")[1]}))
	r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", s.cfg.PublicURL.Scheme+"://"+s.cfg.PublicURL.Host)
	r.AddCookie(cookie)
	for _, extra := range extras {
		if extra != nil {
			r.AddCookie(extra)
		}
	}
	r.AddCookie(csrf.Result().Cookies()[0])
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestMFAAltaCierraSesionesSinFactor(t *testing.T) {
	for _, ruta := range []string{"/cuenta/factor/verificar", "/cuenta/passkey/verificar"} {
		t.Run(ruta, func(t *testing.T) {
			var activa atomic.Bool
			s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/user":
					userID := consentPersona
					if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); strings.HasPrefix(token, "access-") {
						userID = strings.TrimPrefix(token, "access-")
					}
					u := gotrue.User{ID: userID}
					if activa.Load() && userID == consentPersona {
						u.Factors = []gotrue.Factor{{FactorType: "totp", Status: "verified"}}
					}
					_ = json.NewEncoder(w).Encode(u)
				case "/factors/factor/challenge":
					_, _ = w.Write([]byte(`{"id":"reto"}`))
				case "/factors/factor/verify":
					activa.Store(true)
					respuestaVerificada(w, consentPersona)
				case "/logout":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("llamada inesperada: %s", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			if err := s.st.Conceder(t.Context(), consentPersona, "rol", "test"); err != nil {
				t.Fatal(err)
			}
			actualSesion, actual := sesionMFA(t, s, consentPersona, "aal1", 3600)
			sesionAnterior, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
			_, verificada := sesionMFA(t, s, consentPersona, "aal2", 3600)
			_, ajena := sesionMFA(t, s, "00000000-0000-4000-8000-000000000099", "aal2", 3600)
			// Un administrador sin MFA sigue pudiendo conceder antes del alta.
			destino := "00000000-0000-4000-8000-000000000042"
			postMFA(t, s, anterior, "/admin/conceder", url.Values{"user_id": {destino}, "grupo": {"rol"}})
			if ok, err := s.st.EsMiembro(t.Context(), destino, "rol"); err != nil || !ok {
				t.Fatal("control legítimo", ok, err)
			}
			autoridad := prepararAltaMFADePrueba(s, actualSesion, ruta)
			w := postMFA(t, s, actual, ruta, url.Values{"factor_id": {"factor"}, "code": {"123456"}, "challenge_id": {"reto"}, "credential": {`{"id":"credencial"}`}}, autoridad)
			nueva := cookieSesion(w)
			if w.Code != http.StatusSeeOther || nueva == nil {
				t.Fatal("alta no completada", w.Code, w.Body.String())
			}
			if _, err := s.st.Sesion(t.Context(), sesionAnterior.ID); !errors.Is(err, store.ErrNoExiste) {
				t.Fatal("el alta dejó la sesión aal1 anterior", err)
			}
			for _, c := range []*http.Cookie{nueva, ajena} {
				if a, err := cargarCookie(s, c); err != nil || a == nil || !a.EsAAL2() {
					t.Fatal("se perdió una sesión legítima", a, err)
				}
			}
			if a, err := cargarCookie(s, verificada); err != nil || a != nil {
				t.Fatal("el cambio MFA conservó otra sesión aal2", a, err)
			}
			// Una respuesta de login iniciada antes del alta tampoco puede publicar
			// una fila después del corte que acompaña la mutación MFA.
			tardia := httptest.NewRecorder()
			_, err := s.ses.Crear(t.Context(), tardia, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
				AccessToken: "login-anterior", RefreshToken: "refresh-anterior", ExpiresIn: 3600,
				User: gotrue.User{ID: consentPersona, Email: "test@example.com"},
			}, "aal2", false)
			if !errors.Is(err, store.ErrCredencialAnterior) || cookieSesion(tardia) != nil {
				t.Fatalf("una entrada anterior se publicó tarde: %v %+v", err, cookieSesion(tardia))
			}
			for _, c := range []*http.Cookie{anterior} {
				destino = "00000000-0000-4000-8000-000000000043"
				w := postMFA(t, s, c, "/admin/conceder", url.Values{"user_id": {destino}, "grupo": {"rol"}})
				// Al invalidarse la sesión también caduca su formulario firmado.
				if w.Code != http.StatusForbidden {
					t.Fatal("sesión sin factor autorizada", w.Code, w.Header())
				}
				if ok, err := s.st.EsMiembro(t.Context(), destino, "rol"); err != nil || ok {
					t.Fatal("se concedió autoridad sin factor", ok, err)
				}
			}
		})
	}
}

func TestMFACargaCompruebaFactoresActuales(t *testing.T) {
	for _, aal := range []string{"aal1"} {
		for _, tipo := range []string{"totp", "webauthn", "otro"} {
			t.Run(aal+"/"+tipo, func(t *testing.T) {
				var estado atomic.Int32
				s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/user" {
						t.Errorf("llamada inesperada: %s", r.URL.Path)
					}
					status := "unverified"
					if estado.Load() == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					if estado.Load() == 2 {
						status = "verified"
					}
					_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Factors: []gotrue.Factor{{FactorType: tipo, Status: status}}})
				})
				a, c := sesionMFA(t, s, consentPersona, aal, 3600)
				if cargada, err := cargarCookie(s, c); cargada == nil || err != nil {
					t.Fatal("el factor no verificado impide el alta", cargada, err)
				}
				estado.Store(1)
				if cargada, err := cargarCookie(s, c); cargada != nil || err == nil {
					t.Fatal("fallo del proveedor no cerró el acceso", cargada, err)
				}
				if _, err := s.st.Sesion(t.Context(), a.ID); err != nil {
					t.Fatal("fallo temporal borró la sesión", err)
				}
				estado.Store(2)
				// Cubre también la activación externa o una promoción local fallida.
				if cargada, err := cargarCookie(s, c); cargada != nil || err != nil {
					t.Fatal("se autorizó el factor activo sin aal2", cargada, err)
				}
			})
		}
	}
}

func TestMFARefreshDuranteActivacion(t *testing.T) {
	inicio, continuar := make(chan struct{}), make(chan struct{})
	var activa atomic.Bool
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			close(inicio)
			<-continuar
			respuestaVerificada(w, consentPersona)
			return
		}
		if r.URL.Path != "/user" {
			t.Errorf("llamada inesperada: %s", r.URL.Path)
		}
		u := gotrue.User{ID: consentPersona}
		if activa.Load() {
			u.Factors = []gotrue.Factor{{Status: "verified"}}
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	_, c := sesionMFA(t, s, consentPersona, "aal1", 1)
	fin := make(chan error, 1)
	go func() {
		a, err := cargarCookie(s, c)
		if a != nil {
			err = errors.New("refresh autorizó la sesión sin factor")
		}
		fin <- err
	}()
	select {
	case <-inicio:
	case <-time.After(5 * time.Second):
		close(continuar)
		t.Fatal("no se inició el refresh")
	}
	activa.Store(true)
	close(continuar)
	if err := <-fin; err != nil {
		t.Fatal(err)
	}
}

func TestMFACargaDurantePromocion(t *testing.T) {
	inicio, continuar := make(chan struct{}), make(chan struct{})
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		close(inicio)
		<-continuar
		// La consulta empezó antes del alta y responde con la ficha anterior.
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
	})
	a, _ := sesionMFA(t, s, consentPersona, "aal1", 3600)
	_, anterior := sesionMFA(t, s, consentPersona, "aal1", 3600)
	fin := make(chan error, 1)
	go func() {
		cargada, err := cargarCookie(s, anterior)
		if cargada != nil {
			err = errors.New("la carga devolvió una sesión eliminada durante el alta")
		}
		fin <- err
	}()
	select {
	case <-inicio:
	case <-time.After(5 * time.Second):
		close(continuar)
		t.Fatal("no se consultaron los factores")
	}
	err := s.ses.Promover(context.Background(), httptest.NewRecorder(), a, &gotrue.Session{AccessToken: "nuevo", RefreshToken: "nuevo", ExpiresIn: 3600,
		User: gotrue.User{ID: consentPersona}})
	close(continuar)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-fin; err != nil {
		t.Fatal(err)
	}
}
