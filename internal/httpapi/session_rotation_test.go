package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

// Estas pruebas necesitan una base PostgreSQL desechable con el esquema account
// vacío; ACCOUNT_TEST_DATABASE_URL nunca debe apuntar a la base de despliegue.
func servidorConSesiones(t *testing.T, proveedor http.HandlerFunc) *Server {
	t.Helper()
	dsn := os.Getenv("ACCOUNT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCOUNT_TEST_DATABASE_URL no configurada")
	}
	st, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.CheckMigrations(t.Context()); err != nil {
		t.Fatal(err)
	}
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
			return
		}
		proveedor(w, r)
	}))
	t.Cleanup(falso.Close)
	gt := gotrue.New(falso.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, 12*time.Hour, 30*24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: u}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sesionDePrueba(t *testing.T, s *Server, recordar bool, aal string, segundos int) (*session.Actual, *http.Cookie) {
	t.Helper()
	gs := &gotrue.Session{AccessToken: "access-" + consentPersona, RefreshToken: "refresh-anterior", ExpiresIn: segundos,
		User: gotrue.User{ID: consentPersona, Email: "test@example.com", UserMetadata: map[string]any{"name": "Test"}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "navegador de prueba")
	a, err := s.ses.Crear(t.Context(), w, r, gs, aal, recordar)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.st.BorrarSesionesDe(context.Background(), a.UserID, "") })
	return a, cookieSesion(w)
}

func cookieSesion(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

func cargarCookie(s *Server, c *http.Cookie) (*session.Actual, error) {
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(c)
	return s.ses.Cargar(r.Context(), httptest.NewRecorder(), r)
}

func peticionFactor(s *Server, ruta string, a *session.Actual) *http.Request {
	form := url.Values{"factor_id": {"factor"}, "challenge_id": {"reto"}, "code": {"123456"}, "credential": {`{"id":"credencial"}`}}
	r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(prepararAltaMFADePrueba(s, a, ruta))
	return r.WithContext(context.WithValue(r.Context(), claveSesion, a))
}

func respuestaVerificada(w http.ResponseWriter, userIDs ...string) {
	var userID string
	if len(userIDs) > 0 {
		userID = userIDs[0]
	} else {
		userID = consentPersona
	}
	_ = json.NewEncoder(w).Encode(&gotrue.Session{AccessToken: "verificado-aal2", RefreshToken: "refresh-verificado", ExpiresIn: 3600,
		User: gotrue.User{ID: userID, Email: "test@example.com"}})
}

func TestAltaFactorRotaSesion(t *testing.T) {
	for _, ruta := range []string{"/cuenta/factor/verificar", "/cuenta/passkey/verificar"} {
		for _, aal := range []string{"aal1", "aal2"} {
			for _, recordar := range []bool{false, true} {
				t.Run(ruta+"/"+aal+"/recordar="+map[bool]string{false: "no", true: "si"}[recordar], func(t *testing.T) {
					s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
						switch r.URL.Path {
						case "/factors/factor/challenge":
							_, _ = w.Write([]byte(`{"id":"reto"}`))
						case "/factors/factor/verify":
							respuestaVerificada(w)
						default:
							t.Errorf("llamada inesperada: %s", r.URL.Path)
							http.Error(w, "inesperada", 500)
						}
					})
					a, vieja := sesionDePrueba(t, s, recordar, aal, 3600)
					antes, err := s.st.Sesion(t.Context(), a.ID)
					if err != nil {
						t.Fatal(err)
					}
					s.enrolando.Store(a.ID, enrolamiento{hasta: time.Now().Add(time.Minute)})
					// Se atraviesan el enrutador, la carga de sesión y CSRF reales.
					r := peticionFactor(s, ruta, a)
					r.AddCookie(vieja)
					csrf := httptest.NewRecorder()
					campo := s.ses.CSRF(csrf, httptest.NewRequest(http.MethodGet, "/cuenta", nil), a)
					r.Header.Set("Origin", s.cfg.PublicURL.Scheme+"://"+s.cfg.PublicURL.Host)
					r.AddCookie(csrf.Result().Cookies()[0])
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					r.PostForm.Set(session.CSRFField, campo)
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, r)
					if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cuenta" {
						t.Fatalf("verificar: %d %s", w.Code, w.Body.String())
					}
					if actual, err := cargarCookie(s, vieja); err != nil || actual != nil {
						t.Fatalf("la cookie copiada sigue autenticada: %+v %v", actual, err)
					}
					nueva := cookieSesion(w)
					if nueva == nil || nueva.Value == vieja.Value {
						t.Fatalf("no se renovó el portador: %+v", nueva)
					}
					if !nueva.Expires.Equal(vieja.Expires) || !nueva.HttpOnly || !nueva.Secure || nueva.Path != "/" || nueva.SameSite != http.SameSiteLaxMode {
						t.Fatalf("cambió la política de cookie: %+v", nueva)
					}
					actual, err := cargarCookie(s, nueva)
					if err != nil || actual == nil || actual.AAL != "aal2" || actual.Token() != "verificado-aal2" {
						t.Fatalf("la cookie nueva no carga los tokens verificados: %+v %v", actual, err)
					}
					despues, err := s.st.Sesion(t.Context(), actual.ID)
					if err != nil {
						t.Fatal(err)
					}
					if !despues.Expira.Equal(antes.Expira) || !despues.Creada.Equal(antes.Creada) || despues.Agente != antes.Agente || despues.UserID != antes.UserID || despues.Email != antes.Email || despues.Nombre != antes.Nombre {
						t.Fatal("se perdió metadata o se alargó la sesión")
					}
					if _, ok := s.enrolando.Load(antes.ID); ok {
						t.Fatal("el alta quedó bajo el identificador anterior")
					}
				})
			}
		}
	}
}

func TestRefreshConservaSesion(t *testing.T) {
	for _, aal := range []string{"aal1", "aal2"} {
		t.Run(aal, func(t *testing.T) {
			s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/token" || r.URL.Query().Get("grant_type") != "refresh_token" {
					t.Errorf("llamada inesperada: %s", r.URL)
				}
				respuestaVerificada(w)
			})
			a, cookie := sesionDePrueba(t, s, false, aal, 1)
			actual, err := cargarCookie(s, cookie)
			if err != nil || actual == nil || actual.ID != a.ID || actual.AAL != aal || actual.Token() != "verificado-aal2" || !actual.Expira.Equal(a.Expira) {
				t.Fatalf("refresh alteró el portador o su política: %+v %v", actual, err)
			}
		})
	}
}

func TestRefreshAnteriorNoHeredaPromocion(t *testing.T) {
	iniciado, continuar := make(chan struct{}), make(chan struct{})
	s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			close(iniciado)
			<-continuar
		}
		respuestaVerificada(w)
	})
	a, vieja := sesionDePrueba(t, s, false, "aal1", 1)
	idAnterior := a.ID
	type resultado struct {
		a      *session.Actual
		err    error
		cookie *http.Cookie
	}
	hecho := make(chan resultado, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
		r.AddCookie(vieja)
		w := httptest.NewRecorder()
		a, err := s.ses.Cargar(r.Context(), w, r)
		hecho <- resultado{a, err, cookieSesion(w)}
	}()
	select {
	case <-iniciado:
	case <-time.After(5 * time.Second):
		close(continuar)
		t.Fatal("no se inició el refresh")
	}
	w := httptest.NewRecorder()
	s.passkeyVerificar(w, peticionFactor(s, "/cuenta/passkey/verificar", a))
	close(continuar)
	r := <-hecho
	if r.a != nil || r.err != nil {
		t.Fatalf("el refresh anterior devolvió autoridad tras la rotación: %+v %v", r.a, r.err)
	}
	if r.cookie != nil {
		t.Fatal("el refresh anterior sobrescribió la cookie de promoción")
	}
	if nueva := cookieSesion(w); nueva == nil || nueva.Value == vieja.Value {
		t.Fatal("la verificación no renovó la cookie")
	}
	if _, err := s.st.Sesion(t.Context(), idAnterior); !errors.Is(err, store.ErrNoExiste) {
		t.Fatalf("se resucitó la sesión anterior: %v", err)
	}
}

func TestPromocionesConcurrentes(t *testing.T) {
	entradas, continuar := make(chan struct{}, 2), make(chan struct{})
	s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
		entradas <- struct{}{}
		<-continuar
		respuestaVerificada(w)
	})
	a, vieja := sesionDePrueba(t, s, false, "aal1", 3600)
	copia := *a
	hecho := make(chan *httptest.ResponseRecorder, 2)
	for _, actual := range []*session.Actual{a, &copia} {
		go func() {
			w := httptest.NewRecorder()
			s.passkeyVerificar(w, peticionFactor(s, "/cuenta/passkey/verificar", actual))
			hecho <- w
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entradas:
		case <-time.After(5 * time.Second):
			close(continuar)
			t.Fatal("no llegaron las dos verificaciones")
		}
	}
	close(continuar)
	ganadoras := 0
	for i := 0; i < 2; i++ {
		w := <-hecho
		if c := cookieSesion(w); c != nil {
			ganadoras++
			if c.Value == vieja.Value || w.Code != http.StatusSeeOther {
				t.Fatalf("promoción inválida: %d %+v", w.Code, c)
			}
		} else if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("la promoción perdedora anunció éxito: %d", w.Code)
		}
	}
	if ganadoras != 1 {
		t.Fatalf("se entregaron %d portadores nuevos", ganadoras)
	}
	if actual, err := cargarCookie(s, vieja); actual != nil || err != nil {
		t.Fatalf("la cookie anterior sigue viva: %+v %v", actual, err)
	}
}

func TestPromocionRechazaCaducadaYColision(t *testing.T) {
	s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) { respuestaVerificada(w) })
	a, vieja := sesionDePrueba(t, s, false, "aal1", 3600)
	ocupada, _ := sesionDePrueba(t, s, false, "aal1", 3600)
	if _, err := s.st.PromoverSesion(t.Context(), a.ID, ocupada.ID, []byte("access"), []byte("refresh"), time.Now()); err == nil {
		t.Fatal("una colisión no debe sobrescribir otra sesión")
	}
	if actual, err := cargarCookie(s, vieja); err != nil || actual == nil || actual.Token() != "anterior" {
		t.Fatalf("la escritura fallida alteró la sesión original: %+v %v", actual, err)
	}
	x, err := s.st.Sesion(t.Context(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.BorrarSesion(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	x.Expira = time.Now().Add(-time.Minute)
	if err := s.st.CrearSesion(t.Context(), x); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.passkeyVerificar(w, peticionFactor(s, "/cuenta/passkey/verificar", a))
	if w.Code != http.StatusServiceUnavailable || cookieSesion(w) != nil || a.Token() != "anterior" {
		t.Fatalf("se promovió una sesión caducada: %d %+v", w.Code, a)
	}
}

func TestAltaFactorNoResucitaSesion(t *testing.T) {
	for _, ruta := range []string{"/cuenta/factor/verificar", "/cuenta/passkey/verificar"} {
		t.Run(ruta, func(t *testing.T) {
			var antesDeVerificar func()
			s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/challenge") {
					_, _ = w.Write([]byte(`{"id":"reto"}`))
					return
				}
				antesDeVerificar()
				respuestaVerificada(w)
			})
			a, _ := sesionDePrueba(t, s, false, "aal1", 3600)
			antesDeVerificar = func() {
				if err := s.st.BorrarSesion(context.Background(), a.ID); err != nil {
					t.Error(err)
				}
			}
			w := httptest.NewRecorder()
			if strings.Contains(ruta, "passkey") {
				s.passkeyVerificar(w, peticionFactor(s, ruta, a))
			} else {
				s.factorVerificar(w, peticionFactor(s, ruta, a))
			}
			if w.Code != http.StatusServiceUnavailable || cookieSesion(w) != nil || a.Token() != "anterior" || a.AAL != "aal1" {
				t.Fatalf("la sesión revocada pareció promovida: %d %+v %+v", w.Code, cookieSesion(w), a)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == cookieFlash && c.Value != "" {
					t.Fatal("se anunció éxito tras fallar la persistencia")
				}
			}
		})
	}
}

func TestCierreConcurrenteConPromocion(t *testing.T) {
	for _, scope := range []string{"local", "others"} {
		t.Run(scope, func(t *testing.T) {
			iniciado, continuar := make(chan struct{}), make(chan struct{})
			s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/logout" {
					if r.URL.Query().Get("scope") != scope {
						t.Errorf("scope inesperado: %s", r.URL)
					}
					close(iniciado)
					<-continuar
					w.WriteHeader(http.StatusNoContent)
					return
				}
				respuestaVerificada(w)
			})
			a, _ := sesionDePrueba(t, s, false, "aal1", 3600)
			// El alta conserva otras sesiones que ya pasaron un factor.
			otraSesion, otra := sesionDePrueba(t, s, false, "aal2", 3600)
			// Otra sesión de la misma persona, no de otra cuenta.
			x, err := s.st.Sesion(t.Context(), otraSesion.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.st.BorrarSesion(t.Context(), x.ID); err != nil {
				t.Fatal(err)
			}
			x.UserID = a.UserID
			if err := s.st.CrearSesion(t.Context(), x); err != nil {
				t.Fatal(err)
			}
			copia := *a
			hecho := make(chan struct{})
			go func() {
				w := httptest.NewRecorder()
				if scope == "local" {
					s.ses.Cerrar(context.Background(), w, &copia)
				} else {
					s.sesionesCerrar(w, peticionFactor(s, "/cuenta/sesiones/cerrar", &copia))
				}
				close(hecho)
			}()
			select {
			case <-iniciado:
			case <-time.After(5 * time.Second):
				close(continuar)
				t.Fatal("no se inició el cierre")
			}
			w := httptest.NewRecorder()
			s.passkeyVerificar(w, peticionFactor(s, "/cuenta/passkey/verificar", a))
			close(continuar)
			<-hecho
			nueva := cookieSesion(w)
			if nueva == nil {
				t.Fatal("no hubo promoción")
			}
			actual, err := cargarCookie(s, nueva)
			if err != nil || (actual != nil) != (scope == "others") {
				t.Fatalf("el cierre %s perdió la identidad de la sesión promovida: %+v %v", scope, actual, err)
			}
			if otraActual, err := cargarCookie(s, otra); err != nil || (otraActual != nil) != (scope == "local") {
				t.Fatalf("el cierre %s alteró otras sesiones incorrectamente: %+v %v", scope, otraActual, err)
			}
		})
	}
}

func TestRefreshRechazadoNoBorraCookiePromovida(t *testing.T) {
	iniciado, continuar := make(chan struct{}), make(chan struct{})
	s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			close(iniciado)
			<-continuar
			http.Error(w, `{"error_code":"refresh_token_not_found"}`, http.StatusUnauthorized)
			return
		}
		respuestaVerificada(w)
	})
	a, vieja := sesionDePrueba(t, s, false, "aal1", 1)
	hecho := make(chan *http.Cookie, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
		r.AddCookie(vieja)
		w := httptest.NewRecorder()
		actual, err := s.ses.Cargar(r.Context(), w, r)
		if actual != nil || err != nil {
			t.Errorf("refresh rechazado: %+v %v", actual, err)
		}
		hecho <- cookieSesion(w)
	}()
	select {
	case <-iniciado:
	case <-time.After(5 * time.Second):
		close(continuar)
		t.Fatal("no se inició el refresh")
	}
	w := httptest.NewRecorder()
	s.passkeyVerificar(w, peticionFactor(s, "/cuenta/passkey/verificar", a))
	close(continuar)
	if c := <-hecho; c != nil {
		t.Fatalf("la respuesta vieja borró la cookie nueva: %+v", c)
	}
	nueva := cookieSesion(w)
	if nueva == nil {
		t.Fatal("no hubo promoción")
	}
	if actual, err := cargarCookie(s, nueva); actual == nil || err != nil {
		t.Fatalf("se borró la sesión promovida: %+v %v", actual, err)
	}
}
