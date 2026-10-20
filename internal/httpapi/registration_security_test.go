package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

func TestRegistroNoPersistePasswordElegidaYNormalizaRespuestaDelProveedor(t *testing.T) {
	var llamadas atomic.Int32
	var mu sync.Mutex
	var passwords []string
	var redirecciones []string
	s := servidorEnlaceSinStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/signup" || r.Method != http.MethodPost {
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			return
		}
		var cuerpo struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&cuerpo); err != nil {
			t.Errorf("signup inválido: %v", err)
			return
		}
		mu.Lock()
		passwords = append(passwords, cuerpo.Password)
		redirecciones = append(redirecciones, r.URL.Query().Get("redirect_to"))
		mu.Unlock()
		switch llamadas.Add(1) {
		case 2:
			http.Error(w, `{"error_code":"weak_password","msg":"common password"}`, http.StatusUnprocessableEntity)
			return
		case 3:
			http.Error(w, `{"error_code":"signup_disabled","msg":"closed"}`, http.StatusBadRequest)
			return
		case 4:
			http.Error(w, `{"error_code":"email_exists","msg":"already registered"}`, http.StatusBadRequest)
			return
		case 5:
			http.Error(w, `{"error_code":"over_request_rate_limit","msg":"wait"}`, http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"id":"pendiente"}`))
	})

	post := func() *httptest.ResponseRecorder {
		form := url.Values{
			"name":      {"Victim"},
			"email":     {"victim@example.com"},
			"password":  {"attacker-chosen-password"},
			"password2": {"attacker-chosen-password"},
		}
		r := httptest.NewRequest(http.MethodPost, "/registro", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.registroPOST(w, r)
		return w
	}
	respuestas := []*httptest.ResponseRecorder{post(), post(), post(), post(), post()}
	normalizarCSRF := regexp.MustCompile(`name="_csrf" value="[^"]*"`)
	esperada := normalizarCSRF.ReplaceAllString(respuestas[0].Body.String(), `name="_csrf" value="csrf"`)
	for i, respuesta := range respuestas {
		if respuesta.Code != http.StatusOK {
			t.Fatalf("respuesta %d distinguible por status: %d", i, respuesta.Code)
		}
		cuerpo := normalizarCSRF.ReplaceAllString(respuesta.Body.String(), `name="_csrf" value="csrf"`)
		if cuerpo != esperada {
			t.Fatalf("respuesta %d del proveedor hizo distinguible la cuenta", i)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(passwords) != len(respuestas) {
		t.Fatalf("passwords enviados: %d", len(passwords))
	}
	vistos := make(map[string]struct{}, len(passwords))
	for _, p := range passwords {
		if p == "attacker-chosen-password" || len(p) < 52 || !strings.HasPrefix(p, "Aa1!") {
			t.Fatalf("credencial pendiente insegura: %q", p)
		}
		if _, repetida := vistos[p]; repetida {
			t.Fatal("dos altas reutilizaron la misma credencial pendiente")
		}
		vistos[p] = struct{}{}
	}
	if len(redirecciones) != len(respuestas) {
		t.Fatalf("redirecciones enviadas: %d", len(redirecciones))
	}
	for i, raw := range redirecciones {
		u, err := url.Parse(raw)
		if err != nil || u.Path != "/verificar" || u.Query().Get("next") != "/" {
			t.Fatalf("redirección de alta insegura: %q %v", raw, err)
		}
		p, ok := s.validarIntencionRegistro(u.Query().Get("setup"), "victim@example.com")
		if !ok || p != passwords[i] {
			t.Fatal("el correo no quedó ligado a su credencial aleatoria sellada")
		}
	}
}

func TestFormularioRegistroNoPidePasswordAntesDelCorreo(t *testing.T) {
	s := servidorEnlaceSinStore(t, func(http.ResponseWriter, *http.Request) {})
	w := httptest.NewRecorder()
	s.registroGET(w, httptest.NewRequest(http.MethodGet, "/registro", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("registro: %d", w.Code)
	}
	cuerpo := w.Body.String()
	if strings.Contains(cuerpo, `name="password"`) || strings.Contains(cuerpo, `name="password2"`) {
		t.Fatal("el registro pidió una contraseña antes de confirmar el buzón")
	}
	if !strings.Contains(cuerpo, "Send confirmation") {
		t.Fatal("el formulario no explica el siguiente paso")
	}
}

func TestFalloDeRotacionBloqueaLaCuentaConfirmada(t *testing.T) {
	const userID = "00000000-0000-4000-8000-000000000079"
	var bloqueos atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/admin/users/"+userID || r.Header.Get("Authorization") != "Bearer service-test" {
			t.Fatalf("llamada inesperada: %s %s %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
		var cuerpo map[string]string
		if err := json.NewDecoder(r.Body).Decode(&cuerpo); err != nil {
			t.Fatal(err)
		}
		if cuerpo["password"] != "" {
			http.Error(w, `{"msg":"storage unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		if cuerpo["ban_duration"] != "876000h" {
			t.Fatalf("bloqueo inesperado: %v", cuerpo)
		}
		bloqueos.Add(1)
		_, _ = w.Write([]byte(`{"id":"` + userID + `"}`))
	}))
	defer falso.Close()
	s := &Server{gt: gotrue.New(falso.URL, "anon-test", "service-test")}
	gs := &gotrue.Session{AccessToken: "confirmada", User: gotrue.User{ID: userID, Email: "victim@example.com"}}
	if _, _, err := s.rotarPasswordPendiente(t.Context(), gs); err == nil || !strings.Contains(err.Error(), "cuenta bloqueada") {
		t.Fatalf("fallo no cerrado: %v", err)
	}
	if bloqueos.Load() != 1 {
		t.Fatalf("bloqueos: %d", bloqueos.Load())
	}
}

func TestReentradaNoProbadaBloqueaLaCuentaConfirmada(t *testing.T) {
	const userID = "00000000-0000-4000-8000-000000000078"
	var bloqueos atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/admin/users/"+userID:
			var cuerpo map[string]string
			if err := json.NewDecoder(r.Body).Decode(&cuerpo); err != nil {
				t.Fatal(err)
			}
			if cuerpo["ban_duration"] == "876000h" {
				bloqueos.Add(1)
				_, _ = w.Write([]byte(`{"id":"` + userID + `"}`))
				return
			}
			if cuerpo["password"] == "" {
				t.Fatalf("rotación inesperada: %v", cuerpo)
			}
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: userID, Email: "victim@example.com"})
		case r.URL.Path == "/token":
			http.Error(w, `{"error_code":"invalid_credentials","msg":"not installed"}`, http.StatusBadRequest)
		default:
			t.Fatalf("llamada inesperada: %s %s", r.Method, r.URL)
		}
	}))
	defer falso.Close()
	s := &Server{gt: gotrue.New(falso.URL, "anon-test", "service-test")}
	gs := &gotrue.Session{AccessToken: "confirmada", User: gotrue.User{ID: userID, Email: "victim@example.com"}}
	if _, _, err := s.rotarPasswordPendiente(t.Context(), gs); err == nil || !strings.Contains(err.Error(), "cuenta bloqueada") {
		t.Fatalf("reentrada no cerrada: %v", err)
	}
	if bloqueos.Load() != 1 {
		t.Fatalf("bloqueos: %d", bloqueos.Load())
	}
}

func TestEnlaceSignupAntiguoSeRechazaAntesDeConfirmar(t *testing.T) {
	var llamadas atomic.Int32
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llamadas.Add(1)
		t.Fatalf("llamada inesperada: %s %s", r.Method, r.URL)
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "service-test")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, nil, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica}, nil, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verificar?type=signup&token_hash=legacy", nil))
	if w.Code != http.StatusSeeOther || strings.Contains(w.Header().Get("Location"), "legacy") || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("el enlace antiguo no se redaccionó: %d %q", w.Code, w.Header().Get("Location"))
	}
	if llamadas.Load() != 0 {
		t.Fatalf("el enlace antiguo llegó al proveedor: %d llamadas", llamadas.Load())
	}
}

func TestConfirmacionSignupUsaPasswordSelladaYLaSesionNaceTrasElegirLaFinal(t *testing.T) {
	st, _ := baseConsentimiento(t)
	const (
		userID            = "00000000-0000-4000-8000-000000000071"
		email             = "victim@example.com"
		passwordAtacante  = "attacker-chosen-password"
		passwordPendiente = "Aa1!0123456789abcdef0123456789abcdef0123456789abcdef"
		passwordVictima   = "victim-final-password"
	)
	passwordActual := passwordPendiente
	confirmada := false
	signupToken := tokenPruebaIAT(time.Now().Unix() + 30)
	var mu sync.Mutex
	var cambios []string
	falso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/verify":
			confirmada = true
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: signupToken, RefreshToken: "signup-refresh", ExpiresIn: 3600,
				User: gotrue.User{ID: userID, Email: email}})
		case r.URL.Path == "/admin/users/"+userID && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer service-test" {
				http.Error(w, `{"msg":"bad service token"}`, http.StatusUnauthorized)
				return
			}
			var cuerpo struct {
				Password string `json:"password"`
			}
			if json.NewDecoder(r.Body).Decode(&cuerpo) != nil || cuerpo.Password == "" {
				http.Error(w, `{"msg":"bad password"}`, http.StatusBadRequest)
				return
			}
			mu.Lock()
			passwordActual = cuerpo.Password
			cambios = append(cambios, cuerpo.Password)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: userID, Email: email})
		case r.URL.Path == "/user" && r.Method == http.MethodPut:
			if r.Header.Get("Authorization") != "Bearer "+signupToken {
				http.Error(w, `{"msg":"bad token"}`, http.StatusUnauthorized)
				return
			}
			var cuerpo struct {
				Password        string `json:"password"`
				CurrentPassword string `json:"current_password"`
			}
			mu.Lock()
			actual := passwordActual
			mu.Unlock()
			if json.NewDecoder(r.Body).Decode(&cuerpo) != nil || cuerpo.Password == "" || cuerpo.CurrentPassword != actual {
				http.Error(w, `{"msg":"bad password"}`, http.StatusBadRequest)
				return
			}
			mu.Lock()
			passwordActual = cuerpo.Password
			cambios = append(cambios, cuerpo.Password)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: userID, Email: email})
		case r.URL.Path == "/token":
			var cuerpo map[string]string
			_ = json.NewDecoder(r.Body).Decode(&cuerpo)
			mu.Lock()
			aceptada := confirmada && cuerpo["email"] == email && cuerpo["password"] == passwordActual
			mu.Unlock()
			if !aceptada {
				http.Error(w, `{"error_code":"invalid_credentials","msg":"bad"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Unix() + 60), RefreshToken: "login-refresh", ExpiresIn: 3600,
				User: gotrue.User{ID: userID, Email: email}})
		case r.URL.Path == "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("llamada inesperada: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer falso.Close()
	gt := gotrue.New(falso.URL, "anon-test", "service-test")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publica, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publica, AdminGroup: "rol"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.resolverEnlaceCorreo = func(_ context.Context, typ, hash string) (*store.EnlaceCorreoPendiente, error) {
		if typ != "signup" || hash != "signup-hash" {
			return nil, store.ErrNoExiste
		}
		return &store.EnlaceCorreoPendiente{UserID: userID, Destinatario: email, EmailFinal: email, Hasta: time.Now().Add(time.Hour)}, nil
	}

	form, cookies := abrirConfirmacion(t, s, agregarQueryEnlace(t,
		rutaRegistroPrueba(t, s, "signup-hash", email, passwordPendiente), url.Values{"next": {"/welcome"}}))
	form.Set("email", email)
	w := enviarConfirmacion(s, form, cookies, true)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != rutaPasswordRegistro {
		t.Fatalf("confirmación: %d %s", w.Code, w.Header().Get("Location"))
	}
	if cookieSesion(w) != nil {
		t.Fatal("la confirmación publicó una sesión antes del password final")
	}
	filas, err := st.SesionesDe(t.Context(), userID)
	if err != nil || len(filas) != 0 {
		t.Fatalf("sesiones antes del password: %d %v", len(filas), err)
	}
	mu.Lock()
	if len(cambios) != 0 {
		mu.Unlock()
		t.Fatalf("la confirmación volvió a rotar la credencial ya sellada: %v", cambios)
	}
	mu.Unlock()
	if _, err := s.gt.Login(t.Context(), email, passwordAtacante); !errors.Is(err, gotrue.ErrInvalidLogin) {
		t.Fatalf("el password atacante siguió funcionando: %v", err)
	}

	var capacidad *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-account_signup_setup" {
			capacidad = c
		}
	}
	if capacidad == nil || capacidad.Path != "/" || capacidad.Domain != "" || capacidad.MaxAge != 300 || !capacidad.HttpOnly || !capacidad.Secure {
		t.Fatalf("capacidad signup incorrecta: %+v", capacidad)
	}
	post := func() *httptest.ResponseRecorder {
		v := url.Values{"password": {passwordVictima}, "password2": {passwordVictima}}
		r := httptest.NewRequest(http.MethodPost, rutaPasswordRegistro, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(capacidad)
		w := httptest.NewRecorder()
		s.registroPasswordPOST(w, r)
		return w
	}
	w = post()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/welcome" || cookieSesion(w) == nil {
		t.Fatalf("alta final: status=%d location=%q session=%v", w.Code, w.Header().Get("Location"), cookieSesion(w))
	}
	mu.Lock()
	if len(cambios) != 1 || cambios[0] != passwordVictima {
		mu.Unlock()
		t.Fatalf("password final incorrecto: %v", cambios)
	}
	mu.Unlock()
	if _, err := s.gt.Login(t.Context(), email, passwordVictima); err != nil {
		t.Fatalf("el password final no funciona: %v", err)
	}
	post()
	mu.Lock()
	defer mu.Unlock()
	if len(cambios) != 1 {
		t.Fatalf("la capacidad se reutilizó: %v", cambios)
	}
}
