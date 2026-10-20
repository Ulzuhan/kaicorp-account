package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/correo"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
)

type respuestaCambioCorreo struct {
	status   int
	location string
	flash    string
	cookie   string
	body     string
}

type envioCambioCorreo struct {
	actual, propuesta string
	datos             correo.CambioCorreo
}

type remitenteCambioCorreo struct {
	envios chan envioCambioCorreo
}

func (r *remitenteCambioCorreo) EnviarAcceso(context.Context, string, correo.Acceso) error {
	return nil
}

func (r *remitenteCambioCorreo) EnviarCambioCorreo(_ context.Context, actual, propuesta string, datos correo.CambioCorreo) error {
	r.envios <- envioCambioCorreo{actual: actual, propuesta: propuesta, datos: datos}
	return nil
}

func respuestaDeCambio(w *httptest.ResponseRecorder) respuestaCambioCorreo {
	out := respuestaCambioCorreo{status: w.Code, location: w.Header().Get("Location"), body: w.Body.String()}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieFlash {
			out.flash = c.Value
			out.cookie = c.String()
		}
	}
	return out
}

func capacidadFragmentoPrueba(t *testing.T, u *url.URL, nombre string) string {
	t.Helper()
	if u.Query().Has(nombre) {
		t.Fatalf("la capacidad %s apareció en la query: %s", nombre, u.String())
	}
	valores, err := url.ParseQuery(u.Fragment)
	if err != nil || len(valores[nombre]) != 1 || valores.Get(nombre) == "" {
		t.Fatalf("fragmento de capacidad inválido: %q %v", u.Fragment, err)
	}
	return valores.Get(nombre)
}

func TestCambioCorreoNoDistingueDireccionOcupada(t *testing.T) {
	var llamadas atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/user" {
			userID := strings.TrimPrefix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "access-")
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: userID, Email: "test@example.com"})
			return
		}
		llamadas.Add(1)
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if body["email"] == "ocupada@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"code":422,"error_code":"email_exists","msg":"A user with this email address has already been registered"}`))
			return
		}
		if body["email"] == "fallo@example.com" {
			http.Error(w, `{"code":503,"error_code":"provider_unavailable","msg":"diagnóstico interno"}`, http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona, Email: body["email"]})
	})
	remitente := &remitenteCambioCorreo{envios: make(chan envioCambioCorreo, 4)}
	s.correo = remitente
	_, cookieSesion := sesionMFA(t, s, consentPersona, "aal2", 3600)

	iniciar := func(email string) respuestaCambioCorreo {
		return respuestaDeCambio(postMFA(t, s, cookieSesion, "/cuenta/correo", url.Values{"email": {email}}))
	}

	direcciones := []string{"disponible@example.com", "ocupada@example.com", "fallo@example.com"}
	respuestas := map[string]respuestaCambioCorreo{}
	for _, email := range direcciones {
		respuestas[email] = iniciar(email)
	}
	base := respuestas[direcciones[0]]
	for _, email := range direcciones[1:] {
		if respuestas[email] != base {
			t.Fatalf("el inicio revela el estado de %s\nbase: %+v\nactual: %+v", email, base, respuestas[email])
		}
	}
	if llamadas.Load() != 0 {
		t.Fatalf("el inicio consultó al proveedor %d veces antes de probar el buzón propuesto", llamadas.Load())
	}
	if base.status != http.StatusSeeOther || base.location != "/cuenta" || base.body != "" {
		t.Fatalf("acuse genérico inesperado: %+v", base)
	}
	for _, atributo := range []string{"Path=/", "Max-Age=120", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(base.cookie, atributo) {
			t.Fatalf("cookie flash sin %s: %s", atributo, base.cookie)
		}
	}
	mensaje, err := url.QueryUnescape(base.flash)
	if err != nil || mensaje != mensajeCambioCorreo {
		t.Fatalf("flash genérico inesperado: %q %v", base.flash, err)
	}
	for _, secreto := range []string{"test@example.com", "disponible@example.com", "ocupada@example.com", "fallo@example.com", "belongs to", "already registered", "diagnóstico interno"} {
		if strings.Contains(strings.ToLower(mensaje), strings.ToLower(secreto)) {
			t.Fatalf("el acuse revela %q: %q", secreto, mensaje)
		}
	}

	envios := map[string]envioCambioCorreo{}
	for range direcciones {
		select {
		case envio := <-remitente.envios:
			envios[envio.propuesta] = envio
		case <-time.After(2 * time.Second):
			t.Fatal("no llegó el envío privado del cambio")
		}
	}
	for _, email := range direcciones {
		envio, ok := envios[email]
		if !ok || envio.actual != "test@example.com" {
			t.Fatalf("envío inesperado para %s: %+v", email, envio)
		}
		confirmar, err := url.Parse(envio.datos.Confirmar)
		if err != nil || confirmar.Scheme != "https" || confirmar.Host != "account.example.com" || confirmar.Path != "/cuenta/correo/confirmar" {
			t.Fatalf("enlace de prueba inválido para %s: %q (%v)", email, envio.datos.Confirmar, err)
		}
		if strings.Contains(envio.datos.Confirmar, email) || strings.Contains(envio.datos.Confirmar, envio.actual) {
			t.Fatalf("el enlace opaco contiene una dirección: %s", envio.datos.Confirmar)
		}
		token := capacidadFragmentoPrueba(t, confirmar, "token")
		clave, ok := claveCambioCorreo(token)
		if !ok {
			t.Fatalf("token no opaco para %s: %q", email, token)
		}
		if _, existe := s.cambiosCorreo.Load(token); existe {
			t.Fatal("el servidor guardó el token en claro")
		}
		if _, existe := s.cambiosCorreo.Load(clave); !existe {
			t.Fatal("el servidor no guardó la huella de la capacidad")
		}

		get := httptest.NewRequest(http.MethodGet, confirmar.RequestURI(), nil)
		get.AddCookie(cookieSesion)
		wGet := httptest.NewRecorder()
		s.Handler().ServeHTTP(wGet, get)
		if wGet.Code != http.StatusOK || llamadas.Load() != 0 || wGet.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("GET tuvo efecto: status=%d proveedor=%d", wGet.Code, llamadas.Load())
		}
		if strings.Contains(wGet.Body.String(), email) || strings.Contains(wGet.Body.String(), token) || !strings.Contains(wGet.Body.String(), "/static/js/email-link.js?") {
			t.Fatalf("GET reflejó datos o no cargó el traslado seguro para %s", email)
		}
	}

	// Un token de formato válido que nunca fue emitido pinta la misma página y
	// no revela por GET si hay una capacidad almacenada.
	desconocido := strings.Repeat("a", 64)
	wDesconocido := httptest.NewRecorder()
	rDesconocido := peticionEnlace(t, http.MethodGet, "/cuenta/correo/confirmar#token="+desconocido)
	rDesconocido.AddCookie(cookieSesion)
	s.Handler().ServeHTTP(wDesconocido, rDesconocido)
	if wDesconocido.Code != http.StatusOK || llamadas.Load() != 0 {
		t.Fatalf("GET desconocido distinguible: status=%d proveedor=%d", wDesconocido.Code, llamadas.Load())
	}

	// La capacidad pertenece a quien inició el cambio. Otra sesión no la consume
	// y recibe exactamente el mismo acuse que todos los demás resultados.
	confirmarDisponible, _ := url.Parse(envios["disponible@example.com"].datos.Confirmar)
	tokenDisponible := capacidadFragmentoPrueba(t, confirmarDisponible, "token")
	duplicada := respuestaDeCambio(postMFA(t, s, cookieSesion, "/cuenta/correo/confirmar", url.Values{"token": {tokenDisponible, strings.Repeat("b", 64)}}))
	if duplicada != base || llamadas.Load() != 0 {
		t.Fatalf("un token duplicado distinguió o consumió la capacidad: respuesta=%+v proveedor=%d", duplicada, llamadas.Load())
	}
	_, cookieAjena := sesionMFA(t, s, "00000000-0000-4000-8000-000000000099", "aal2", 3600)
	respuestaAjena := respuestaDeCambio(postMFA(t, s, cookieAjena, "/cuenta/correo/confirmar", url.Values{"token": {tokenDisponible}}))
	if respuestaAjena != base || llamadas.Load() != 0 {
		t.Fatalf("otra identidad distinguió o consumió la capacidad: respuesta=%+v proveedor=%d", respuestaAjena, llamadas.Load())
	}

	confirmaciones := map[string]respuestaCambioCorreo{}
	for _, email := range direcciones {
		u, _ := url.Parse(envios[email].datos.Confirmar)
		confirmaciones[email] = respuestaDeCambio(postMFA(t, s, cookieSesion, "/cuenta/correo/confirmar", url.Values{"token": {capacidadFragmentoPrueba(t, u, "token")}}))
	}
	for _, email := range direcciones {
		if confirmaciones[email] != base {
			t.Fatalf("el proveedor hizo distinguible la confirmación de %s\nbase: %+v\nactual: %+v", email, base, confirmaciones[email])
		}
	}
	if llamadas.Load() != 3 {
		t.Fatalf("confirmaciones que llegaron al proveedor: %d", llamadas.Load())
	}

	// Resultado exitoso, email_exists y fallo ambiguo consumen la capacidad: no
	// hay reintento que permita convertir el proveedor en un oráculo.
	for _, email := range direcciones {
		u, _ := url.Parse(envios[email].datos.Confirmar)
		repetida := respuestaDeCambio(postMFA(t, s, cookieSesion, "/cuenta/correo/confirmar", url.Values{"token": {capacidadFragmentoPrueba(t, u, "token")}}))
		if repetida != base || llamadas.Load() != 3 {
			t.Fatalf("la capacidad de %s se pudo repetir: respuesta=%+v proveedor=%d", email, repetida, llamadas.Load())
		}
	}

	invalida := iniciar("no-es-correo")
	propia := iniciar("test@example.com")
	if llamadas.Load() != 3 || len(remitente.envios) != 0 {
		t.Fatalf("una entrada local produjo efecto: proveedor=%d correo=%d", llamadas.Load(), len(remitente.envios))
	}
	if invalida.flash == base.flash || propia.flash == base.flash || invalida.flash == propia.flash {
		t.Fatalf("la validación local perdió sus mensajes: inválida=%q propia=%q genérica=%q", invalida.flash, propia.flash, base.flash)
	}
}

func TestCambioCorreoConfirmacionConcurrenteEsUnSoloUso(t *testing.T) {
	inicio, continuar := make(chan struct{}), make(chan struct{})
	var llamadas atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, _ *http.Request) {
		if llamadas.Add(1) == 1 {
			close(inicio)
			<-continuar
		}
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
	})
	a, _ := sesionMFA(t, s, consentPersona, "aal2", 3600)
	token := strings.Repeat("c", 64)
	clave, _ := claveCambioCorreo(token)
	s.cambiosCorreo.Store(clave, &cambioCorreoPendiente{UserID: consentPersona, Email: "propuesta@example.com", Hasta: time.Now().Add(time.Minute)})

	confirmar := func() respuestaCambioCorreo {
		form := url.Values{"token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/cuenta/correo/confirmar", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), claveSesion, a))
		w := httptest.NewRecorder()
		s.cuentaCorreoConfirmarPOST(w, r)
		return respuestaDeCambio(w)
	}

	primera := make(chan respuestaCambioCorreo, 1)
	go func() { primera <- confirmar() }()
	select {
	case <-inicio:
	case <-time.After(2 * time.Second):
		t.Fatal("la primera confirmación no llegó al proveedor")
	}
	segunda := confirmar()
	close(continuar)
	resultadoPrimera := <-primera
	if llamadas.Load() != 1 || segunda != resultadoPrimera || segunda.flash != url.QueryEscape(mensajeCambioCorreo) {
		t.Fatalf("la capacidad concurrente no fue de un solo uso: proveedor=%d primera=%+v segunda=%+v", llamadas.Load(), resultadoPrimera, segunda)
	}
}

func TestCambioCorreoCaducadoNoLlegaAlProveedor(t *testing.T) {
	var llamadas atomic.Int32
	s := servidorMFA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
			return
		}
		llamadas.Add(1)
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: consentPersona})
	})
	_, cookie := sesionMFA(t, s, consentPersona, "aal2", 3600)
	token := strings.Repeat("b", 64)
	clave, _ := claveCambioCorreo(token)
	pendiente := &cambioCorreoPendiente{UserID: consentPersona, Email: "propuesta@example.com", Hasta: time.Now().Add(-time.Second)}
	s.cambiosCorreo.Store(clave, pendiente)

	w := postMFA(t, s, cookie, "/cuenta/correo/confirmar", url.Values{"token": {token}})
	if respuestaDeCambio(w).flash != url.QueryEscape(mensajeCambioCorreo) || llamadas.Load() != 0 {
		t.Fatalf("capacidad caducada tuvo efecto: status=%d proveedor=%d", w.Code, llamadas.Load())
	}
	if _, ok := s.cambiosCorreo.Load(clave); ok {
		t.Fatal("la capacidad caducada siguió almacenada")
	}
}
