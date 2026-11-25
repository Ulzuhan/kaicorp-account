package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

func TestCiphertextProveedorNoSeTrasplantaEntreSesiones(t *testing.T) {
	st, db := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("llamada inesperada: %s", r.URL)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: strings.TrimPrefix(token, "access-")})
	}))
	defer proveedor.Close()
	gt := gotrue.New(proveedor.URL, "anon-test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	crear := func(userID string) (*session.Actual, *http.Cookie) {
		t.Helper()
		w := httptest.NewRecorder()
		a, err := m.Crear(t.Context(), w, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
			AccessToken: "access-" + userID, RefreshToken: "refresh-" + userID, ExpiresIn: 3600,
			User: gotrue.User{ID: userID, Email: userID + "@example.com"},
		}, "aal2", false)
		if err != nil {
			t.Fatal(err)
		}
		return a, cookieSesion(w)
	}
	atacante, cookie := crear("00000000-0000-4000-8000-000000000091")
	victima, _ := crear("00000000-0000-4000-8000-000000000092")
	if _, err := db.Exec(t.Context(), `update account.sesiones destino set
		access_token=origen.access_token,refresh_token=origen.refresh_token,access_expira=origen.access_expira
		from account.sesiones origen where destino.id=$1 and origen.id=$2`, atacante.ID, victima.ID); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookie)
	cargada, err := m.Cargar(t.Context(), httptest.NewRecorder(), r)
	if err != nil {
		t.Fatal(err)
	}
	if cargada != nil {
		t.Fatalf("el ciphertext trasplantado autenticó: user=%s token=%q", cargada.UserID, cargada.Token())
	}
	if _, err := st.Sesion(t.Context(), atacante.ID); !errors.Is(err, store.ErrNoExiste) {
		t.Fatalf("la fila manipulada no se invalidó: %v", err)
	}
}

func TestMetadataLigadaNoSePuedeReescribir(t *testing.T) {
	st, db := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: strings.TrimPrefix(token, "access-")})
	}))
	defer proveedor.Close()
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gotrue.New(proveedor.URL, "anon-test", ""))
	if err != nil {
		t.Fatal(err)
	}
	mutaciones := []struct {
		nombre string
		sql    string
	}{
		{"usuario", `update account.sesiones set user_id='00000000-0000-4000-8000-000000000099' where id=$1`},
		{"aal", `update account.sesiones set aal='aal1' where id=$1`},
		{"referencia", `update account.sesiones set referencia=gen_random_uuid() where id=$1`},
		{"clase", `update account.sesiones set access_token=refresh_token,refresh_token=access_token where id=$1`},
	}
	for i, tc := range mutaciones {
		t.Run(tc.nombre, func(t *testing.T) {
			userID := "00000000-0000-4000-8000-00000000008" + string(rune('0'+i))
			w := httptest.NewRecorder()
			a, err := m.Crear(t.Context(), w, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
				AccessToken: "access-" + userID, RefreshToken: "refresh-" + userID, ExpiresIn: 3600,
				User: gotrue.User{ID: userID, Email: userID + "@example.com"},
			}, "aal2", false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(t.Context(), tc.sql, a.ID); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
			r.AddCookie(cookieSesion(w))
			if cargada, err := m.Cargar(t.Context(), httptest.NewRecorder(), r); err != nil || cargada != nil {
				t.Fatalf("metadata manipulada autenticó: %+v %v", cargada, err)
			}
			if _, err := st.Sesion(t.Context(), a.ID); !errors.Is(err, store.ErrNoExiste) {
				t.Fatalf("la fila manipulada no se invalidó: %v", err)
			}
		})
	}
}

func TestCargaAAL2RechazaSujetoProveedorDistinto(t *testing.T) {
	st, _ := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("llamada inesperada: %s", r.URL)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: "00000000-0000-4000-8000-000000000092"})
	}))
	defer proveedor.Close()
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gotrue.New(proveedor.URL, "anon-test", ""))
	if err != nil {
		t.Fatal(err)
	}
	userID := "00000000-0000-4000-8000-000000000091"
	w := httptest.NewRecorder()
	a, err := m.Crear(t.Context(), w, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
		AccessToken: "access-" + userID, RefreshToken: "refresh-" + userID, ExpiresIn: 3600,
		User: gotrue.User{ID: userID, Email: "attacker@example.com"},
	}, "aal2", false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookieSesion(w))
	if cargada, err := m.Cargar(t.Context(), httptest.NewRecorder(), r); err != nil || cargada != nil {
		t.Fatalf("AAL2 aceptó otro sujeto: %+v %v", cargada, err)
	}
	if _, err := st.Sesion(t.Context(), a.ID); !errors.Is(err, store.ErrNoExiste) {
		t.Fatalf("la sesión con sujeto distinto no se invalidó: %v", err)
	}
}

func TestRefreshRechazaSujetoProveedorDistinto(t *testing.T) {
	st, _ := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Errorf("llamada inesperada: %s", r.URL)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(gotrue.Session{
			AccessToken: "access-victima", RefreshToken: "refresh-victima", ExpiresIn: 3600,
			User: gotrue.User{ID: "00000000-0000-4000-8000-000000000092"},
		})
	}))
	defer proveedor.Close()
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gotrue.New(proveedor.URL, "anon-test", ""))
	if err != nil {
		t.Fatal(err)
	}
	userID := "00000000-0000-4000-8000-000000000091"
	w := httptest.NewRecorder()
	a, err := m.Crear(t.Context(), w, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
		AccessToken: "access-" + userID, RefreshToken: "refresh-" + userID, ExpiresIn: 1,
		User: gotrue.User{ID: userID, Email: "attacker@example.com"},
	}, "aal2", false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookieSesion(w))
	if cargada, err := m.Cargar(t.Context(), httptest.NewRecorder(), r); err != nil || cargada != nil {
		t.Fatalf("refresh aceptó otro sujeto: %+v %v", cargada, err)
	}
	if _, err := st.Sesion(t.Context(), a.ID); !errors.Is(err, store.ErrNoExiste) {
		t.Fatalf("la sesión refrescada con otro sujeto no se invalidó: %v", err)
	}
}

func TestRotacionYPromocionVuelvenASellarTokens(t *testing.T) {
	st, _ := baseConsentimiento(t)
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_ = json.NewEncoder(w).Encode(gotrue.User{ID: strings.TrimPrefix(token, "access-")})
	}))
	defer proveedor.Close()
	m, err := session.New(make([]byte, 32), true, time.Hour, time.Hour, st, gotrue.New(proveedor.URL, "anon-test", ""))
	if err != nil {
		t.Fatal(err)
	}
	userID := "00000000-0000-4000-8000-000000000091"
	crear := httptest.NewRecorder()
	a, err := m.Crear(t.Context(), crear, httptest.NewRequest(http.MethodGet, "/", nil), &gotrue.Session{
		AccessToken: "access-" + userID, RefreshToken: "refresh-inicial", ExpiresIn: 3600,
		User: gotrue.User{ID: userID, Email: "test@example.com"},
	}, "aal1", false)
	if err != nil {
		t.Fatal(err)
	}
	idInicial := a.ID
	rotada := httptest.NewRecorder()
	if err := m.RotarPortador(t.Context(), rotada, a); err != nil {
		t.Fatal(err)
	}
	if a.ID == idInicial || cookieSesion(rotada) == nil {
		t.Fatal("la rotación no sustituyó el portador")
	}
	r := httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookieSesion(rotada))
	a, err = m.Cargar(t.Context(), httptest.NewRecorder(), r)
	if err != nil || a == nil || a.AAL != "aal1" || a.UserID != userID {
		t.Fatalf("los sobres re-sellados no cargan tras rotar: %+v %v", a, err)
	}

	idRotado := a.ID
	promovida := httptest.NewRecorder()
	if err := m.Promover(t.Context(), promovida, a, &gotrue.Session{
		AccessToken: "access-" + userID, RefreshToken: "refresh-aal2", ExpiresIn: 3600,
		User: gotrue.User{ID: userID, Email: "test@example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if a.ID == idRotado || cookieSesion(promovida) == nil {
		t.Fatal("la promoción no sustituyó el portador")
	}
	r = httptest.NewRequest(http.MethodGet, "/cuenta", nil)
	r.AddCookie(cookieSesion(promovida))
	cargada, err := m.Cargar(t.Context(), httptest.NewRecorder(), r)
	if err != nil || cargada == nil || !cargada.EsAAL2() || cargada.UserID != userID {
		t.Fatalf("los sobres re-sellados no cargan tras promover: %+v %v", cargada, err)
	}
}
