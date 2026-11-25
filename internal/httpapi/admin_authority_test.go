package httpapi

import (
	"context"
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
)

const (
	adminAutoridad = "00000000-0000-4000-8000-000000000091"
	adminRevocado  = "00000000-0000-4000-8000-000000000092"
)

func TestRevocarAdministracionInvalidaSesionesYComandos(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo,tipo,solicitable)
		values ('account-admin','Administration','rol',false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into account.membresias(user_id,grupo,por) values
		($1,'account-admin','test'),($2,'account-admin','test')`, adminAutoridad, adminRevocado); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.sessions(user_id) values ($1)`, adminRevocado); err != nil {
		t.Fatal(err)
	}
	gt := gotrue.New("http://unused.invalid", "anon", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	gs := &gotrue.Session{AccessToken: tokenPruebaIAT(time.Now().Unix()), RefreshToken: "refresh", ExpiresIn: 3600,
		User: gotrue.User{ID: adminRevocado, Email: "revoked@example.com"}}
	actualRevocado, err := m.Crear(t.Context(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), gs, "aal2", false)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL, AdminGroup: "account-admin"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"user_id": {adminRevocado}, "grupo": {"account-admin"}}
	r := httptest.NewRequest(http.MethodPost, "/admin/revocar", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{UserID: adminAutoridad, Email: "admin@example.com", AAL: "aal2"}))
	w := httptest.NewRecorder()
	s.adminRevocar(w, r)
	if w.Code != http.StatusSeeOther || strings.Contains(flashDeRespuesta(t, w), "Could not") {
		t.Fatalf("revocación: HTTP %d, flash %q", w.Code, flashDeRespuesta(t, w))
	}
	if ok, err := st.EsMiembro(t.Context(), adminRevocado, "account-admin"); err != nil || ok {
		t.Fatalf("membresía administradora superviviente: %v %v", ok, err)
	}
	if sesiones, err := st.SesionesDe(t.Context(), adminRevocado); err != nil || len(sesiones) != 0 {
		t.Fatalf("sesiones locales supervivientes: %d %v", len(sesiones), err)
	}
	var proveedor int
	if err := db.QueryRow(t.Context(), `select count(*) from auth.sessions where user_id=$1`, adminRevocado).Scan(&proveedor); err != nil || proveedor != 0 {
		t.Fatalf("sesiones del proveedor supervivientes: %d %v", proveedor, err)
	}
	var generacion int64
	if err := db.QueryRow(t.Context(), `select generacion from account.autoridad_administrativa where user_id=$1`, adminRevocado).Scan(&generacion); err != nil || generacion == 0 {
		t.Fatalf("la revocación no invalidó comandos: generación=%d error=%v", generacion, err)
	}

	// Ni siquiera volver a conceder el rol rejuvenece una petición cuya sesión
	// se cargó antes de la revocación.
	if err := st.Conceder(t.Context(), adminRevocado, "account-admin", "system"); err != nil {
		t.Fatal(err)
	}
	destino := "00000000-0000-4000-8000-000000000093"
	conceder := url.Values{"user_id": {destino}, "grupo": {"rol"}}
	rAntigua := httptest.NewRequest(http.MethodPost, "/admin/conceder", strings.NewReader(conceder.Encode()))
	rAntigua.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rAntigua = rAntigua.WithContext(context.WithValue(rAntigua.Context(), claveSesion, actualRevocado))
	wAntigua := httptest.NewRecorder()
	s.adminConceder(wAntigua, rAntigua)
	if wAntigua.Code != http.StatusForbidden {
		t.Fatalf("la sesión anterior revivió tras reconceder: HTTP %d", wAntigua.Code)
	}
	if ok, err := st.EsMiembro(t.Context(), destino, "rol"); err != nil || ok {
		t.Fatalf("la orden anterior concedió autoridad: %v %v", ok, err)
	}
}

func TestInvitacionLimitaGruposAntesDelProveedor(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo,tipo,solicitable)
		values ('account-admin','Administration','rol',false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into account.membresias(user_id,grupo,por)
		values ($1,'account-admin','test')`, adminAutoridad); err != nil {
		t.Fatal(err)
	}
	var llamadas atomic.Int32
	proveedor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llamadas.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(proveedor.Close)
	gt := gotrue.New(proveedor.URL, "anon", "service")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL, AdminGroup: "account-admin"}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"email": {"invitee@example.com"}}
	for range 33 {
		form.Add("grupo", "rol")
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/invitar", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{UserID: adminAutoridad, Email: "admin@example.com", AAL: "aal2"}))
	w := httptest.NewRecorder()
	s.adminInvitar(w, r)
	if w.Code != http.StatusSeeOther || !strings.Contains(flashDeRespuesta(t, w), "at most 32") {
		t.Fatalf("límite de grupos: HTTP %d, flash %q", w.Code, flashDeRespuesta(t, w))
	}
	if llamadas.Load() != 0 {
		t.Fatalf("la entrada sobredimensionada alcanzó al proveedor: %d", llamadas.Load())
	}
}
