package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
)

func TestSolicitudConSesionCargadaAntesDeRevocarTodo(t *testing.T) {
	st, db := baseConsentimiento(t)
	if _, err := db.Exec(t.Context(), `insert into account.grupos(nombre,titulo) values ('segunda','Second')`); err != nil {
		t.Fatal(err)
	}
	gt := gotrue.New("http://unused.invalid", "test", "")
	m, err := session.New(make([]byte, 32), true, time.Hour, 24*time.Hour, st, gt)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://account.example.com")
	s, err := New(&config.Config{PublicURL: publicURL}, st, gt, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/solicitar/segunda", strings.NewReader("next=%2Fcuenta"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("grupo", "segunda")
	r = r.WithContext(context.WithValue(r.Context(), claveSesion, &session.Actual{UserID: consentPersona, Email: "test@example.com"}))

	w := httptest.NewRecorder()
	s.solicitar(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cuenta" {
		t.Fatalf("control legítimo: %d %s", w.Code, w.Body.String())
	}
	if ok, err := st.EsMiembro(t.Context(), consentPersona, "segunda"); err != nil || !ok {
		t.Fatalf("segunda herramienta no concedida: %v %v", ok, err)
	}
	if _, err := st.RevocarTodo(t.Context(), consentPersona); err != nil {
		t.Fatal(err)
	}

	// El middleware ya había cargado Actual, pero la decisión en Store tiene que
	// volver a leer el estado posterior a la revocación.
	w = httptest.NewRecorder()
	s.solicitar(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cuenta" {
		t.Fatalf("solicitud posterior: %d %s", w.Code, w.Body.String())
	}
	if ok, err := st.EsMiembro(t.Context(), consentPersona, "segunda"); err != nil || ok {
		t.Fatalf("la sesión cargada restauró membresía: %v %v", ok, err)
	}
	var pendientes int
	if err := db.QueryRow(t.Context(), `select count(*) from account.solicitudes
		where user_id=$1 and grupo='segunda' and estado='pendiente'`, consentPersona).Scan(&pendientes); err != nil || pendientes != 1 {
		t.Fatalf("la nueva aprobación no quedó pendiente: %d %v", pendientes, err)
	}
}
