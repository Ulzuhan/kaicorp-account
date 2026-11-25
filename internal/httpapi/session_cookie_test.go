package httpapi

import (
	"net/http"
	"testing"
)

func TestIdentificadoresGuardadosNoAutentican(t *testing.T) {
	s := servidorConSesiones(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("llamada inesperada al proveedor: %s", r.URL.Path)
	})
	a, cookie := sesionDePrueba(t, s, true, "aal2", 3600)
	filas, err := s.st.SesionesDe(t.Context(), a.UserID)
	if err != nil || len(filas) != 1 {
		t.Fatalf("listar sesiones: %v %v", filas, err)
	}
	for _, id := range []string{filas[0].ID, filas[0].Referencia} {
		if actual, err := cargarCookie(s, &http.Cookie{Name: cookie.Name, Value: id}); err != nil || actual != nil {
			t.Errorf("el identificador guardado autenticó al lector de la base: %+v %v", actual, err)
		}
	}
	actual, err := cargarCookie(s, cookie)
	if err != nil || actual == nil || actual.ID != a.ID || actual.AAL != a.AAL || actual.Token() != a.Token() || !actual.Expira.Equal(a.Expira) {
		t.Fatalf("la cookie legítima perdió autoridad o caducidad: %+v %v", actual, err)
	}
}
