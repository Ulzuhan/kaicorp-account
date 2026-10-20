package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

const etiquetaSesionSinNombre = "Account"

// respuestaSesionAPI es deliberadamente incapaz de transportar correo, id o
// tokens. Esta ruta cruza un origen y su contrato público termina en estos tres
// campos.
type respuestaSesionAPI struct {
	SignedIn bool   `json:"signed_in"`
	Name     string `json:"name,omitempty"`
	Admin    *bool  `json:"admin,omitempty"`
}

func proyectarSesionAPI(nombre string, admin bool) respuestaSesionAPI {
	if strings.TrimSpace(nombre) == "" {
		nombre = etiquetaSesionSinNombre
	}
	return respuestaSesionAPI{SignedIn: true, Name: nombre, Admin: &admin}
}

// apiSesion dice a la web pública si quien mira tiene sesión aquí, para que su
// cabecera enseñe «Your tools · Nombre» en vez de «Sign in». Es la única ruta
// con CORS, y sólo para los orígenes de la casa (cfg.SessionOrigins): la
// cookie es SameSite=Lax y kaicorplabs.com es el mismo sitio que
// account.kaicorplabs.com, así que el navegador la adjunta a un fetch con
// credenciales desde la portada; a cualquier otro origen se le contesta sin
// cabeceras CORS y su navegador no le deja leer la respuesta.
//
// Devuelve lo mínimo que la cabecera necesita: si hay sesión, el nombre y si
// administra. Ni correo, ni identificadores, ni nada que sirva para otra cosa.
func (s *Server) apiSesion(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Origin")
	if origen := r.Header.Get("Origin"); origen != "" && s.origenDeCasa(origen) {
		h.Set("Access-Control-Allow-Origin", origen)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	a := sesionDe(r)
	if a == nil {
		_ = json.NewEncoder(w).Encode(respuestaSesionAPI{SignedIn: false})
		return
	}
	_ = json.NewEncoder(w).Encode(proyectarSesionAPI(a.Nombre, s.esAdmin(r.Context(), a)))
}

func (s *Server) origenDeCasa(origen string) bool {
	origen = strings.TrimRight(origen, "/")
	for _, o := range s.cfg.SessionOrigins {
		if strings.EqualFold(o, origen) {
			return true
		}
	}
	return false
}
