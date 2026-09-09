package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

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
		_ = json.NewEncoder(w).Encode(map[string]any{"signed_in": false})
		return
	}
	nombre := a.Nombre
	if nombre == "" {
		nombre = a.Email
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"signed_in": true,
		"name":      nombre,
		"admin":     s.esAdmin(r.Context(), a),
	})
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
