package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

type almacenSesion interface {
	Grupos(ctx context.Context) ([]store.Grupo, error)
	MembresiasDe(ctx context.Context, userID string) ([]store.Membresia, error)
	SolicitudesDe(ctx context.Context, userID string) ([]store.Solicitud, error)
	EsMiembro(ctx context.Context, userID, grupo string) (bool, error)
}

func (s *Server) almacenDeSesion() almacenSesion {
	if s.stSesion != nil {
		return s.stSesion
	}
	if s.st != nil {
		return s.st
	}
	return nil
}

// apiSesion dice a la web pública y a las herramientas si quien mira tiene
// sesión aquí, y qué permisos tiene según quien pregunta (sin exponer correos,
// identificadores ni el resto de herramientas a una app concreta):
//
//   - Sin sesión: {"signed_in": false}.
//   - Desde una herramienta (Origin coincide con un grupo): su `tool_access`
//     ("granted" | "pending" | "requestable" | "invite_only") y `account_url`.
//   - Desde el portal (kaicorplabs.com): listas `granted` y `pending` de hosts.
//
// Es la única ruta con CORS, restringido estrictamente a cfg.SessionOrigins.
func (s *Server) apiSesion(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Origin")
	origen := r.Header.Get("Origin")
	origenAutorizado := origen != "" && s.origenDeCasa(origen)
	if origenAutorizado {
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
	resp := map[string]any{
		"signed_in": true,
		"name":      nombre,
		"admin":     s.esAdmin(r.Context(), a),
	}
	// Si la petición trae un Origin fuera de cfg.SessionOrigins no exponemos
	// listas de permisos ni estado de acceso.
	if origen == "" || origenAutorizado {
		s.rellenarPermisosSesion(r.Context(), a.UserID, origen, resp)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) rellenarPermisosSesion(ctx context.Context, userID, origen string, resp map[string]any) {
	st := s.almacenDeSesion()
	if st == nil {
		return
	}
	grupos, err := st.Grupos(ctx)
	if err != nil {
		return
	}
	var listaMembresias []string
	if ms, err := st.MembresiasDe(ctx, userID); err == nil {
		listaMembresias = make([]string, 0, len(ms))
		for _, m := range ms {
			listaMembresias = append(listaMembresias, m.Grupo)
		}
	}
	pendienteMap := map[string]bool{}
	if sols, err := st.SolicitudesDe(ctx, userID); err == nil {
		for _, x := range sols {
			if x.Estado == "pendiente" {
				pendienteMap[x.Grupo] = true
			}
		}
	}

	if originHost := hostDeOrigin(origen); originHost != "" {
		for _, g := range grupos {
			if gHost := strings.ToLower(g.Host()); gHost != "" && gHost == originHost {
				var estado string
				switch {
				case policy.PuedeEntrar(g.Nombre, listaMembresias):
					estado = "granted"
				case pendienteMap[g.Nombre]:
					estado = "pending"
				case g.Solicitable:
					estado = "requestable"
				default:
					estado = "invite_only"
				}
				resp["tool_access"] = estado
				if s.cfg.PublicURL != nil {
					resp["account_url"] = strings.TrimRight(s.cfg.PublicURL.String(), "/") + "/"
				}
				return
			}
		}
	}

	concedidas := make([]string, 0)
	pendientes := make([]string, 0)
	vistosConcedidas := map[string]bool{}
	vistosPendientes := map[string]bool{}
	for _, g := range grupos {
		host := strings.ToLower(g.Host())
		if host == "" {
			continue
		}
		if policy.PuedeEntrar(g.Nombre, listaMembresias) {
			if !vistosConcedidas[host] {
				vistosConcedidas[host] = true
				concedidas = append(concedidas, host)
			}
			continue
		}
		if pendienteMap[g.Nombre] && !vistosPendientes[host] {
			vistosPendientes[host] = true
			pendientes = append(pendientes, host)
		}
	}
	sort.Strings(concedidas)
	sort.Strings(pendientes)
	resp["granted"] = concedidas
	resp["pending"] = pendientes
}

func hostDeOrigin(origen string) string {
	if origen == "" {
		return ""
	}
	u, err := url.Parse(origen)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
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
