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

const etiquetaSesionSinNombre = "Account"

// respuestaSesionAPI es deliberadamente incapaz de transportar correo, id o
// tokens. Esta ruta cruza un origen y su contrato público omite identificadores y sólo proyecta
// permisos del origen autorizado o los del propio portal.
type respuestaSesionAPI struct {
	SignedIn   bool      `json:"signed_in"`
	Name       string    `json:"name,omitempty"`
	Admin      *bool     `json:"admin,omitempty"`
	ToolAccess string    `json:"tool_access,omitempty"`
	AccountURL string    `json:"account_url,omitempty"`
	Granted    *[]string `json:"granted,omitempty"`
	Pending    *[]string `json:"pending,omitempty"`
}

func proyectarSesionAPI(nombre string, admin bool) respuestaSesionAPI {
	if strings.TrimSpace(nombre) == "" {
		nombre = etiquetaSesionSinNombre
	}
	return respuestaSesionAPI{SignedIn: true, Name: nombre, Admin: &admin}
}

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
		_ = json.NewEncoder(w).Encode(respuestaSesionAPI{SignedIn: false})
		return
	}
	resp := proyectarSesionAPI(a.Nombre, s.esAdmin(r.Context(), a))
	if origenAutorizado {
		s.rellenarPermisosSesion(r.Context(), a.UserID, origen, &resp)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) rellenarPermisosSesion(ctx context.Context, userID, origen string, resp *respuestaSesionAPI) {
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
			if gHost := strings.ToLower(g.Host()); g.Tipo == store.TipoGrupoHerramienta && gHost != "" && gHost == originHost {
				var estado string
				switch {
				case policy.PuedeEntrar(g.Nombre, listaMembresias):
					estado = "granted"
				case pendienteMap[g.Nombre]:
					estado = "pending"
				case g.Solicitable && g.Nombre != s.cfg.AdminGroup:
					estado = "requestable"
				default:
					estado = "invite_only"
				}
				resp.ToolAccess = estado
				if s.cfg.PublicURL != nil {
					resp.AccountURL = strings.TrimRight(s.cfg.PublicURL.String(), "/") + "/"
				}
				return
			}
		}
	}

	// Un origen permitido pero no asociado a una herramienta no es
	// automáticamente el portal. Sólo el origen padre de Account lo es.
	if s.cfg.PublicURL == nil {
		return
	}
	_, padre, ok := strings.Cut(s.cfg.PublicURL.Hostname(), ".")
	if !ok || !strings.Contains(padre, ".") || !strings.EqualFold(strings.TrimRight(origen, "/"), s.cfg.PublicURL.Scheme+"://"+padre) {
		return
	}
	concedidas := make([]string, 0)
	pendientes := make([]string, 0)
	vistosConcedidas := map[string]bool{}
	vistosPendientes := map[string]bool{}
	for _, g := range grupos {
		host := strings.ToLower(g.Host())
		if g.Tipo != store.TipoGrupoHerramienta || host == "" {
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
	resp.Granted = &concedidas
	resp.Pending = &pendientes
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
