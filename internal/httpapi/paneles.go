package httpapi

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/policy"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

// ── Portada: tus herramientas ──────────────────────────────────────────────

type herramientaVista struct {
	store.Grupo
	Miembro   bool
	Pendiente bool
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	a := sesionDe(r)
	if a == nil {
		s.render(w, r, "home.html", "", nil, http.StatusOK)
		return
	}
	grupos, err := s.st.Grupos(r.Context())
	if err != nil {
		s.errorPagina(w, r, http.StatusServiceUnavailable, "Temporarily unavailable", "Could not read the list of tools.")
		return
	}
	miembro := map[string]bool{}
	for _, g := range s.membresias(r.Context(), a.UserID) {
		miembro[g] = true
	}
	pendiente := map[string]bool{}
	if sols, err := s.st.SolicitudesDe(r.Context(), a.UserID); err == nil {
		for _, x := range sols {
			if x.Estado == "pendiente" {
				pendiente[x.Grupo] = true
			}
		}
	}
	var hs []herramientaVista
	for _, g := range grupos {
		if g.URL == "" && !miembro[g.Nombre] {
			continue // los roles sólo se enseñan a quien los tiene
		}
		hs = append(hs, herramientaVista{Grupo: g, Miembro: miembro[g.Nombre], Pendiente: pendiente[g.Nombre]})
	}
	s.render(w, r, "home.html", "Your tools", map[string]any{"Herramientas": hs}, http.StatusOK)
}

// ── Solicitar acceso ───────────────────────────────────────────────────────

func (s *Server) solicitar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	nombre := r.PathValue("grupo")
	g, err := s.st.Grupo(r.Context(), nombre)
	if err != nil {
		s.errorPagina(w, r, http.StatusNotFound, "Unknown tool", "There is no tool with that name.")
		return
	}
	grupos, _ := s.st.Grupos(r.Context())
	herramientas := map[string]bool{}
	for _, x := range grupos {
		if x.Solicitable {
			herramientas[x.Nombre] = true
		}
	}
	next := s.nextSeguro(r.PostFormValue("next"))
	switch policy.Solicitar(g.Nombre, g.Solicitable, s.membresias(r.Context(), a.UserID), herramientas) {
	case policy.Automatica:
		if err := s.st.Conceder(r.Context(), a.UserID, g.Nombre, "automática"); err != nil {
			s.errorPagina(w, r, http.StatusServiceUnavailable, "Try again", "Could not record the access.")
			return
		}
		_, _ = s.st.CrearSolicitud(r.Context(), a.UserID, g.Nombre, "automatica", "automática")
		s.ponerFlash(w, g.Titulo+": access granted. You already had an approved account, so no one needs to read this one.")
	case policy.Pendiente:
		if _, err := s.st.CrearSolicitud(r.Context(), a.UserID, g.Nombre, "pendiente", ""); err != nil {
			s.errorPagina(w, r, http.StatusServiceUnavailable, "Try again", "Could not record the request.")
			return
		}
		s.ponerFlash(w, g.Titulo+": request sent. A person reads the first one; you will get access once it is approved.")
	default:
		s.ponerFlash(w, g.Titulo+" is by invitation only.")
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ── Consentimiento OAuth ───────────────────────────────────────────────────
//
// El orden importa y no es el que sugiere la API de GoTrue: primero se mira en
// la base QUÉ cliente pide la autorización y si la persona pertenece a su
// grupo; sólo entonces se piden los detalles a GoTrue, porque esa llamada
// aprueba sola cuando ya hay un grant previo.

func (s *Server) consentGET(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	aid := r.URL.Query().Get("authorization_id")
	if aid == "" {
		s.errorPagina(w, r, http.StatusBadRequest, "Nothing to authorize", "This page is where a tool sends you to sign in. Open the tool and use its sign-in button.")
		return
	}
	clienteID, err := s.st.ClienteDeAutorizacion(r.Context(), aid)
	if err != nil {
		s.errorPagina(w, r, http.StatusGone, "This sign-in has expired", "Go back to the tool and try again.")
		return
	}
	g, err := s.st.GrupoDeCliente(r.Context(), clienteID)
	if err != nil {
		log.Printf("consent: cliente %s sin grupo", clienteID)
		s.errorPagina(w, r, http.StatusForbidden, "Not available", "This tool is not open to anyone yet.")
		return
	}
	if !policy.PuedeEntrar(g.Nombre, s.membresias(r.Context(), a.UserID)) {
		pendiente := false
		if sols, err := s.st.SolicitudesDe(r.Context(), a.UserID); err == nil {
			for _, x := range sols {
				if x.Grupo == g.Nombre && x.Estado == "pendiente" {
					pendiente = true
				}
			}
		}
		s.render(w, r, "sin-acceso.html", g.Titulo, map[string]any{"Grupo": g, "Pendiente": pendiente, "Next": r.URL.RequestURI()}, http.StatusForbidden)
		return
	}
	auth, err := s.gt.GetAuthorization(r.Context(), a.Token(), aid)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Sign-in", mensajeGoTrue(err))
		return
	}
	if auth.AutoApproved() {
		http.Redirect(w, r, auth.RedirectURL, http.StatusSeeOther)
		return
	}
	s.render(w, r, "consent.html", "Sign in to "+auth.Client.Name, map[string]any{
		"Client": auth.Client, "Scopes": describirScopes(auth.Scopes()), "AuthorizationID": aid,
	}, http.StatusOK)
}

func describirScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		switch sc {
		case "openid":
			out = append(out, "Your account identifier")
		case "email":
			out = append(out, "Your email address")
		case "profile":
			out = append(out, "Your name")
		case "phone":
			out = append(out, "Your phone number")
		default:
			out = append(out, sc)
		}
	}
	return out
}

func (s *Server) consentPOST(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	aid := r.PostFormValue("authorization_id")
	action := r.PostFormValue("action")
	if action != "approve" && action != "deny" {
		action = "deny"
	}
	if action == "approve" {
		// La política otra vez, por si cambió entre pintar y pulsar.
		clienteID, err := s.st.ClienteDeAutorizacion(r.Context(), aid)
		if err != nil {
			s.errorPagina(w, r, http.StatusGone, "This sign-in has expired", "Go back to the tool and try again.")
			return
		}
		g, err := s.st.GrupoDeCliente(r.Context(), clienteID)
		if err != nil || !policy.PuedeEntrar(g.Nombre, s.membresias(r.Context(), a.UserID)) {
			s.errorPagina(w, r, http.StatusForbidden, "Not allowed", "Your account does not have access to this tool.")
			return
		}
	}
	dest, err := s.gt.Consent(r.Context(), a.Token(), aid, action)
	if err != nil {
		s.errorPagina(w, r, http.StatusBadGateway, "Sign-in", mensajeGoTrue(err))
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ── Seguridad de la cuenta ─────────────────────────────────────────────────

type enrolamiento struct {
	factor *gotrue.EnrolledFactor
	hasta  time.Time
}

func (s *Server) cuenta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	datos := map[string]any{}
	if u, err := s.gt.Me(r.Context(), a.Token()); err == nil {
		datos["Factores"] = u.Factors
		if n := u.Name(); n != "" {
			a.Nombre = n
		}
	} else {
		datos["Error"] = mensajeGoTrue(err)
	}
	if gs, err := s.gt.Grants(r.Context(), a.Token()); err == nil {
		for i := range gs {
			if t, err := time.Parse(time.RFC3339Nano, gs[i].GrantedAt); err == nil {
				gs[i].GrantedAt = t.Format("2006-01-02")
			}
		}
		datos["Grants"] = gs
	}
	if ss, err := s.st.SesionesDe(r.Context(), a.UserID); err == nil {
		datos["Sesiones"] = ss
	}
	if v, ok := s.enrolando.Load(a.ID); ok {
		e := v.(enrolamiento)
		if time.Now().Before(e.hasta) {
			datos["Enrolando"] = e.factor
			// html/template convierte una URL data: en "#ZgotmplZ" salvo que
			// llegue marcada como segura; el QR viene de GoTrue y va en base64.
			datos["EnrolandoQR"] = template.URL(e.factor.QRDataURL())
		} else {
			s.enrolando.Delete(a.ID)
		}
	}
	s.render(w, r, "cuenta.html", "Security", datos, http.StatusOK)
}

func (s *Server) cuentaNombre(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 80 {
		s.ponerFlash(w, "The name has to be between 1 and 80 characters.")
	} else if _, err := s.gt.UpdateUser(r.Context(), a.Token(), "", name, ""); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.ponerFlash(w, "Name saved.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) cuentaPassword(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	p1, p2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if len(p1) < 12 || p1 != p2 {
		s.ponerFlash(w, "Use 12 characters or more, and type it twice the same.")
	} else if _, err := s.gt.UpdateUser(r.Context(), a.Token(), p1, "", ""); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.ponerFlash(w, "Password changed.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorAlta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	f, err := s.gt.EnrollTOTP(r.Context(), a.Token(), "Authenticator app", "KaiCorp Labs")
	if err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.enrolando.Store(a.ID, enrolamiento{factor: f, hasta: time.Now().Add(10 * time.Minute)})
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorVerificar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	factorID := r.PostFormValue("factor_id")
	ch, err := s.gt.ChallengeFactor(r.Context(), a.Token(), factorID)
	if err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	gs, err := s.gt.VerifyFactor(r.Context(), a.Token(), factorID, ch.ID, strings.TrimSpace(r.PostFormValue("code")))
	if err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
		http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
		return
	}
	// La sesión pasa a aal2 con los tokens nuevos.
	if err := s.ses.Actualizar(r.Context(), a, gs, "aal2"); err != nil {
		log.Printf("actualizar sesión aal2: %v", err)
	}
	s.enrolando.Delete(a.ID)
	s.ponerFlash(w, "Second factor active. From now on, signing in asks for a code.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) factorBorrar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	if err := s.gt.DeleteFactor(r.Context(), a.Token(), r.PostFormValue("factor_id")); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.enrolando.Delete(a.ID)
		s.ponerFlash(w, "Factor removed.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) grantRevocar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	if err := s.gt.RevokeGrant(r.Context(), a.Token(), r.PostFormValue("client_id")); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		s.ponerFlash(w, "Signed out of that tool. It will ask you again next time.")
	}
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

func (s *Server) sesionesCerrar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereSesion(w, r)
	if a == nil {
		return
	}
	_ = s.gt.Logout(r.Context(), a.Token(), "others")
	_ = s.st.BorrarSesionesDe(r.Context(), a.UserID, a.ID)
	s.ponerFlash(w, "Every other session is closed.")
	http.Redirect(w, r, "/cuenta", http.StatusSeeOther)
}

// ── Administración ─────────────────────────────────────────────────────────

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	datos := map[string]any{"IsAdmin": true, "Q": strings.TrimSpace(r.URL.Query().Get("q"))}
	if xs, err := s.st.SolicitudesPendientes(r.Context()); err == nil {
		datos["Pendientes"] = xs
	} else {
		datos["Error"] = "Could not read the requests."
	}
	if us, err := s.st.Usuarios(r.Context(), datos["Q"].(string), 50); err == nil {
		datos["Usuarios"] = us
	}
	if gs, err := s.st.Grupos(r.Context()); err == nil {
		datos["Grupos"] = gs
	}
	if cs, err := s.st.Clientes(r.Context()); err == nil {
		datos["Clientes"] = cs
	}
	s.render(w, r, "admin.html", "Administration", datos, http.StatusOK)
}

func (s *Server) adminCuenta(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	u, err := s.st.UsuarioPorID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.errorPagina(w, r, http.StatusNotFound, "No such account", "There is no account with that id.")
		return
	}
	datos := map[string]any{"IsAdmin": true, "Cuenta": u}
	datos["Membresias"], _ = s.st.MembresiasDe(r.Context(), u.ID)
	datos["Solicitudes"], _ = s.st.SolicitudesDe(r.Context(), u.ID)
	datos["Grupos"], _ = s.st.Grupos(r.Context())
	s.render(w, r, "admin-cuenta.html", u.Email, datos, http.StatusOK)
}

func (s *Server) adminSolicitud(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	x, err := s.st.Solicitud(r.Context(), r.PostFormValue("id"))
	if err != nil {
		s.ponerFlash(w, "That request no longer exists.")
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	switch r.PostFormValue("decision") {
	case "aprobar":
		if err := s.st.Conceder(r.Context(), x.UserID, x.Grupo, a.Email); err == nil {
			_ = s.st.ResolverSolicitud(r.Context(), x.ID, "aprobada", a.Email)
			s.ponerFlash(w, x.Email+" can now use "+x.Grupo+".")
		} else {
			log.Printf("aprobar %s/%s: %v", x.UserID, x.Grupo, err)
			s.ponerFlash(w, "Could not grant the access.")
		}
	case "rechazar":
		_ = s.st.ResolverSolicitud(r.Context(), x.ID, "rechazada", a.Email)
		s.ponerFlash(w, "Request from "+x.Email+" rejected.")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminVincular(w http.ResponseWriter, r *http.Request) {
	if s.requiereAdmin(w, r) == nil {
		return
	}
	if err := s.st.VincularCliente(r.Context(), r.PostFormValue("grupo"), r.PostFormValue("cliente_id")); err != nil {
		log.Printf("vincular: %v", err)
		s.ponerFlash(w, "Could not link the client.")
	} else {
		s.ponerFlash(w, "Client linked.")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminConceder(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	uid, grupo := r.PostFormValue("user_id"), r.PostFormValue("grupo")
	if err := s.st.Conceder(r.Context(), uid, grupo, a.Email); err != nil {
		log.Printf("conceder %s/%s: %v", uid, grupo, err)
		s.ponerFlash(w, "Could not grant the membership.")
	} else {
		s.ponerFlash(w, "Granted "+grupo+".")
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

func (s *Server) adminRevocar(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	uid, grupo := r.PostFormValue("user_id"), r.PostFormValue("grupo")
	if uid == a.UserID && grupo == s.cfg.AdminGroup {
		s.ponerFlash(w, "You cannot remove your own administration.")
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	if err := s.st.Revocar(r.Context(), uid, grupo); err != nil {
		log.Printf("revocar %s/%s: %v", uid, grupo, err)
		s.ponerFlash(w, "Could not revoke.")
	} else {
		// Sin el grant, GoTrue deja de aprobar solo y los refresh tokens de esa
		// herramienta mueren: es lo que hace que revocar revoque de verdad.
		if g, err := s.st.Grupo(r.Context(), grupo); err == nil && g.ClienteID != "" {
			if err := s.st.RevocarGrants(r.Context(), uid, g.ClienteID); err != nil {
				log.Printf("revocar grants %s/%s: %v", uid, g.ClienteID, err)
			}
		}
		s.ponerFlash(w, "Revoked "+grupo+". The tool's sessions end within its cookie lifetime.")
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

func (s *Server) adminCerrarSesiones(w http.ResponseWriter, r *http.Request) {
	if s.requiereAdmin(w, r) == nil {
		return
	}
	uid := r.PostFormValue("user_id")
	if err := s.st.CerrarSesionesGoTrue(r.Context(), uid); err != nil {
		log.Printf("cerrar sesiones %s: %v", uid, err)
		s.ponerFlash(w, "Could not close the provider sessions.")
	} else {
		_ = s.st.BorrarSesionesDe(r.Context(), uid, "")
		s.ponerFlash(w, "Every session of that account is closed.")
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

func (s *Server) adminBloquear(w http.ResponseWriter, r *http.Request) {
	a := s.requiereAdmin(w, r)
	if a == nil {
		return
	}
	uid := r.PostFormValue("user_id")
	if uid == a.UserID {
		s.ponerFlash(w, "You cannot block yourself.")
		http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	duracion := "876000h"
	if r.PostFormValue("accion") == "desbloquear" {
		duracion = "none"
	}
	if err := s.gt.AdminBanUser(r.Context(), uid, duracion); err != nil {
		s.ponerFlash(w, mensajeGoTrue(err))
	} else {
		if duracion != "none" {
			_ = s.st.CerrarSesionesGoTrue(r.Context(), uid)
			_ = s.st.BorrarSesionesDe(r.Context(), uid, "")
			s.ponerFlash(w, "Account blocked and signed out everywhere.")
		} else {
			s.ponerFlash(w, "Account unblocked.")
		}
	}
	http.Redirect(w, r, "/admin/cuenta/"+url.PathEscape(uid), http.StatusSeeOther)
}

// ── Plantillas de correo para GoTrue y salud ───────────────────────────────

var plantillasPermitidas = map[string]bool{
	"confirmacion.html": true, "recuperacion.html": true, "cambio-correo.html": true,
	"invitacion.html": true, "magic.html": true, "reautenticacion.html": true,
}

// plantilla sirve las plantillas de correo tal cual: GoTrue las pide por HTTP
// (GOTRUE_MAILER_TEMPLATES_*) desde la red interna y las procesa él.
func (s *Server) plantilla(w http.ResponseWriter, r *http.Request) {
	nombre := r.PathValue("nombre")
	if !plantillasPermitidas[nombre] {
		http.NotFound(w, r)
		return
	}
	b, err := webPlantilla(nombre)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextoBreve(r)
	defer cancel()
	estado := map[string]any{"ok": true}
	code := http.StatusOK
	if err := s.st.Ping(ctx); err != nil {
		estado["ok"], estado["db"] = false, "down"
		code = http.StatusServiceUnavailable
	}
	if err := s.gt.Health(ctx); err != nil {
		estado["ok"], estado["gotrue"] = false, "down"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(estado)
}
