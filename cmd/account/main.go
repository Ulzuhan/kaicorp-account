// account es la app de cuenta de KaiCorp Labs: registro, entrada, segundo
// factor, consentimiento OAuth y administración de membresías sobre una
// instancia propia de Supabase Auth.
//
//	account            arranca el servidor (por defecto)
//	account sonda      sonda de salud para el HEALTHCHECK de la imagen
//	account migrar     aplica las migraciones y sale
//	account admin <correo>                   da la membresía de administración
//	account aprobar <correo> <grupo>         concede una herramienta (y cierra su solicitud)
//	account revocar <correo> <grupo>         la quita, y revoca el grant OAuth
//	account vincular <grupo> <client_id>     ata un cliente OAuth a su grupo
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/config"
	"github.com/Ulzuhan/kaicorp-account/internal/gotrue"
	"github.com/Ulzuhan/kaicorp-account/internal/httpapi"
	"github.com/Ulzuhan/kaicorp-account/internal/session"
	"github.com/Ulzuhan/kaicorp-account/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) > 1 && os.Args[1] == "sonda" {
		os.Exit(sonda())
	}
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("configuración:\n%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	st, err := store.Open(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		log.Fatalf("base de datos: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(context.Background()); err != nil {
		log.Fatalf("migraciones: %v", err)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrar":
			log.Print("migraciones al día")
			return
		case "admin":
			if len(os.Args) != 3 {
				log.Fatal("uso: account admin <correo>")
			}
			u, err := st.UsuarioPorCorreo(context.Background(), os.Args[2])
			if err != nil {
				log.Fatalf("no hay cuenta con ese correo: %v", err)
			}
			if err := st.Conceder(context.Background(), u.ID, cfg.AdminGroup, "cli"); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s administra (%s)\n", u.Email, cfg.AdminGroup)
			return
		case "invitar":
			// account invitar <correo> [grupo…]: crea la cuenta por invitación
			// (GoTrue manda el correo) y le concede los grupos de una vez, para
			// traer a alguien de otro proveedor con sus herramientas ya puestas.
			if len(os.Args) < 3 {
				log.Fatal("uso: account invitar <correo> [grupo…]")
			}
			ctx := context.Background()
			gt := gotrue.New(cfg.GoTrueURL, cfg.AnonKey, cfg.ServiceKey)
			u, err := gt.AdminInvite(ctx, os.Args[2])
			if err != nil {
				log.Fatalf("invitar: %v", err)
			}
			for _, g := range os.Args[3:] {
				if _, err := st.Grupo(ctx, g); err != nil {
					log.Fatalf("no hay grupo %q", g)
				}
				if err := st.Conceder(ctx, u.ID, g, "cli"); err != nil {
					log.Fatal(err)
				}
			}
			fmt.Printf("%s invitada · id %s · grupos: %s\n", u.Email, u.ID, strings.Join(os.Args[3:], ", "))
			return
		case "aprobar", "revocar":
			if len(os.Args) != 4 {
				log.Fatalf("uso: account %s <correo> <grupo>", os.Args[1])
			}
			ctx := context.Background()
			u, err := st.UsuarioPorCorreo(ctx, os.Args[2])
			if err != nil {
				log.Fatalf("no hay cuenta con ese correo: %v", err)
			}
			g, err := st.Grupo(ctx, os.Args[3])
			if err != nil {
				log.Fatalf("no hay grupo %q", os.Args[3])
			}
			if os.Args[1] == "aprobar" {
				if err := st.Conceder(ctx, u.ID, g.Nombre, "cli"); err != nil {
					log.Fatal(err)
				}
				// Si había solicitud pendiente, queda cerrada como aprobada.
				if xs, err := st.SolicitudesDe(ctx, u.ID); err == nil {
					for _, x := range xs {
						if x.Grupo == g.Nombre && x.Estado == "pendiente" {
							_ = st.ResolverSolicitud(ctx, x.ID, "aprobada", "cli")
						}
					}
				}
				fmt.Printf("%s puede usar %s\n", u.Email, g.Nombre)
				return
			}
			if err := st.Revocar(ctx, u.ID, g.Nombre); err != nil {
				log.Fatal(err)
			}
			if g.ClienteID != "" {
				if err := st.RevocarGrants(ctx, u.ID, g.ClienteID); err != nil {
					log.Fatal(err)
				}
			}
			fmt.Printf("%s ya no puede usar %s\n", u.Email, g.Nombre)
			return
		case "vincular":
			if len(os.Args) != 4 {
				log.Fatal("uso: account vincular <grupo> <client_id>")
			}
			if err := st.VincularCliente(context.Background(), os.Args[2], os.Args[3]); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s ← %s\n", os.Args[2], os.Args[3])
			return
		default:
			log.Fatalf("orden desconocida: %s", os.Args[1])
		}
	}

	gt := gotrue.New(cfg.GoTrueURL, cfg.AnonKey, cfg.ServiceKey)
	ses, err := session.New(cfg.SessionKey, cfg.CookieSecure(), cfg.SessionTTL, cfg.RememberTTL, st, gt)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := httpapi.New(cfg, st, gt, ses)
	if err != nil {
		log.Fatalf("plantillas: %v", err)
	}

	// Las sesiones caducadas se barren cada hora; no hace falta más.
	go func() {
		for {
			time.Sleep(time.Hour)
			if n, err := st.PurgarSesiones(context.Background()); err == nil && n > 0 {
				log.Printf("sesiones caducadas purgadas: %d", n)
			}
		}
	}()

	h := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		log.Printf("account escuchando en %s (público %s)", cfg.Addr, cfg.PublicURL)
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.Shutdown(ctx)
	log.Print("account parado")
}

// sonda pega a la salud del propio proceso. Sale 0 si está bien.
func sonda() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3467"
	}
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/api/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "salud:", resp.Status)
		return 1
	}
	return 0
}
