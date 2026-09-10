// account es la app de cuenta de KaiCorp Labs: registro, entrada, segundo
// factor, consentimiento OAuth y administración de membresías sobre una
// instancia propia de Supabase Auth.
//
//	account            arranca el servidor (por defecto)
//	account sonda      sonda de salud para el HEALTHCHECK de la imagen
//	account migrar     aplica las migraciones y sale
//	account admin <correo>                   da la membresía de administración
//	account ver <correo>                     enseña la cuenta: estado, membresías, solicitudes, sesiones
//	account invitar <correo> [grupo…]        invita (GoTrue manda el correo) y concede los grupos
//	account aprobar <correo> <grupo>         concede una herramienta (y cierra su solicitud)
//	account revocar <correo> <grupo|todo>    la quita y revoca el grant OAuth; `todo` lo quita todo y cierra sesiones
//	account bloquear <correo>                bloquea la cuenta y cierra todas sus sesiones
//	account desbloquear <correo>             levanta el bloqueo
//	account borrar <correo> [--de-verdad]    borra la cuenta y su rastro en esta app (en seco sin la marca)
//	account purgar [--de-verdad]             borra las cuentas sin confirmar más viejas que ACCOUNT_UNCONFIRMED_DAYS
//	account vincular <grupo> <client_id>     ata un cliente OAuth a su grupo
//
// Lo que sale por la salida estándar de `ver` va en columnas separadas por
// tabulador y con la primera palabra fija (id, correo, membresia…): lo leen
// personas y también herramientas (borrar-persona), así que no se reordena.
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
	"github.com/Ulzuhan/kaicorp-account/internal/correo"
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

	gt := gotrue.New(cfg.GoTrueURL, cfg.AnonKey, cfg.ServiceKey)
	if len(os.Args) > 1 {
		if err := orden(context.Background(), cfg, st, gt, os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	ses, err := session.New(cfg.SessionKey, cfg.CookieSecure(), cfg.SessionTTL, cfg.RememberTTL, st, gt)
	if err != nil {
		log.Fatal(err)
	}
	rem, err := correo.Nuevo(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)
	if err != nil {
		log.Fatalf("correo: %v", err)
	}
	if rem == nil {
		log.Print("sin ACCOUNT_SMTP_*: los accesos se conceden sin aviso por correo")
	}
	srv, err := httpapi.New(cfg, st, gt, ses, rem)
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
	// Las cuentas que se registraron y nunca confirmaron el correo se borran
	// una vez al día (GoTrue las guardaría para siempre). La primera pasada,
	// una hora después de arrancar: un arranque no es momento de borrar nada.
	if cfg.UnconfirmedDays > 0 {
		go func() {
			time.Sleep(time.Hour)
			for {
				if n, err := purgar(context.Background(), cfg, st, gt, true, log.Printf); err != nil {
					log.Printf("purga de cuentas sin confirmar: %v", err)
				} else if n > 0 {
					log.Printf("cuentas sin confirmar purgadas: %d", n)
				}
				time.Sleep(24 * time.Hour)
			}
		}()
	}

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

// orden ejecuta una orden de la línea de órdenes. Todas hablan con la misma
// base y el mismo GoTrue que el servidor, con la misma configuración.
func orden(ctx context.Context, cfg *config.Config, st *store.Store, gt *gotrue.Client, args []string) error {
	deVerdad := false
	var resto []string
	for _, a := range args {
		if a == "--de-verdad" {
			deVerdad = true
		} else {
			resto = append(resto, a)
		}
	}
	args = resto
	uso := func(s string) error { return fmt.Errorf("uso: account %s", s) }

	switch args[0] {
	case "migrar":
		log.Print("migraciones al día")
		return nil

	case "admin":
		if len(args) != 2 {
			return uso("admin <correo>")
		}
		u, err := cuenta(ctx, st, args[1])
		if err != nil {
			return err
		}
		if err := st.Conceder(ctx, u.ID, cfg.AdminGroup, "cli"); err != nil {
			return err
		}
		fmt.Printf("%s administra (%s)\n", u.Email, cfg.AdminGroup)
		return nil

	case "ver":
		if len(args) != 2 {
			return uso("ver <correo>")
		}
		return ver(ctx, st, args[1])

	case "invitar":
		// Crea la cuenta por invitación (GoTrue manda el correo) y le concede
		// los grupos de una vez, para traer a alguien con sus herramientas ya
		// puestas. Repetirlo sobre quien no ha aceptado reenvía el correo y
		// conserva el id.
		if len(args) < 2 {
			return uso("invitar <correo> [grupo…]")
		}
		for _, g := range args[2:] {
			if _, err := st.Grupo(ctx, g); err != nil {
				return fmt.Errorf("no hay grupo %q", g)
			}
		}
		u, err := gt.AdminInvite(ctx, args[1])
		if err != nil {
			return fmt.Errorf("invitar: %w", err)
		}
		for _, g := range args[2:] {
			if err := st.Conceder(ctx, u.ID, g, "cli"); err != nil {
				return err
			}
		}
		fmt.Printf("%s invitada · id %s · grupos: %s\n", u.Email, u.ID, strings.Join(args[2:], ", "))
		return nil

	case "aprobar":
		if len(args) != 3 {
			return uso("aprobar <correo> <grupo>")
		}
		u, err := cuenta(ctx, st, args[1])
		if err != nil {
			return err
		}
		g, err := st.Grupo(ctx, args[2])
		if err != nil {
			return fmt.Errorf("no hay grupo %q", args[2])
		}
		if err := st.Conceder(ctx, u.ID, g.Nombre, "cli"); err != nil {
			return err
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
		if g.URL != "" {
			if rem, err := correo.Nuevo(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom); err == nil && rem != nil {
				nombre := u.Nombre
				if nombre == "" {
					nombre = u.Email
				}
				if err := rem.EnviarAcceso(ctx, u.Email, correo.Acceso{Nombre: nombre, Herramienta: g.Titulo, URL: g.URL, Cuenta: cfg.PublicURL.String() + "/"}); err != nil {
					fmt.Printf("  (el aviso por correo no salió: %v)\n", err)
				} else {
					fmt.Println("  avisada por correo")
				}
			}
		}
		return nil

	case "revocar":
		if len(args) != 3 {
			return uso("revocar <correo> <grupo|todo>")
		}
		u, err := cuenta(ctx, st, args[1])
		if err != nil {
			return err
		}
		if args[2] == "todo" {
			// Todo: cada membresía con su grant, y además las sesiones del
			// proveedor y las de esta app. Quitar el grupo cierra la puerta para
			// la próxima vez; esto saca a quien ya está dentro.
			ms, err := st.MembresiasDe(ctx, u.ID)
			if err != nil {
				return err
			}
			for _, m := range ms {
				if err := revocarUna(ctx, st, u.ID, m.Grupo); err != nil {
					return err
				}
				fmt.Printf("%s ya no puede usar %s\n", u.Email, m.Grupo)
			}
			if err := st.CerrarSesionesGoTrue(ctx, u.ID); err != nil {
				return err
			}
			if err := st.BorrarSesionesDe(ctx, u.ID, ""); err != nil {
				return err
			}
			fmt.Printf("%s: sin membresías y sin sesiones\n", u.Email)
			return nil
		}
		if _, err := st.Grupo(ctx, args[2]); err != nil {
			return fmt.Errorf("no hay grupo %q", args[2])
		}
		if err := revocarUna(ctx, st, u.ID, args[2]); err != nil {
			return err
		}
		fmt.Printf("%s ya no puede usar %s\n", u.Email, args[2])
		return nil

	case "bloquear", "desbloquear":
		if len(args) != 2 {
			return uso(args[0] + " <correo>")
		}
		u, err := cuenta(ctx, st, args[1])
		if err != nil {
			return err
		}
		if args[0] == "desbloquear" {
			if err := gt.AdminBanUser(ctx, u.ID, "none"); err != nil {
				return err
			}
			fmt.Printf("%s puede volver a entrar\n", u.Email)
			return nil
		}
		// Bloqueada no puede entrar ni renovar tokens; las sesiones que ya
		// tenía se cierran aquí, o seguiría dentro hasta que caducasen.
		if err := gt.AdminBanUser(ctx, u.ID, "876000h"); err != nil {
			return err
		}
		if err := st.CerrarSesionesGoTrue(ctx, u.ID); err != nil {
			return err
		}
		if err := st.BorrarSesionesDe(ctx, u.ID, ""); err != nil {
			return err
		}
		fmt.Printf("%s bloqueada y sin sesiones\n", u.Email)
		return nil

	case "borrar":
		if len(args) != 2 {
			return uso("borrar <correo> [--de-verdad]")
		}
		return borrar(ctx, st, gt, args[1], deVerdad)

	case "purgar":
		if len(args) != 1 {
			return uso("purgar [--de-verdad]")
		}
		if cfg.UnconfirmedDays == 0 {
			return errors.New("ACCOUNT_UNCONFIRMED_DAYS=0: la purga está desactivada")
		}
		n, err := purgar(ctx, cfg, st, gt, deVerdad, func(f string, a ...any) { fmt.Printf(f+"\n", a...) })
		if err != nil {
			return err
		}
		if deVerdad {
			fmt.Printf("%d cuenta(s) sin confirmar borradas\n", n)
		} else {
			fmt.Printf("%d cuenta(s) sin confirmar de más de %d días; en seco, nada borrado (añade --de-verdad)\n", n, cfg.UnconfirmedDays)
		}
		return nil

	case "vincular":
		if len(args) != 3 {
			return uso("vincular <grupo> <client_id>")
		}
		if err := st.VincularCliente(ctx, args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("%s ← %s\n", args[1], args[2])
		return nil
	}
	return fmt.Errorf("orden desconocida: %s", args[0])
}

func cuenta(ctx context.Context, st *store.Store, correo string) (*store.Usuario, error) {
	u, err := st.UsuarioPorCorreo(ctx, correo)
	if err != nil {
		return nil, fmt.Errorf("no hay cuenta con el correo %s", correo)
	}
	return u, nil
}

// revocarUna quita una membresía y, si el grupo abre un cliente, revoca el
// grant: sin eso la herramienta seguiría renovando tokens hasta caducar.
func revocarUna(ctx context.Context, st *store.Store, userID, grupo string) error {
	if err := st.Revocar(ctx, userID, grupo); err != nil {
		return err
	}
	if g, err := st.Grupo(ctx, grupo); err == nil && g.ClienteID != "" {
		return st.RevocarGrants(ctx, userID, g.ClienteID)
	}
	return nil
}

// ver enseña una cuenta en columnas con tabulador y primera palabra fija.
func ver(ctx context.Context, st *store.Store, correo string) error {
	u, err := cuenta(ctx, st, correo)
	if err != nil {
		return err
	}
	estado := "activa"
	switch {
	case u.Bloqueada:
		estado = "bloqueada"
	case !u.Confirmada:
		estado = "sin confirmar"
	}
	fmt.Printf("id\t%s\ncorreo\t%s\nnombre\t%s\nestado\t%s\ncreada\t%s\n", u.ID, u.Email, u.Nombre, estado, u.Creada.UTC().Format("2006-01-02 15:04"))
	if u.UltimaEntr != nil {
		fmt.Printf("ultima-entrada\t%s\n", u.UltimaEntr.UTC().Format("2006-01-02 15:04"))
	} else {
		fmt.Println("ultima-entrada\tnunca")
	}
	if ms, err := st.MembresiasDe(ctx, u.ID); err == nil {
		for _, m := range ms {
			fmt.Printf("membresia\t%s\t%s\t%s\n", m.Grupo, m.Desde.UTC().Format("2006-01-02"), m.Por)
		}
	}
	if xs, err := st.SolicitudesDe(ctx, u.ID); err == nil {
		for _, x := range xs {
			fmt.Printf("solicitud\t%s\t%s\t%s\n", x.Grupo, x.Estado, x.Creada.UTC().Format("2006-01-02 15:04"))
		}
	}
	r, err := st.RastroDe(ctx, u.ID)
	if err != nil {
		return err
	}
	fmt.Printf("sesiones-app\t%d\nsesiones-proveedor\t%d\ngrants-vivos\t%d\n", r.Sesiones, r.SesionesProveedor, r.Grants)
	return nil
}

// borrar quita a una persona de esta app y del proveedor. En seco por defecto:
// cuenta y enseña, no toca. Los datos que cada herramienta guarda de ella no
// son de aquí: los borra borrar-persona antes de llamar a esto.
func borrar(ctx context.Context, st *store.Store, gt *gotrue.Client, correo string, deVerdad bool) error {
	u, err := cuenta(ctx, st, correo)
	if err != nil {
		return err
	}
	r, err := st.RastroDe(ctx, u.ID)
	if err != nil {
		return err
	}
	fmt.Printf("id\t%s\ncorreo\t%s\nmembresias\t%d\nsolicitudes\t%d\nsesiones-app\t%d\nsesiones-proveedor\t%d\ngrants-vivos\t%d\n",
		u.ID, u.Email, r.Membresias, r.Solicitudes, r.Sesiones, r.SesionesProveedor, r.Grants)
	if !deVerdad {
		fmt.Println("en-seco\tnada borrado; añade --de-verdad")
		return nil
	}
	if err := st.BorrarRastro(ctx, u.ID); err != nil {
		return fmt.Errorf("rastro en la app: %w", err)
	}
	// La cuenta del proveedor se lleva en cascada identidades, factores,
	// sesiones, refresh tokens y consentimientos OAuth.
	if err := gt.AdminDeleteUser(ctx, u.ID); err != nil {
		return fmt.Errorf("cuenta en el proveedor: %w", err)
	}
	fmt.Println("borrada\tla cuenta y su rastro en la app")
	return nil
}

// purgar borra las cuentas que se registraron solas y no confirmaron el correo
// en cfg.UnconfirmedDays días, y las filas huérfanas de la app. Devuelve
// cuántas cuentas había (y borró, si deVerdad).
func purgar(ctx context.Context, cfg *config.Config, st *store.Store, gt *gotrue.Client, deVerdad bool, decir func(string, ...any)) (int, error) {
	antes := time.Now().Add(-time.Duration(cfg.UnconfirmedDays) * 24 * time.Hour)
	us, err := st.SinConfirmar(ctx, antes)
	if err != nil {
		return 0, err
	}
	for _, u := range us {
		if !deVerdad {
			decir("sin confirmar\t%s\tcreada %s", u.Email, u.Creada.UTC().Format("2006-01-02"))
			continue
		}
		if err := st.BorrarRastro(ctx, u.ID); err != nil {
			return 0, err
		}
		if err := gt.AdminDeleteUser(ctx, u.ID); err != nil {
			return 0, fmt.Errorf("%s: %w", u.Email, err)
		}
		decir("cuenta sin confirmar borrada: %s (creada %s)", u.Email, u.Creada.UTC().Format("2006-01-02"))
	}
	if deVerdad {
		if n, err := st.PurgarHuerfanos(ctx); err != nil {
			return len(us), err
		} else if n > 0 {
			decir("filas huérfanas de la app borradas: %d", n)
		}
	}
	return len(us), nil
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
