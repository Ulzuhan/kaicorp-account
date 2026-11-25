package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRevocarSesionesCierraCarreraYFiltraSuperviviente(t *testing.T) {
	s, db := storeVinculos(t)
	antigua := time.Now().Add(-time.Minute).Unix()
	if err := s.CrearSesion(t.Context(), sesionParaCorte("antes-revocacion", personaUno, antigua)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `insert into auth.sessions(user_id) values ($1)`, personaUno); err != nil {
		t.Fatal(err)
	}

	if err := s.RevocarSesiones(t.Context(), personaUno); err != nil {
		t.Fatal(err)
	}
	var proveedor, locales int
	if err := db.QueryRow(t.Context(), `select
		(select count(*) from auth.sessions where user_id=$1),
		(select count(*) from account.sesiones where user_id=$1)`, personaUno).Scan(&proveedor, &locales); err != nil {
		t.Fatal(err)
	}
	if proveedor != 0 || locales != 0 {
		t.Fatalf("la revocación no limpió ambas clases de sesión: proveedor=%d locales=%d", proveedor, locales)
	}
	var corte, reloj int64
	if err := db.QueryRow(t.Context(), `select sesiones_no_antes, extract(epoch from clock_timestamp())::bigint
		from account.cortes_credencial where user_id=$1`, personaUno).Scan(&corte, &reloj); err != nil {
		t.Fatal(err)
	}
	if reloj <= corte {
		t.Fatalf("la revocación se anunció dentro del segundo todavía rechazado: reloj=%d corte=%d", reloj, corte)
	}

	// Simula una fila física que sobrevivió o fue restaurada por fuera del
	// runtime. La generación durable debe hacerla inservible incluso si es aal2.
	if _, err := db.Exec(t.Context(), `insert into account.sesiones
		(id,user_id,email,aal,access_token,refresh_token,access_expira,expira,revocacion_generacion)
		values ('superviviente',$1,'test@example.com','aal2','a','r',now()+interval '1 hour',now()+interval '1 hour',0)`, personaUno); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sesion(t.Context(), "superviviente"); !errors.Is(err, ErrNoExiste) {
		t.Fatalf("una fila anterior a la revocación volvió a cargar: %v", err)
	}
	if sesiones, err := s.SesionesDe(t.Context(), personaUno); err != nil || len(sesiones) != 0 {
		t.Fatalf("una fila revocada apareció como sesión viva: %d %v", len(sesiones), err)
	}

	if err := s.CrearSesion(t.Context(), sesionParaCorte("publicacion-tardia", personaUno, antigua)); !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("un token anterior se publicó tras la revocación: %v", err)
	}
	// RevocarSesiones no anuncia el cierre hasta abandonar el segundo del
	// corte: un login iniciado después de la respuesta obtiene un iat admisible.
	fresca := reloj
	if err := s.CrearSesion(t.Context(), sesionParaCorte("entrada-nueva", personaUno, fresca)); err != nil {
		t.Fatalf("una autenticación posterior a la revocación dejó de funcionar: %v", err)
	}
	if _, err := s.Sesion(t.Context(), "entrada-nueva"); err != nil {
		t.Fatalf("la sesión nueva no quedó vigente: %v", err)
	}
}

func TestRevocacionSerializaPublicacionTardia(t *testing.T) {
	s, _ := storeVinculos(t)
	antigua := time.Now().Add(-time.Minute).Unix()
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := revocarSesionesLocalesTx(t.Context(), tx, personaDos); err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() {
		fin <- s.CrearSesion(t.Context(), sesionParaCorte("publicacion-en-vuelo", personaDos, antigua))
	}()
	select {
	case err := <-fin:
		t.Fatalf("la creación no esperó la frontera de revocación: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-fin; !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("el token obtenido antes del cierre se publicó después: %v", err)
	}
	if sesiones, err := s.SesionesDe(t.Context(), personaDos); err != nil || len(sesiones) != 0 {
		t.Fatalf("la carrera dejó una sesión: %d %v", len(sesiones), err)
	}
}

func TestRevocarSesionesIntentaAmbasLimpiezasYSePuedeReintentar(t *testing.T) {
	for _, tc := range []struct {
		nombre  string
		tabla   string
		mensaje string
	}{
		{nombre: "proveedor", tabla: "auth.sessions", mensaje: "proveedor"},
		{nombre: "local", tabla: "account.sesiones", mensaje: "locales"},
	} {
		t.Run(tc.nombre, func(t *testing.T) {
			s, db := storeVinculos(t)
			if err := s.CrearSesion(t.Context(), sesionParaCorte("fallo-"+tc.nombre, personaUno, time.Now().Unix())); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(t.Context(), `insert into auth.sessions(user_id) values ($1)`, personaUno); err != nil {
				t.Fatal(err)
			}
			funcion := "falla_cierre_" + tc.nombre
			trigger := "falla_cierre_" + tc.nombre
			if _, err := db.Exec(t.Context(), `create function `+funcion+`() returns trigger language plpgsql as
				'begin raise exception ''fallo de limpieza forzado''; end';
				create trigger `+trigger+` before delete on `+tc.tabla+` for each statement execute function `+funcion+`()`); err != nil {
				t.Fatal(err)
			}

			err := s.RevocarSesiones(t.Context(), personaUno)
			if err == nil || !strings.Contains(err.Error(), tc.mensaje) {
				t.Fatalf("el fallo de %s no se devolvió con contexto: %v", tc.nombre, err)
			}
			if _, err := db.Exec(t.Context(), `drop trigger `+trigger+` on `+tc.tabla+`; drop function `+funcion+`()`); err != nil {
				t.Fatal(err)
			}
			if err := s.RevocarSesiones(t.Context(), personaUno); err != nil {
				t.Fatalf("el reintento idempotente falló: %v", err)
			}
			var total int
			if err := db.QueryRow(t.Context(), `select
				(select count(*) from auth.sessions where user_id=$1)+
				(select count(*) from account.sesiones where user_id=$1)`, personaUno).Scan(&total); err != nil || total != 0 {
				t.Fatalf("el reintento dejó sesiones: total=%d err=%v", total, err)
			}
		})
	}
}
