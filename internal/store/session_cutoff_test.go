package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func sesionParaCorte(id, userID string, emitido int64) *Sesion {
	now := time.Now()
	return &Sesion{
		ID: id, UserID: userID, Email: "test@example.com", AAL: "aal1",
		AccessToken: []byte("access"), RefreshToken: []byte("refresh"),
		AccessExpira: now.Add(time.Hour), Expira: now.Add(time.Hour), Emitido: emitido,
	}
}

func TestCambioCredencialSerializaMutacionesPorPersona(t *testing.T) {
	s, _ := storeVinculos(t)
	emitido := time.Now().Unix()
	primeraDentro := make(chan struct{})
	continuar := make(chan struct{})
	var llamadas atomic.Int32
	primera := make(chan error, 1)
	go func() {
		_, err := s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) {
			llamadas.Add(1)
			close(primeraDentro)
			<-continuar
			return true, nil
		})
		primera <- err
	}()
	select {
	case <-primeraDentro:
	case <-time.After(5 * time.Second):
		t.Fatal("la primera mutación no entró")
	}
	segunda := make(chan error, 1)
	go func() {
		_, err := s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) {
			llamadas.Add(1)
			return true, nil
		})
		segunda <- err
	}()
	select {
	case err := <-segunda:
		t.Fatalf("la segunda mutación no esperó el bloqueo: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(continuar)
	if err := <-primera; err != nil {
		t.Fatal(err)
	}
	if err := <-segunda; !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("la segunda mutación alcanzó al proveedor: %v", err)
	}
	if llamadas.Load() != 1 {
		t.Fatalf("se ejecutaron %d mutaciones remotas", llamadas.Load())
	}
}

func TestSesionDeCambioExigeGeneracionActual(t *testing.T) {
	s, _ := storeVinculos(t)
	primeraIAT := time.Now().Unix()
	primera, err := s.CambiarCredencial(t.Context(), personaUno, primeraIAT, nil, func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	segunda, err := s.CambiarCredencial(t.Context(), personaUno, primeraIAT+60, nil, func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	if primera == segunda {
		t.Fatalf("la generación no avanzó: %d", primera)
	}
	if err := s.CrearSesionUnicaEnGeneracion(t.Context(), sesionParaCorte("anterior", personaUno, primeraIAT), primera); !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("la sesión de la mutación anterior se publicó: %v", err)
	}
	if err := s.CrearSesionUnicaEnGeneracion(t.Context(), sesionParaCorte("ganadora", personaUno, primeraIAT+60), segunda); err != nil {
		t.Fatalf("la sesión ganadora no se publicó: %v", err)
	}
}

func TestGeneracionLigadaNoSeRejuveneceConOtroToken(t *testing.T) {
	s, _ := storeVinculos(t)
	antigua, err := s.GeneracionCredencial(t.Context(), personaUno)
	if err != nil {
		t.Fatal(err)
	}
	nueva, err := s.CambiarCredencialAdministrativa(t.Context(), personaUno, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if nueva <= antigua {
		t.Fatalf("la rotación administrativa no avanzó la generación: antes=%d después=%d", antigua, nueva)
	}
	llamada := false
	_, err = s.CambiarCredencial(t.Context(), personaUno, time.Now().Add(time.Hour).Unix(), &antigua, func() (bool, error) {
		llamada = true
		return true, nil
	})
	if !errors.Is(err, ErrCredencialAnterior) || llamada {
		t.Fatalf("una intención antigua se rejuveneció con otro token: llamada=%v err=%v", llamada, err)
	}
}

func TestRechazoConocidoConservaCredencial(t *testing.T) {
	s, _ := storeVinculos(t)
	emitido := time.Now().Unix()
	rechazo := errors.New("política de password")
	if generacion, err := s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) { return false, rechazo }); generacion != 0 || !errors.Is(err, rechazo) {
		t.Fatalf("rechazo conocido inesperado: generación=%d err=%v", generacion, err)
	}
	if _, err := s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) { return true, nil }); err != nil {
		t.Fatalf("el rechazo conocido consumió la credencial: %v", err)
	}
}

func TestResultadoAmbiguoAvanzaGeneracion(t *testing.T) {
	s, _ := storeVinculos(t)
	emitido := time.Now().Unix()
	ambiguo := errors.New("respuesta remota ambigua")
	generacion, err := s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) { return true, ambiguo })
	if generacion <= 0 || !errors.Is(err, ambiguo) {
		t.Fatalf("resultado ambiguo no invalidó: generación=%d err=%v", generacion, err)
	}
	llamada := false
	_, err = s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) {
		llamada = true
		return true, nil
	})
	if !errors.Is(err, ErrCredencialAnterior) || llamada {
		t.Fatalf("la credencial sobrevivió al resultado ambiguo: llamada=%v err=%v", llamada, err)
	}
}

func TestResultadoAmbiguoConPeticionCanceladaAvanzaGeneracion(t *testing.T) {
	s, _ := storeVinculos(t)
	emitido := time.Now().Unix()
	ctx, cancelar := context.WithCancel(t.Context())
	generacion, err := s.CambiarCredencial(ctx, personaUno, emitido, nil, func() (bool, error) {
		cancelar()
		return true, context.Canceled
	})
	if generacion <= 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("la cancelación dejó el cambio sin corte durable: generación=%d err=%v", generacion, err)
	}
	llamada := false
	_, err = s.CambiarCredencial(t.Context(), personaUno, emitido, nil, func() (bool, error) {
		llamada = true
		return true, nil
	})
	if !errors.Is(err, ErrCredencialAnterior) || llamada {
		t.Fatalf("la autoridad previa sobrevivió a la cancelación: llamada=%v err=%v", llamada, err)
	}
}

func TestCorteCredencialSerializaCreacionConCambioPassword(t *testing.T) {
	s, _ := storeVinculos(t)
	now := time.Now().Unix()
	actual := sesionParaCorte("actual", personaUno, now)
	if err := s.CrearSesion(t.Context(), actual); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotarPortadorSesion(t.Context(), actual.ID, "rotada", actual.AccessToken, actual.RefreshToken, actual.AccessExpira); err != nil {
		t.Fatal(err)
	}
	if err := s.CrearSesion(t.Context(), sesionParaCorte("tardia", personaUno, now-60)); !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("una ficha anterior reapareció tras el cambio: %v", err)
	}

	// Mantiene abierto exactamente el tramo crítico de un cambio. La creación
	// concurrente debe esperar al mismo advisory lock y, al continuar, observar
	// el corte ya confirmado en vez de insertar una fila invisible al DELETE.
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := bloquearSesionesPersona(t.Context(), tx, personaDos); err != nil {
		t.Fatal(err)
	}
	if err := avanzarCorteCredencial(t.Context(), tx, personaDos); err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() {
		fin <- s.CrearSesion(t.Context(), sesionParaCorte("concurrente", personaDos, now-60))
	}()
	select {
	case err := <-fin:
		t.Fatalf("la creación no esperó al cambio concurrente: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-fin; !errors.Is(err, ErrCredencialAnterior) {
		t.Fatalf("la creación concurrente sobrevivió al corte: %v", err)
	}
	if sesiones, err := s.SesionesDe(t.Context(), personaDos); err != nil || len(sesiones) != 0 {
		t.Fatalf("quedó una sesión concurrente: %d %v", len(sesiones), err)
	}
}
