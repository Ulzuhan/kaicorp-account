package store

import (
	"errors"
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

func TestCorteCredencialSerializaCreacionConCambioPassword(t *testing.T) {
	s, _ := storeVinculos(t)
	now := time.Now().Unix()
	actual := sesionParaCorte("actual", personaUno, now)
	if err := s.CrearSesion(t.Context(), actual); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotarPortadorSesion(t.Context(), actual.ID, "rotada"); err != nil {
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
