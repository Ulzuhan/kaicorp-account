package store

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func replicaStore(t *testing.T, original *Store) *Store {
	t.Helper()
	pool, err := pgxpool.NewWithConfig(t.Context(), original.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
}

func TestPausaIntentosPasswordProgresaYSeAcota(t *testing.T) {
	casos := map[int]time.Duration{
		9: 0, 10: time.Second, 11: 2 * time.Second, 15: 32 * time.Second, 16: time.Minute, 100: time.Minute,
	}
	for intentos, esperado := range casos {
		if got := pausaIntentoPassword(intentos); got != esperado {
			t.Fatalf("%d intentos: pausa=%s, quería %s", intentos, got, esperado)
		}
	}
}

func TestIntentosPasswordPersistenEntreReplicasEIPs(t *testing.T) {
	primera, _ := storeVinculos(t)
	segunda := replicaStore(t, primera)
	for i := 0; i < 10; i++ {
		espera, err := []*Store{primera, segunda}[i%2].ReservarIntentoPassword(t.Context(), "usuario", personaUno,
			fmt.Sprintf("198.51.100.%d", i+1))
		if err != nil || espera != 0 {
			t.Fatalf("reserva %d: espera=%s err=%v", i+1, espera, err)
		}
	}
	espera, err := segunda.ReservarIntentoPassword(t.Context(), "usuario", personaUno, "203.0.113.200")
	if err != nil {
		t.Fatal(err)
	}
	if espera <= 0 || espera > time.Minute {
		t.Fatalf("la IP nueva reinició el presupuesto compartido: %s", espera)
	}
	if err := primera.AcreditarPassword(t.Context(), "usuario", personaUno, "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if espera, err := segunda.ReservarIntentoPassword(t.Context(), "usuario", personaUno, "203.0.113.201"); err != nil || espera != 0 {
		t.Fatalf("una prueba válida no reinició el agregado: espera=%s err=%v", espera, err)
	}
}

func TestIntentosPasswordReservanAtomicos(t *testing.T) {
	primera, _ := storeVinculos(t)
	segunda := replicaStore(t, primera)
	var admitidos atomic.Int32
	var bloqueados atomic.Int32
	errores := make(chan error, 20)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			espera, err := []*Store{primera, segunda}[i%2].ReservarIntentoPassword(t.Context(), "usuario", personaDos, "203.0.113.10")
			if err != nil {
				errores <- err
				return
			}
			if espera > 0 {
				bloqueados.Add(1)
			} else {
				admitidos.Add(1)
			}
		}(i)
	}
	wg.Wait()
	close(errores)
	for err := range errores {
		t.Fatal(err)
	}
	if admitidos.Load() != 10 || bloqueados.Load() != 10 {
		t.Fatalf("reservas concurrentes: admitidas=%d bloqueadas=%d", admitidos.Load(), bloqueados.Load())
	}
}
