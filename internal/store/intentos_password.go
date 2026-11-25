package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	ventanaIntentosPassword = 15 * time.Minute
	primerBackoffPassword   = 10
	maxIntentosPassword     = 1_000_000
)

type estadoIntentoPassword struct {
	cliente     string
	intentos    int
	noAntes     time.Time
	actualizado time.Time
}

// pausaIntentoPassword conserva una ráfaga inicial compatible con el límite
// HTTP local y, desde el décimo intento, aplica 1, 2, 4... hasta 60 segundos.
func pausaIntentoPassword(intentos int) time.Duration {
	if intentos < primerBackoffPassword {
		return 0
	}
	exponente := intentos - primerBackoffPassword
	if exponente >= 6 {
		return time.Minute
	}
	return time.Second * time.Duration(1<<exponente)
}

// ReservarIntentoPassword reserva atómicamente un intento antes de consultar
// al proveedor. Bloquea siempre primero el agregado del sujeto y después su
// par con el cliente, de modo que dos réplicas no puedan exceder la ráfaga.
// Una duración positiva significa que no se reservó nada y el proveedor no
// debe recibir la contraseña.
func (s *Store) ReservarIntentoPassword(ctx context.Context, tipo, sujeto, cliente string) (time.Duration, error) {
	if tipo != "usuario" && tipo != "correo" || sujeto == "" || cliente == "" {
		return 0, errors.New("identidad de límite de contraseña incompleta")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `delete from account.intentos_password where actualizado < clock_timestamp() - interval '24 hours'`); err != nil {
		return 0, fmt.Errorf("purgar intentos de contraseña: %w", err)
	}
	for _, claveCliente := range []string{"", cliente} {
		if _, err := tx.Exec(ctx, `insert into account.intentos_password(tipo,sujeto,cliente)
			values($1,$2,$3) on conflict do nothing`, tipo, sujeto, claveCliente); err != nil {
			return 0, fmt.Errorf("crear presupuesto de contraseña: %w", err)
		}
	}

	estados := make([]estadoIntentoPassword, 0, 2)
	for _, claveCliente := range []string{"", cliente} {
		var estado estadoIntentoPassword
		estado.cliente = claveCliente
		if err := tx.QueryRow(ctx, `select intentos,no_antes,actualizado
			from account.intentos_password where tipo=$1 and sujeto=$2 and cliente=$3 for update`,
			tipo, sujeto, claveCliente).Scan(&estado.intentos, &estado.noAntes, &estado.actualizado); err != nil {
			return 0, fmt.Errorf("bloquear presupuesto de contraseña: %w", err)
		}
		estados = append(estados, estado)
	}
	// clock_timestamp se toma después de adquirir ambos bloqueos: una petición
	// que esperó a otra réplica no decide con una hora anterior a esa espera.
	var ahora time.Time
	if err := tx.QueryRow(ctx, `select clock_timestamp()`).Scan(&ahora); err != nil {
		return 0, err
	}
	for i := range estados {
		if ahora.Sub(estados[i].actualizado) >= ventanaIntentosPassword {
			estados[i].intentos = 0
			estados[i].noAntes = ahora
		}
	}

	var espera time.Duration
	for _, estado := range estados {
		if restante := estado.noAntes.Sub(ahora); restante > espera {
			espera = restante
		}
	}
	if espera > 0 {
		if espera > time.Minute {
			espera = time.Minute
		}
		return espera, nil
	}

	for _, estado := range estados {
		if estado.intentos < maxIntentosPassword {
			estado.intentos++
		}
		pausa := pausaIntentoPassword(estado.intentos)
		if _, err := tx.Exec(ctx, `update account.intentos_password
			set intentos=$4,no_antes=$5,actualizado=$6
			where tipo=$1 and sujeto=$2 and cliente=$3`,
			tipo, sujeto, estado.cliente, estado.intentos, ahora.Add(pausa), ahora); err != nil {
			return 0, fmt.Errorf("reservar intento de contraseña: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return 0, nil
}

// AcreditarPassword reinicia sólo el presupuesto del sujeto y de este par de
// cliente. No existe un presupuesto global por IP que otra cuenta pueda
// limpiar para ayudar a atacar a la víctima.
func (s *Store) AcreditarPassword(ctx context.Context, tipo, sujeto, cliente string) error {
	if tipo != "usuario" && tipo != "correo" || sujeto == "" || cliente == "" {
		return errors.New("identidad de límite de contraseña incompleta")
	}
	_, err := s.pool.Exec(ctx, `delete from account.intentos_password
		where tipo=$1 and sujeto=$2 and cliente in ('',$3)`, tipo, sujeto, cliente)
	return err
}
