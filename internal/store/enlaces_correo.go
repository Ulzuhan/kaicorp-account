package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const salEnlaceCorreo int64 = 730023

var errEnlaceCorreoAmbiguo = errors.New("enlace de correo ambiguo")

// bloqueoEnlaceCorreo conserva un bloqueo asesor de sesión en una conexión
// exclusiva. Abarca deliberadamente /verify: dos mitades de un cambio seguro
// nunca pueden presentar a GoTrue el mismo snapshot de fase cero.
type bloqueoEnlaceCorreo struct {
	conn   *pgxpool.Conn
	unaVez sync.Once
}

func (b *bloqueoEnlaceCorreo) cerrar() {
	if b == nil {
		return
	}
	b.unaVez.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := b.conn.Exec(ctx, `select pg_advisory_unlock_all()`); err != nil {
			conn := b.conn.Hijack()
			_ = conn.Close(ctx)
			return
		}
		b.conn.Release()
	})
}

// EnlaceCorreoPendiente es la identidad que GoTrue ligó a un hash todavía
// pendiente. Destinatario es el buzón que recibió ese enlace concreto; EmailFinal
// es el correo que debe tener la identidad cuando el canje termina. En un cambio
// seguro pueden diferir: el enlace del buzón antiguo confirma al mismo usuario,
// cuyo correo final será el nuevo.
type EnlaceCorreoPendiente struct {
	UserID       string
	Destinatario string
	EmailFinal   string
	Hasta        time.Time
	bloqueo      *bloqueoEnlaceCorreo
}

// Cerrar libera la exclusión por usuario adquirida al resolver el enlace. El
// handler debe conservarla hasta que termine la llamada a /verify.
func (e *EnlaceCorreoPendiente) Cerrar() {
	if e != nil {
		e.bloqueo.cerrar()
	}
}

type lectorFila interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const consultaEnlaceCorreo = `with pendientes as (
	select u.id::text as user_id, ott.relates_to as destinatario,
		case when $1='email_change' then u.email_change else u.email end as email_final,
		case
			when $1 in ('signup','invite') then u.confirmation_sent_at
			when $1='recovery' then u.recovery_sent_at
			when $1='email_change' then u.email_change_sent_at
		end as emitido
	from auth.one_time_tokens ott
	join auth.users u on u.id=ott.user_id
	where ott.token_hash=$2 and u.deleted_at is null
	  and (
		($1='signup' and ott.token_type::text='confirmation_token'
			and u.email_confirmed_at is null and u.invited_at is null
			and lower(btrim(ott.relates_to))=lower(btrim(coalesce(u.email,''))))
		or ($1='invite' and ott.token_type::text='confirmation_token'
			and u.email_confirmed_at is null and u.invited_at is not null
			and lower(btrim(ott.relates_to))=lower(btrim(coalesce(u.email,''))))
		or ($1='recovery' and ott.token_type::text='recovery_token'
			and lower(btrim(ott.relates_to))=lower(btrim(coalesce(u.email,''))))
		or ($1='email_change' and ott.token_type::text='email_change_token_current'
			and u.email_change_confirm_status in (0,1) and coalesce(u.email_change,'')<>''
			and lower(btrim(ott.relates_to))=lower(btrim(coalesce(u.email,''))))
		or ($1='email_change' and ott.token_type::text='email_change_token_new'
			and u.email_change_confirm_status in (0,1) and coalesce(u.email_change,'')<>''
			and lower(btrim(ott.relates_to))=lower(btrim(u.email_change)))
	  )
)
select user_id, destinatario, email_final, emitido, count(*) over()
from pendientes where emitido is not null limit 1`

func resolverEnlaceCorreoCon(ctx context.Context, q lectorFila, tipo, hash string, vida time.Duration) (*EnlaceCorreoPendiente, error) {
	var enlace EnlaceCorreoPendiente
	var emitido time.Time
	var coincidencias int64
	err := q.QueryRow(ctx, consultaEnlaceCorreo, tipo, hash).Scan(
		&enlace.UserID, &enlace.Destinatario, &enlace.EmailFinal, &emitido, &coincidencias)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoExiste
	}
	if err != nil {
		return nil, err
	}
	if coincidencias != 1 {
		return nil, errEnlaceCorreoAmbiguo
	}
	enlace.Hasta = emitido.Add(vida)
	if enlace.Hasta.Before(emitido) {
		return nil, fmt.Errorf("vida de enlace de correo fuera de rango")
	}
	if !time.Now().Before(enlace.Hasta) {
		return nil, ErrNoExiste
	}
	return &enlace, nil
}

// ResolverEnlaceCorreo consulta auth.one_time_tokens, la misma fuente de verdad
// que /verify consume. Después toma un bloqueo por usuario y relee bajo ese
// bloqueo: el hash queda ligado a propósito, buzón, usuario y caducidad antes de
// cruzar la frontera irreversible del proveedor, y ninguna otra confirmación
// de la misma identidad puede adelantarse hasta que Cerrar libere el bloqueo.
func (s *Store) ResolverEnlaceCorreo(ctx context.Context, tipo, hash string, vida time.Duration) (*EnlaceCorreoPendiente, error) {
	if vida <= 0 {
		return nil, errors.New("vida de enlace de correo no configurada")
	}
	previo, err := resolverEnlaceCorreoCon(ctx, s.pool, tipo, hash, vida)
	if err != nil {
		return nil, err
	}
	pool := s.autoridadPool
	if pool == nil {
		pool = s.pool
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	bloqueo := &bloqueoEnlaceCorreo{conn: conn}
	fallar := func(err error) (*EnlaceCorreoPendiente, error) {
		bloqueo.cerrar()
		return nil, err
	}
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(hashtextextended($1::uuid::text,$2))`, previo.UserID, salEnlaceCorreo); err != nil {
		return fallar(err)
	}
	enlace, err := resolverEnlaceCorreoCon(ctx, conn, tipo, hash, vida)
	if err != nil {
		return fallar(err)
	}
	if enlace.UserID != previo.UserID {
		return fallar(errEnlaceCorreoAmbiguo)
	}
	enlace.bloqueo = bloqueo
	return enlace, nil
}
