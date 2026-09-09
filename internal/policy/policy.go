// Package policy son las reglas de acceso de la casa, escritas una vez y sin
// base de datos delante para poder probarlas: quién puede entrar a qué, qué
// pasa cuando alguien pide una herramienta, y quién administra.
//
// Las reglas (historia/23, historia/41):
//
//   - Cada cliente OAuth exige EXACTAMENTE un grupo. Sin membresía, la
//     autorización se deniega antes de que GoTrue emita nada.
//   - La PRIMERA herramienta la aprueba una persona: la solicitud queda
//     pendiente. Una cuenta que YA pertenece a algún grupo de herramienta es
//     una persona ya juzgada: la siguiente se le concede sola.
//   - Los roles (linkup-admins, account-admin, chorus) no se piden: se dan.
package policy

// Decision es lo que pasa con una solicitud.
type Decision int

const (
	// Pendiente: la lee una persona.
	Pendiente Decision = iota
	// Automatica: se concede al momento.
	Automatica
	// Rechazada: el grupo no se puede pedir.
	Rechazada
)

func (d Decision) String() string {
	switch d {
	case Automatica:
		return "automatica"
	case Rechazada:
		return "rechazada"
	default:
		return "pendiente"
	}
}

// Solicitar decide qué pasa cuando una persona pide `grupo`.
//   - solicitable: si el grupo admite peticiones.
//   - membresias: los grupos que ya tiene.
//   - herramientas: los grupos que son herramientas (solicitables), para saber
//     si la persona ya fue aprobada alguna vez. Un rol no cuenta como
//     aprobación previa.
func Solicitar(grupo string, solicitable bool, membresias []string, herramientas map[string]bool) Decision {
	if !solicitable {
		return Rechazada
	}
	for _, m := range membresias {
		if m == grupo {
			return Automatica // ya la tiene: conceder es idempotente
		}
	}
	for _, m := range membresias {
		if herramientas[m] {
			return Automatica
		}
	}
	return Pendiente
}

// PuedeEntrar dice si la persona pasa el consentimiento de un cliente que
// exige `grupoExigido`.
func PuedeEntrar(grupoExigido string, membresias []string) bool {
	if grupoExigido == "" {
		return false // un cliente sin grupo vinculado no deja pasar a nadie
	}
	for _, m := range membresias {
		if m == grupoExigido {
			return true
		}
	}
	return false
}

// Administra dice si la persona puede usar /admin.
func Administra(grupoAdmin string, membresias []string) bool {
	return PuedeEntrar(grupoAdmin, membresias)
}
