package policy

import "testing"

var herramientas = map[string]bool{"docdrop": true, "tabup": true, "secretdrop": true}

func TestSolicitarPrimeraVezQuedaPendiente(t *testing.T) {
	if d := Solicitar("docdrop", true, nil, herramientas); d != Pendiente {
		t.Fatalf("una cuenta sin nada debe quedar pendiente, no %s", d)
	}
}

func TestSolicitarSegundaHerramientaEsAutomatica(t *testing.T) {
	if d := Solicitar("tabup", true, []string{"docdrop"}, herramientas); d != Automatica {
		t.Fatalf("una cuenta ya aprobada recibe la segunda al momento, no %s", d)
	}
}

func TestUnRolNoCuentaComoAprobacionPrevia(t *testing.T) {
	if d := Solicitar("docdrop", true, []string{"linkup-admins"}, herramientas); d != Pendiente {
		t.Fatalf("un rol no es una herramienta aprobada; esperaba pendiente, no %s", d)
	}
}

func TestLoQueNoSePidesSeRechaza(t *testing.T) {
	if d := Solicitar("chorus", false, []string{"docdrop"}, herramientas); d != Rechazada {
		t.Fatalf("chorus no se pide: esperaba rechazada, no %s", d)
	}
}

func TestRepetirLoQueYaTienesEsIdempotente(t *testing.T) {
	if d := Solicitar("docdrop", true, []string{"docdrop"}, herramientas); d != Automatica {
		t.Fatalf("pedir lo que ya tienes se concede sin más, no %s", d)
	}
}

func TestPuedeEntrar(t *testing.T) {
	if PuedeEntrar("", []string{"docdrop"}) {
		t.Fatal("un cliente sin grupo vinculado no deja pasar a nadie")
	}
	if !PuedeEntrar("docdrop", []string{"tabup", "docdrop"}) {
		t.Fatal("miembro de docdrop debe entrar")
	}
	if PuedeEntrar("docdrop", []string{"tabup"}) {
		t.Fatal("sin membresía no se entra")
	}
}

func TestAdministra(t *testing.T) {
	if !Administra("account-admin", []string{"account-admin"}) || Administra("account-admin", []string{"docdrop"}) {
		t.Fatal("sólo el grupo de administración administra")
	}
}
