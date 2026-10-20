package correo

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlantillasCambioCorreoSeparanLosBuzones(t *testing.T) {
	r, err := Nuevo("smtp.example.com", "587", "usuario", "clave", "KaiCorp Labs <account@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	datos := CambioCorreo{
		Cuenta:    "https://account.example.com/security-overview",
		Confirmar: "https://account.example.com/cuenta/correo/confirmar#token=secreto-opaco",
	}
	var actual, propuesta bytes.Buffer
	if err := r.cambioIniciado.Execute(&actual, datos); err != nil {
		t.Fatal(err)
	}
	if err := r.cambioConfirmar.Execute(&propuesta, datos); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(actual.String(), datos.Cuenta) || strings.Contains(actual.String(), datos.Confirmar) {
		t.Fatalf("el aviso al buzón actual mezcló la prueba propuesta: %s", actual.String())
	}
	if !strings.Contains(propuesta.String(), "token=secreto-opaco") || strings.Contains(propuesta.String(), datos.Cuenta) {
		t.Fatalf("la prueba al buzón propuesto mezcló datos del actual: %s", propuesta.String())
	}
}
