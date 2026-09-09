# Para agentes

Esta es la app de cuenta de KaiCorp Labs. Antes de tocarla, lee `docs/DISENO.md`: qué decide GoTrue y qué decide esta app,
y por qué el orden del consentimiento es el que es.

Reglas que no se negocian aquí:

- **Nada de JavaScript ni de inline**: la CSP es `script-src 'none'`. Si una
  función lo necesita de verdad (WebAuthn), se añade un fichero en
  `internal/web/static/js/` y se abre la CSP sólo para `'self'`, con el porqué.
- **La política va antes que GoTrue**: en `/oauth/consent` se mira en la base
  qué cliente pide y si la persona es miembro ANTES de pedir los detalles a
  GoTrue, porque esa llamada aprueba sola si hay grant previo.
- **Sin enumerar correos**: registro, recuperación y entrada responden igual
  exista la cuenta o no.
- **Ninguna sesión de la app existe sin haber pasado el factor**: entre la
  contraseña y el código, los tokens van en una cookie sellada de cinco minutos.
- El SQL vive en `internal/store`; los permisos sobre `auth.*` en
  `db/bootstrap.sql`, con su motivo cada uno. No se añade un permiso sin él.
- Interfaz en inglés, comentarios en español, como el resto de la casa.
- `go test ./... && go vet ./... && gofmt -l .` antes de cualquier commit.
