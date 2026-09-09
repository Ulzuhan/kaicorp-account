# Diseño de la app de cuenta

*Septiembre de 2026. Fase 2 de `historia/41` de kaicorplabs-infra.*

## Reparto: qué hace GoTrue y qué hace esta app

| GoTrue (Supabase Auth) | Esta app |
|---|---|
| Cuentas, contraseñas, confirmación de correo, recuperación | Las pantallas de todo eso, con la marca de la casa |
| Segundo factor (TOTP hoy; WebAuthn en el binario, sin pantalla aún) | Alta, reto y verificación desde `/cuenta` y al entrar |
| Emisor OIDC: discovery, authorize, token, userinfo, grants | **La pantalla de consentimiento y la política**: quién puede entrar a qué |
| Sus sesiones y refresh tokens | Sesiones propias que los envuelven, cifrados, en `account.sesiones` |
| Auditoría (`auth.audit_log_entries`) | Membresías y solicitudes (`account.*`), que son la historia de quién aprobó qué |
| Envío de correo (SMTP) | Las plantillas, servidas en `/plantillas/*.html` |

## Decisiones

1. **Plantillas Go y cero JavaScript**, no React. La casa había migrado tres
   servicios a React + Go, pero una interfaz de autenticación es formularios y
   redirecciones; sin scripts la CSP es `script-src 'none'`, no hay build ni
   dependencias de npm que auditar, y el cromado se calca de LinkUp, que ya lo
   tenía en plantillas Go. WebAuthn necesitará un fichero JS: cuando llegue, se
   abre la CSP para `'self'` y nada más.
2. **La política se comprueba antes de hablar con GoTrue.** `GET
   /oauth/authorizations/{id}` aprueba solo si la persona ya autorizó ese
   cliente. Por eso el cliente de la autorización se lee de
   `auth.oauth_authorizations` y la membresía se decide primero; a GoTrue sólo
   se le pide algo cuando la respuesta ya es «puede».
3. **Revocar una membresía revoca el grant** (`auth.oauth_consents.revoked_at`).
   Sin esto, quitarle a alguien una herramienta no le quitaría nada: GoTrue
   seguiría aprobando en silencio.
4. **Sesiones de la app en la base, cookie opaca, tokens cifrados.** Permite
   listarlas y cerrarlas (la persona las suyas, un administrador las de otro),
   y ningún token de GoTrue viaja en cookies. AES-GCM con `ACCOUNT_SESSION_KEY`.
5. **Ninguna sesión sin factor.** Si la cuenta tiene un factor verificado, los
   tokens aal1 no se convierten en sesión: van sellados en `account_mfa` cinco
   minutos hasta que el código los cambia por aal2.
6. **CSRF por doble envío firmado** (`account_csrf` + HMAC), porque el login y
   el registro son POST sin sesión.
7. **No se enumeran correos**: registro, recuperación y entrada dan la misma
   respuesta exista o no la cuenta. GoTrue ya lo hace por su lado (devuelve una
   ficha falsa en el registro de un correo existente); esta app no lo deshace.
8. **Permisos acotados sobre `auth`** en vez de la clave de servicio para todo.
   La clave de servicio sólo bloquea y borra cuentas; lo demás son `select` y
   dos escrituras concretas, enumeradas en `db/bootstrap.sql` con su motivo.
9. **Aprobación humana la primera vez, automática después**, el modelo de la
   casa desde agosto (`historia/23`): se decide sobre la persona, una vez.
10. **La primera cuenta administradora se da por CLI** (`account admin
    <correo>`), no por interfaz: no hay «primer usuario es admin».

## Lo que no está (todavía)

- WebAuthn como segundo factor: GoTrue lo trae; falta la pantalla y su JS.
- Aviso por correo a la persona cuando se aprueba su solicitud: GoTrue no
  manda correos arbitrarios; hará falta Resend por HTTP desde esta app
  (egress 443 para su contenedor), o el `aprobar.py` de la casa.
- Cambio de correo desde `/cuenta` (GoTrue lo soporta; la pantalla no está).
- Borrar una cuenta desde la interfaz: a propósito no. Es `borrar-persona.py`,
  que borra también lo que cada herramienta guarda.

## Rutas

| Ruta | Qué |
|---|---|
| `GET /` | Tus herramientas, o la portada si no hay sesión |
| `/entrar`, `/registro`, `/recuperar`, `/restablecer`, `/factor`, `POST /salir` | Entrada, alta, recuperación, segundo factor |
| `GET /verificar?token_hash&type&next` | Canje de los enlaces de correo (signup, invite, email_change, magiclink) |
| `POST /solicitar/{grupo}` | Pedir una herramienta (pendiente o automática según la política) |
| `GET/POST /oauth/consent` | El consentimiento OAuth, con la política delante |
| `/cuenta/*` | Nombre, contraseña, factores, herramientas autorizadas, sesiones |
| `/admin/*` | Solicitudes, cuentas, membresías, clientes ↔ grupos, cerrar sesiones, bloquear |
| `GET /plantillas/{nombre}` | Plantillas de correo para GoTrue |
| `GET /api/health` | 200 si la base y GoTrue responden |
