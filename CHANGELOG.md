# Cambios

## 0.8.0 — 2026-09-12

- **Reenviar una invitación, desde la ficha de la persona.** Repetir la
  invitación ya reenviaba el correo y conservaba id y membresías, pero nada en
  el panel lo decía, así que en la práctica no existía: el 12-09 hubo cuatro
  invitaciones caducadas y quien administra no tenía forma de saber que bastaba
  con repetirlas. Ahora, en `/admin/cuenta/{id}` de quien no ha aceptado, hay una
  tarjeta con el botón y la explicación de qué cambia y qué no.
- **Cuándo se invitó a cada quien.** La ficha dice «invited 3 days ago» y la
  fecha exacta; la lista de `/admin` acompaña el «Unconfirmed» con el día. Sin
  ese dato, «sin confirmar» no distingue a quien se invitó esta mañana de quien
  lleva un mes con un enlace muerto.
- No se afirma si el enlace ha caducado, a propósito: el plazo lo fija GoTrue
  con `GOTRUE_MAILER_OTP_EXP` y no esta aplicación, así que una etiqueta aquí
  podría desincronizarse y mentir. Reenviar es inofensivo en cualquier caso.

## 0.7.0 — 2026-09-11

- Passkeys como segundo factor, opcionales, junto al autenticador TOTP. Se dan de
  alta en Seguridad («Add a passkey»: el navegador pide huella, cara, PIN o
  llave) y al entrar se ofrecen antes que el código; quien tenga las dos cosas
  elige. GoTrue las guarda como factores `webauthn` (hacen falta
  `GOTRUE_MFA_WEB_AUTHN_ENROLL_ENABLED` y `_VERIFY_ENABLED`); el RP ID es el
  host público de la app.
- El primer y único script: `static/js/passkey.js`, porque WebAuthn sólo existe
  en el navegador. Convierte las opciones de GoTrue, llama a
  `navigator.credentials` y envía la credencial por el formulario; sin red
  desde el navegador. La CSP pasa de `script-src 'none'` a `'self'`; nada inline.
- La forma de la API WebAuthn de GoTrue 2.189 va en camelCase (`rpId`,
  `rpOrigins`) y con `type` create/request, al revés que el resto: está en el
  cliente, con cómo se averiguó.

## 0.6.0 — 2026-09-11

- Cambio de correo desde Seguridad. GoTrue manda un enlace a la dirección vieja
  y otro a la nueva (cambio seguro, el valor por defecto) y no cambia nada hasta
  que se abren los dos; por eso no se vuelve a pedir la contraseña: quien robe
  una sesión no tiene el buzón viejo. `/verificar` distingue el primer enlace
  («one confirmed, one to go») del segundo, que pone el correo nuevo en las
  sesiones de la app y vuelve a Seguridad. Tres intentos cada diez minutos por IP.
- La plantilla `cambio-correo.html` habla a las dos direcciones (dice de cuál a
  cuál, y a quién se envió con `SendingTo`).

## 0.5.0 — 2026-09-10

- Invitar desde `/admin`: el correo y las herramientas que tendrá al llegar.
  GoTrue manda el enlace y las membresías quedan puestas, sin nada que aprobar.
  Invitar a quien aún no ha aceptado reenvía sobre la misma cuenta; a quien ya
  tiene cuenta se le conceden las herramientas desde su ficha.
- Cuentas sin confirmar: las que se registraron solas y no confirmaron el correo
  en `ACCOUNT_UNCONFIRMED_DAYS` días (14 por defecto; 0 desactiva) se borran una
  vez al día, con su rastro en la app. Las invitadas no se tocan. `account
  purgar [--de-verdad]` lo hace a mano y enseña qué borraría.
- Línea de órdenes: `ver <correo>` (estado, membresías, solicitudes, sesiones y
  grants, en columnas con tabulador y primera palabra fija, para personas y para
  herramientas), `borrar <correo> [--de-verdad]` (el rastro en la app y la cuenta
  en GoTrue; en seco por defecto), `revocar <correo> todo` (todas las
  membresías, sus grants y todas las sesiones), `bloquear` y `desbloquear`.
- Los correos llevan la paleta de la web: fondo `#05070d`, tarjeta `#0c1019`,
  acento `#45e0f5`, textos `#e6ecf5` / `#9fb0c8` / `#6b7c94`.
- Una prueba compila todas las plantillas con el layout y falla si hay una
  plantilla fuera de la lista (el «plantilla desconocida» de 0.3.3).

## 0.4.3 — 2026-09-10

- El consentimiento comprueba la autorización antes de pedir que se entre: sin
  `authorization_id` explica que no hay nada que autorizar, y una autorización
  caducada lo dice al momento en vez de después de un login inútil.

## 0.4.2 — 2026-09-10

- Revisión de redirecciones. Quien confirma el correo de una cuenta nueva
  aterriza en sus herramientas (donde toca pedir la primera), no en la página de
  la web desde la que se registró; si venía de una herramienta sigue al
  consentimiento como antes. `/registro` con sesión ya abierta vuelve a donde se
  iba, no a la portada. `Sign out` sin sesión (enlace de la web con la sesión
  ya caducada) vuelve a la web, no a la portada de la cuenta.
- «Send the confirmation again» (`/reenviar`): desde la página de «check your
  inbox» y desde el error de entrada, para quien no encuentra el correo de
  confirmación; responde igual exista o no la cuenta.

## 0.4.1 — 2026-09-10

- Sin cambios: la etiqueta se puso sobre la 0.4.0 por error, antes de que los
  cambios de arriba estuvieran en el árbol. La imagen es idéntica a la 0.4.0.

## 0.4.0 — 2026-09-10

- Aviso por correo cuando se concede un acceso a mano: al aprobar una solicitud
  o conceder una herramienta desde el panel o la línea de órdenes, la persona
  recibe «Your access to <Tool> is ready» con el enlace a la herramienta. La app
  lo manda por SMTP con STARTTLS (`ACCOUNT_SMTP_HOST`, `_PORT`, `_USER`,
  `_PASS`, `_FROM`); sin esas variables se concede igual y el panel lo dice. Los
  roles y las concesiones automáticas no avisan: los roles no abren nada y en
  las automáticas la persona está delante.

## 0.3.8 — 2026-09-09

- Administración: la tabla de clientes OAuth se explica. Cada herramienta abre
  con un cliente, la fila dice qué grupo hace falta; el cliente sale por su
  nombre (el identificador, pequeño y debajo), los roles no llevan cliente ni
  formulario, y el desplegable es «Change» con el cliente actual
  preseleccionado, o «Link» cuando falta. La cifra de arriba cuenta
  herramientas, no grupos.

## 0.3.7 — 2026-09-09

- Las tarjetas de autenticación llevan el material de la tarjeta del hero de la
  web: degradado, sombra cian y el foco difuminado de la esquina.

## 0.3.6 — 2026-09-09

- Las pantallas de una sola tarjeta (entrar, registro, recuperación, segundo
  factor, consentimiento, confirmaciones) van centradas en escritorio; estaban
  pegadas a la izquierda.

## 0.3.5 — 2026-09-09

- `form-action` de la CSP admite el dominio de la casa y sus subdominios. Chrome
  aplica esa directiva también a la redirección que responde a un formulario, y
  con `'self'` a secas bloqueaba la vuelta a la herramienta tras el
  consentimiento OAuth y la vuelta a la web pública tras entrar o salir: la
  persona se quedaba en la página, con el envío hecho, sin ningún aviso. Lo cazó
  la primera prueba con un navegador de verdad desde la web; los recorridos con
  un cliente HTTP seguían las redirecciones sin esa regla.

## 0.3.4 — 2026-09-09

- `GET /salir` no estaba en la lista de plantillas y respondía «plantilla
  desconocida»: el «Sign out» de la web pública caía ahí.
- `next` admite URLs https de la casa (kaicorplabs.com y sus subdominios): quien
  entra, se registra o sale desde la web pública vuelve a la web pública, y no a
  la portada de la cuenta. Todo lo que no sea de la casa sigue siendo «/».

## 0.3.3 — 2026-09-09

- `account invitar <correo> [grupo…]`: crea la cuenta por invitación (GoTrue
  envía el correo con la plantilla de la casa) y concede los grupos de una vez.
  Es la manera de traer a quien viene de otro proveedor con su `sub` definitivo
  antes de que entre, para remapear sus datos de un solo golpe.
- Quien llega por el enlace de invitación va a Seguridad a elegir contraseña,
  con el aviso de por qué: sin ella no podría volver a entrar.

## 0.3.2 — 2026-09-09

- Los enlaces de los correos llevaban una barra invertida delante de cada `&`
  (`\&type=signup`): el navegador mandaba `type=signup\` y la app respondía
  «This link is not one we sent». Lo cazó el primer registro real; los
  recorridos de prueba no lo vieron porque usaban enlaces generados por la API
  de administración, no el correo.

## 0.3.1 — 2026-09-09

- La barra a 320 px: «Sign in» se esconde por debajo de 420 px (queda «Create
  account», y la portada de la app ofrece las dos cosas), como hace la web con
  su enlace «Account». Lo cazó el barrido de anchuras de la web.

## 0.3.0 — 2026-09-09

- La misma hoja que la web pública: `account.css` copia las primitivas de
  `site.css` de kaicorplabs.com (fondo, barra, secciones, hero, botones,
  tarjetas, píldoras, pie) y añade sólo lo que la web no tiene. La barra lleva
  las mismas secciones que la web y, a la derecha, la sesión. Fuera
  `kaicorp.css` y `landing-polish.css`.
- «Keep me signed in»: una casilla al entrar alarga la sesión a
  `ACCOUNT_SESSION_REMEMBER_DAYS` (30 por defecto, 1 a 90) en vez de las
  `ACCOUNT_SESSION_TTL_HOURS`. Sobrevive al segundo factor.
- `GET /api/session`: la web pública pregunta si quien mira tiene sesión y
  enseña su nombre en la cabecera. Sólo contesta con CORS a los orígenes de la
  casa (`ACCOUNT_SESSION_ORIGINS`; por defecto el dominio padre del
  `ACCOUNT_PUBLIC_URL`). Devuelve nombre y si administra; nada más.
- `GET /salir`: página de confirmación, para que la web pueda enlazar «Sign
  out» sin que un GET cierre sesiones.
- Las herramientas enseñan su dominio en el pie de la tarjeta, como las
  tarjetas de proyectos de la web.

## 0.2.0 — 2026-09-09

- Rediseño de todas las pantallas con la composición de la casa: portada con
  su demostración de la lista de herramientas y «cómo funciona»; entrada,
  registro, recuperación, segundo factor y consentimiento como una tarjeta
  centrada; herramientas como tarjetas con estado y monograma; seguridad y
  administración con cabecera de página, cifras, tablas apilables en móvil,
  píldoras de estado y vacíos explicados. Sin JavaScript, como antes.
- La hoja compartida mezcla colores en oklch y Chrome desplaza el tono hacia el
  rojo sobre superficies casi neutras: tarjetas y campos llevan su propia
  mezcla en srgb.
- La portada de quien ha entrado cuenta las herramientas concedidas y las que
  esperan; la administración, las solicitudes pendientes y los grupos con
  cliente.

## 0.1.2 — 2026-09-09

- La capa de producto que faltaba en la hoja de estilos: fuentes autoalojadas,
  base, cabecera, pie, menú de cuenta, botones y formularios sobre los tokens
  de la casa. Hasta ahora la app servía sólo las primitivas de marca y sus
  clases propias, y la página salía con la letra y los enlaces del navegador.

## 0.1.1 — 2026-09-09

- Primera imagen firmada: el repositorio pasa a público.

## 0.1.0 — 2026-09-09

- Primera versión: registro con confirmación, entrada, TOTP, recuperación,
  consentimiento OAuth con política de membresía, solicitudes con aprobación
  humana la primera vez, administración, plantillas de correo, sonda de salud.
