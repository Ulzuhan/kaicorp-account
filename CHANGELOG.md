# Cambios

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
