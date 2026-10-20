# Diseño de la app de cuenta

*Septiembre de 2026.*

## Reparto: qué hace GoTrue y qué hace esta app

| GoTrue (Supabase Auth) | Esta app |
|---|---|
| Cuentas, contraseñas, confirmación de correo, recuperación | Las pantallas de todo eso, con la marca de la casa |
| Segundo factor (TOTP y passkeys WebAuthn) | Alta, reto y verificación desde `/cuenta` y al entrar |
| Emisor OIDC: discovery, authorize, token, userinfo, grants | **La pantalla de consentimiento y la política**: quién puede entrar a qué |
| Sus sesiones y refresh tokens | Sesiones propias que los envuelven, cifrados, en `account.sesiones` |
| Auditoría (`auth.audit_log_entries`) | Membresías y solicitudes (`account.*`), que son la historia de quién aprobó qué |
| Confirmaciones finales de correo (SMTP) | Plantillas de GoTrue en `/plantillas/*.html` y avisos privados preliminares de la app |

## Decisiones

1. **Plantillas Go y JavaScript mínimo, propio y sin inline**: `passkey.js`
   existe porque WebAuthn sólo vive en el navegador; `email-link.js` mueve una
   capacidad desde el fragmento de un enlace al formulario CSRF y sustituye de
   inmediato la entrada de historial por la URL limpia. Ninguno hace red y sólo
   se carga en las páginas que lo necesitan. No React. La casa había migrado tres
   servicios a React + Go, pero una interfaz de autenticación es formularios y
   redirecciones; no hay build ni dependencias de npm que auditar, y el cromado
   se calca de LinkUp, que ya lo tenía en plantillas Go. La CSP sólo abre
   `script-src 'self'`.
2. **La política se comprueba antes de hablar con GoTrue.** `GET
   /oauth/authorizations/{id}` aprueba solo si la persona ya autorizó ese
   cliente. Por eso el cliente de la autorización se lee de
   `auth.oauth_authorizations` y la membresía se decide primero; a GoTrue sólo
   se le pide algo cuando la respuesta ya es «puede». Ese salto transporta
   contraseñas, tokens y la clave de servicio: en operación normal es HTTPS con
   validación de certificado y nombre, y el cliente no sigue redirecciones. Una
   red Docker o privada no sustituye TLS. El HTTP sólo se habilita de forma
   explícita para desarrollo y hacia una IP literal de loopback.
3. **Revocar una membresía revoca el grant** (`auth.oauth_consents.revoked_at`).
   Sin esto, quitarle a alguien una herramienta no le quitaría nada: GoTrue
   seguiría aprobando en silencio. Vincular un cliente es la misma clase de
   transición: antes de confirmar el vínculo se deniegan sus códigos aprobados,
   se revocan los grants y se cierran las sesiones OAuth de quienes no sean
   miembros. Las guardas de proveedor serializan también un canje o refresh que
   ya estuviera en vuelo.
4. **Sesiones de la app en la base, cookie opaca, tokens cifrados.** Permite
   listarlas y cerrarlas (la persona las suyas, un administrador las de otro),
   y ningún token de GoTrue viaja en cookies. AES-GCM con `ACCOUNT_SESSION_KEY`.
   El AAD de cada sobre liga su clase (`access` o `refresh`), la persona, el AAL,
   la referencia estable y el portador actual; una rotación vuelve a cifrar. En
   cada carga se autentican ambos sobres y `/user` confirma que el sujeto del
   access coincide, también para aal2 y antes de persistir un refresh. El rol de
   runtime no tiene `UPDATE` general sobre `account.sesiones`: usa funciones
   `SECURITY DEFINER` acotadas al ciclo de vida. La migración inicial a este
   formato cierra una vez las sesiones antiguas, que no tienen contexto ligado;
   se aplica con las réplicas antiguas detenidas para impedir una escritura del
   formato anterior durante la transición.
   En HTTPS el portador usa `__Host-account_session`, Secure, host-only y
   Path=/; sólo el desarrollo HTTP explícito sobre una IP literal de loopback
   usa `account_session`. Cualquier autoridad
   duplicada se rechaza en vez de depender del orden elegido por el navegador.
   Cerrar administrativamente todas las sesiones avanza además una generación
   y un corte por persona bajo el mismo bloqueo que publica sesiones. El corte
   rechaza tokens obtenidos antes del cierre; la generación se comprueba en
   cada carga, también en la ruta rápida aal2, aunque una fila sobreviva al
   borrado físico. La operación no anuncia éxito hasta abandonar el segundo
   rechazado por el corte, para que una entrada iniciada después de la respuesta
   no herede el mismo `iat`. El panel, la CLI y los cierres de emergencia tras
   una mutación ambigua comparten esa única operación idempotente.
5. **Ninguna sesión sin factor y ninguna mutación MFA con la sesión sola.** Si
   la cuenta tiene un factor verificado, los tokens aal1 no se convierten en
   sesión: van sellados en `__Host-account_mfa` cinco minutos hasta que el
   código los cambia por aal2. Dar de alta, verificar o borrar un factor exige
   además una
   concesión reciente de cinco minutos, de un uso y guardada en el servidor,
   ligada a la persona, al portador de sesión, al propósito y, al borrar, al
   factor exacto. Nace al comprobar la contraseña actual; si ya había factores,
   debe elevarse con un reto de otro factor que ya estuviera verificado. El
   factor nuevo, su reto y la sesión que inició el alta quedan en estado
   pendiente del servidor, por lo que no puede autorizarse a sí mismo ni
   sustituirse desde el formulario. Incluso una invitación debe terminar
   primero la elección de contraseña; después autoriza el primer factor con
   esa contraseña ya instalada.
   Retirar el último factor añade una prueba de recuperación por correo ligada
   a esa misma sesión y a ese factor. Cualquier cambio completado rota el
   portador activo y cierra todas las demás sesiones de la app y del proveedor;
   cancelar el factor no verificado exacto sólo revierte esa alta pendiente.
   Las capacidades de recuperación, alta de contraseña y cambio de MFA usan
   igualmente nombres `__Host-`, Path=/ y lectura no ambigua; sus alias sin
   prefijo quedan reservados al desarrollo HTTP.
6. **CSRF con estado aleatorio sellado y un HMAC ligado a la sesión cargada**;
   antes del login se usa un contexto anónimo distinto. La cookie HTTPS
   `__Host-account_csrf` es Secure, host-only y Path=/; sólo el modo HTTP de
   desarrollo usa `account_csrf`. Se rechazan cookies y campos duplicados.
   Cada POST exige el origen exacto de `ACCOUNT_PUBLIC_URL`; sin Origin sólo
   se acepta Referer del mismo origen, y sin ambos se rechaza. Los formularios
   caducan al cambiar o terminar la sesión, incluido el ascenso a aal2.
7. **No se enumeran correos ni se ata una contraseña antes de demostrar el
   buzón**: registro, recuperación, entrada e inicio del cambio de correo dan la
   misma respuesta exista la cuenta o no. El alta pública manda a GoTrue una
   contraseña aleatoria que nadie conoce. El enlace lleva además un sobre cifrado,
   ligado al correo, con esa credencial y caducidad; un enlace antiguo sin el sobre
   se rechaza antes de confirmar. Al repetir el alta o reenviar, cualquier cuenta
   aún sin confirmar se rota primero por la API administrativa y sólo entonces se
   manda el correo nuevo. Tras canjearlo se entrega durante cinco minutos una
   capacidad opaca, de un uso, para elegir la contraseña final. La capacidad
   conserva en memoria el secreto aleatorio para que el cambio satisfaga incluso
   la política que exige la contraseña actual. Su autoridad queda ligada al `iat`
   original o a la generación que tenía la cuenta al pedir el correo, también al
   atravesar MFA. Cada escritura de contraseña conserva el bloqueo transaccional
   por persona durante el `PUT /user`, adelanta el corte e incrementa esa generación;
   sólo la sesión con el ticket de la generación nueva puede publicarse después.
   El corte se confirma con un contexto interno aunque el navegador cancele la
   petición; si el proveedor pudo escribir pero el corte local no queda durable,
   la cuenta se bloquea. El mismo corte invalida sobres MFA y las demás capacidades
   se expulsan de memoria. En una invitación, tras el cambio final se rotan
   también los tokens de proveedor, se cierran sus demás sesiones y sólo
   entonces nace una única sesión general con un portador nuevo. Las rotaciones
   administrativas de altas e invitaciones toman el mismo bloqueo, incrementan la
   generación y ligan a ella la capacidad de elegir la contraseña final; si su
   resultado queda incierto, la cuenta se bloquea.
   GoTrue comparte almacenamiento entre `signup`/`invite` y entre
   `recovery`/`magiclink`: la primera pareja sigue por ello el mismo camino
   preautenticado, pero conserva capacidades distintas para registro e
   invitación. Cada invitación lleva además un sobre cifrado de propósito y
   destinatario en su `redirect_to`; los enlaces antiguos sin él fallan antes
   del canje. El alta pública no puede rotar ni reclasificar una invitación
   pendiente: sólo su reenvío administrativo emite otro enlace de invitación.
   `magiclink` y el alias genérico `email` se rechazan porque el
   proveedor no devuelve a esta app el propósito que resolvió. Además, cada
   solicitud a `/recuperar` crea una intención cifrada, ligada al correo, a la
   identidad y a su generación de credencial, con una hora de vida, que debe volver
   junto al token: un hash suelto de la familia compartida no basta para cambiar la
   contraseña, y canjear un enlace viejo no lo rejuvenece con el `iat` de la
   respuesta. El sobre es stateless para sobrevivir reinicios y saltos de réplica;
   el token del proveedor conserva el uso único. El cambio de correo se
   queda primero en otra capacidad opaca de quince minutos, ligada a la persona
   y guardada sólo por su huella; la prueba se envía al buzón propuesto sin
   consultar a GoTrue. Un POST con sesión y CSRF consume esa capacidad una sola
   vez y entonces pide a GoTrue sus confirmaciones finales para los dos buzones.
   Así el buzón actual tampoco distingue `email_exists`; ese detalle sólo queda
   en el diagnóstico interno después de demostrar acceso al buzón propuesto.
   Los hashes de GoTrue y la prueba preliminar nunca viajan en paths ni queries:
   el correo los pone en un fragmento, el intersticial usa `no-referrer`, un
   script propio los copia al cuerpo del POST y limpia el historial. El borde
   HTTP descarta cualquier enlace antiguo que aún los traiga como query.
   Antes de enviar un hash a `/verify`, la app valida el sobre específico del
   propósito y relee `auth.one_time_tokens`, la fuente de verdad que consume
   GoTrue: el conjunto exige que el hash siga ligado al propósito exacto, al
   usuario y al buzón normalizado que la persona escribió. La fecha `*_sent_at` debe seguir dentro de
   `ACCOUNT_EMAIL_LINK_TTL_SECONDS`, copia obligatoria y no mayor de un día de
   `GOTRUE_MAILER_OTP_EXP`; ambos valores deben estar en el entorno de la app y
   el arranque exige que coincidan. Para el cambio seguro distingue
   el enlace del buzón antiguo del del nuevo y conserva también el correo final
   esperado. Un bloqueo asesor por usuario, conservado durante `/verify`,
   serializa ambas mitades entre réplicas; tras la primera sólo admite el registro
   de un uso contrario que GoTrue 2.189 deja pendiente, aunque una columna antigua
   de `auth.users` reaparezca por una escritura concurrente. Una respuesta parcial sólo se acepta para ese propósito
   después de probar el vínculo. Un rechazo local no consume el enlace.
   Toda contraseña introducida por una persona reserva antes de llegar a GoTrue
   dos filas en `account.intentos_password`: el agregado estable de la cuenta y
   su par con la identidad de cliente obtenida de la frontera de proxy. Entrada,
   cambio de contraseña y autorización MFA comparten ese presupuesto en todas
   las réplicas; cambiar de IP no reinicia el agregado. Los correos inexistentes
   usan una huella opaca y reciben el mismo 429 con `Retry-After`. El backoff
   progresa hasta 60 segundos y las filas inactivas se purgan a las 24 horas.
   Los límites de GoTrue y del borde sólo añaden defensa en profundidad.
8. **Permisos acotados sobre `auth`** en vez de la clave de servicio para todo.
   La clave de servicio sólo bloquea, borra y rota la credencial desconocida de
   un alta que acaba de confirmar el buzón; lo demás son `select` y
   tres escrituras concretas, enumeradas en `db/bootstrap.sql` con su motivo.
   En `account` también hay identidades separadas: el servidor usa el
   login `account` con DML explícito; `account_migrator` posee el esquema y sólo
   aparece en el paso de despliegue; `account_hook`, sin login ni superusuario,
   posee las seis funciones `SECURITY DEFINER` y sólo lee sus tres relaciones
   de negocio. Un cuarto rol sin login encierra el `FOR SHARE` necesario para
   los snapshots antiguos y sólo puede actualizar las columnas `version` de
   dos filas de coordinación. Por eso una sesión runtime comprometida no puede
   sustituir una tabla o función que luego ejecute GoTrue con más autoridad.
9. **La clase del grupo es autoridad explícita.** `tipo='rol'` es el valor
   cerrado por defecto y la base impide que un rol sea solicitable; una
   herramienta debe declarar `tipo='herramienta'` y optar expresamente por las
   solicitudes. Como históricamente también hubo roles con URL, la migración
   no adivina: cierra toda fila heredada como rol no solicitable y exige que la
   instalación vuelva a declarar explícitamente sus herramientas. `SolicitarAcceso`
   vuelve a negar tanto cualquier rol como el grupo administrador configurado,
   sin confiar en el indicador guardado, y el arranque exige que ese grupo
   exista como rol no solicitable.
10. **Aprobación humana la primera vez, automática después**, el modelo de la
   casa desde agosto: se decide sobre la persona, una vez.
11. **La primera cuenta administradora se da por CLI** (`account admin
    <correo>`), no por interfaz: no hay «primer usuario es admin».
12. **La autoridad administrativa se decide al efectuar, no al entrar en el
    handler.** Cada mutación de `/admin` toma bloqueos PostgreSQL para actor y
    destinos UUID normalizados en orden canónico, relee la membresía
    administradora bajo esos bloqueos y la vuelve a leer justo antes de cada
    escritura o llamada remota. Revocar membresías, cerrar sesiones, bloquear
    o borrar una cuenta toma la misma frontera y adelanta una generación
    durable; una orden anterior no revive aunque se vuelva a conceder el rol.
    Las invitaciones conservan esa generación entre el envío y la concesión de
    grupos. La interfaz tampoco permite autoconcederse administración, limita
    a 32 los grupos de una invitación y elimina duplicados antes de consultarlos.

## Lo que no está (todavía)

- Aviso por correo a la persona cuando se aprueba su solicitud: GoTrue no
  manda correos arbitrarios; hará falta Resend por HTTP desde esta app
  (egress 443 para su contenedor), o el `aprobar.py` de la casa.
- Borrar una cuenta desde la interfaz: a propósito no. Es `borrar-persona.py`,
  que borra también lo que cada herramienta guarda.

## Rutas

| Ruta | Qué |
|---|---|
| `GET /` | Tus herramientas, o la portada si no hay sesión |
| `/entrar`, `/registro`, `/registro/password`, `/recuperar`, `/restablecer`, `/factor`, `POST /salir` | Entrada, alta con contraseña posterior a la confirmación, recuperación, segundo factor |
| `GET /verificar?type&next#token_hash`, `GET /restablecer?intent#token_hash` | Presentación inerte de los enlaces de correo; el fragmento no llega por HTTP, se copia al formulario y se borra del historial; GET no canjea tokens ni cambia autoridad |
| `POST /verificar` | Confirmación explícita, con origen, CSRF y correo esperado; signup/invite no abren sesión antes de elegir contraseña, recovery sólo entrega capacidad de cambio, y `magiclink`/`email` se rechazan |
| `GET/POST /cuenta/correo/confirmar` | Presentación inerte y consumo con sesión y CSRF de la prueba preliminar enviada al buzón propuesto; sólo el POST llega a GoTrue |
| `POST /solicitar/{grupo}` | Pedir una herramienta (pendiente o automática según la política) |
| `GET/POST /oauth/consent` | El consentimiento OAuth, con la política delante |
| `/cuenta/*` | Nombre, contraseña, factores, herramientas autorizadas, sesiones |
| `/admin/*` | Solicitudes, cuentas, membresías, clientes ↔ grupos, cerrar sesiones, bloquear |
| `GET /plantillas/{nombre}` | Plantillas de correo para GoTrue |
| `GET /api/session` | Proyección CORS mínima para la portada: estado, nombre visible o la etiqueta neutra `Account`, y administración; su DTO no admite correo, identificadores ni tokens |
| `GET /api/health` | 200 si la base y GoTrue responden |
