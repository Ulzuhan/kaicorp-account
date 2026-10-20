// Package correo envía los correos que son de la app de cuenta y no de GoTrue:
// avisos de acceso y la prueba preliminar de un cambio de correo. GoTrue manda
// después sus confirmaciones finales, así que esto habla SMTP por su cuenta,
// con la misma cuenta de envío de la casa. Sin configuración no hay remitente
// y quien llama lo sabe.
package correo

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/web"
)

// ErrSinRemitente: no hay SMTP configurado.
var ErrSinRemitente = errors.New("correo: sin remitente configurado")

// Remitente es una cuenta SMTP con STARTTLS (587) y la plantilla del aviso.
type Remitente struct {
	host, port, usuario, clave string
	de                         *mail.Address
	acceso                     *template.Template
	cambioIniciado             *template.Template
	cambioConfirmar            *template.Template
}

// Nuevo devuelve nil, nil si no hay host: la app funciona sin correo propio.
func Nuevo(host, port, usuario, clave, de string) (*Remitente, error) {
	if host == "" {
		return nil, nil
	}
	if port == "" {
		port = "587"
	}
	addr, err := mail.ParseAddress(de)
	if err != nil {
		return nil, fmt.Errorf("remitente %q: %w", de, err)
	}
	compilar := func(nombre string) (*template.Template, error) {
		b, err := web.Plantilla(nombre)
		if err != nil {
			return nil, err
		}
		return template.New(nombre).Parse(string(b))
	}
	acceso, err := compilar("acceso.html")
	if err != nil {
		return nil, err
	}
	cambioIniciado, err := compilar("cambio-correo-iniciado.html")
	if err != nil {
		return nil, err
	}
	cambioConfirmar, err := compilar("cambio-correo-confirmar.html")
	if err != nil {
		return nil, err
	}
	return &Remitente{host: host, port: port, usuario: usuario, clave: clave, de: addr,
		acceso: acceso, cambioIniciado: cambioIniciado, cambioConfirmar: cambioConfirmar}, nil
}

// Acceso es lo que el aviso necesita saber.
type Acceso struct {
	Nombre      string // cómo se llama la persona, o su correo si no dio nombre
	Herramienta string // «SecretDrop»
	URL         string // https://secret.kaicorplabs.com
	Cuenta      string // https://account.kaicorplabs.com/
}

// EnviarAcceso avisa de que una herramienta ya está concedida. Síncrono y con
// tope de tiempo: quien aprueba en el panel ve si el correo salió o no.
func (r *Remitente) EnviarAcceso(ctx context.Context, para string, a Acceso) error {
	if r == nil {
		return ErrSinRemitente
	}
	if _, err := mail.ParseAddress(para); err != nil {
		return fmt.Errorf("destinatario %q: %w", para, err)
	}
	var html bytes.Buffer
	if err := r.acceso.Execute(&html, a); err != nil {
		return err
	}
	texto := fmt.Sprintf("Hi %s,\n\nYour access to %s is ready. Open it here:\n%s\n\nEverything about your account (password, second factor, the tools you are signed in to) lives at %s\n\nKaiCorp Labs", a.Nombre, a.Herramienta, a.URL, a.Cuenta)
	asunto := fmt.Sprintf("Your access to %s is ready", a.Herramienta)
	msg := r.mensaje(para, asunto, texto, html.String())
	return r.enviar(ctx, para, msg)
}

// CambioCorreo mantiene separados los dos secretos del inicio: el buzón
// actual sólo recibe el enlace de seguridad de la cuenta y el propuesto sólo
// recibe la prueba opaca que permite continuar.
type CambioCorreo struct {
	Cuenta    string
	Confirmar string
}

// EnviarCambioCorreo avisa siempre al buzón actual y manda al propuesto la
// prueba preliminar. Intenta ambos envíos aunque el primero falle; quien llama
// no debe convertir el resultado SMTP en una diferencia HTTP observable.
func (r *Remitente) EnviarCambioCorreo(ctx context.Context, actual, propuesta string, c CambioCorreo) error {
	if r == nil {
		return ErrSinRemitente
	}
	if _, err := mail.ParseAddress(actual); err != nil {
		return fmt.Errorf("destinatario actual: %w", err)
	}
	if _, err := mail.ParseAddress(propuesta); err != nil {
		return fmt.Errorf("destinatario propuesto: %w", err)
	}
	var avisoHTML, pruebaHTML bytes.Buffer
	if err := r.cambioIniciado.Execute(&avisoHTML, c); err != nil {
		return err
	}
	if err := r.cambioConfirmar.Execute(&pruebaHTML, c); err != nil {
		return err
	}
	avisoTexto := "A request to change the email address on your KaiCorp Labs account was started. A private preliminary confirmation was sent separately to the proposed mailbox. Nothing has changed yet. If this was not you, review your account security:\n" + c.Cuenta + "\n\nKaiCorp Labs"
	pruebaTexto := "Someone asked to use this address for a KaiCorp Labs account. While signed in to the account that started the request, confirm access to this mailbox:\n" + c.Confirmar + "\n\nThis is a preliminary check. The identity service will send final confirmations to both mailboxes before anything changes. Ignore this message if you did not expect it.\n\nKaiCorp Labs"
	errActual := r.enviar(ctx, actual, r.mensaje(actual, "Email change requested", avisoTexto, avisoHTML.String()))
	errPropuesta := r.enviar(ctx, propuesta, r.mensaje(propuesta, "Confirm this address for an email change", pruebaTexto, pruebaHTML.String()))
	return errors.Join(errActual, errPropuesta)
}

func (r *Remitente) mensaje(para, asunto, texto, html string) []byte {
	limite := fmt.Sprintf("kc-%d", time.Now().UnixNano())
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d.%s>\r\nMIME-Version: 1.0\r\n",
		r.de.String(), para, asunto, time.Now().UTC().Format(time.RFC1123Z), time.Now().UnixNano(), strings.TrimPrefix(r.de.Address[strings.Index(r.de.Address, "@"):], "@"))
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", limite)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n", limite, texto)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n", limite, html)
	fmt.Fprintf(&b, "--%s--\r\n", limite)
	return []byte(b.String())
}

// enviar habla SMTP con STARTTLS y autenticación PLAIN, en menos de diez
// segundos o nada: el panel no se queda colgado por un servidor de correo.
func (r *Remitente) enviar(ctx context.Context, para string, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.host, r.port))
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if plazo, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(plazo)
	}
	c, err := smtp.NewClient(conn, r.host)
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if err := c.StartTLS(&tls.Config{ServerName: r.host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if err := c.Auth(smtp.PlainAuth("", r.usuario, r.clave, r.host)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(r.de.Address); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	if err := c.Rcpt(para); err != nil {
		return fmt.Errorf("smtp to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return c.Quit()
}
