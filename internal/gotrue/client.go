// Package gotrue es el cliente de la API de Supabase Auth (GoTrue) que usa la
// app de cuenta: la parte pública (registro, entrada, verificación, factores,
// consentimiento OAuth) con la clave anónima y el token de la persona, y la de
// administración con la clave de servicio, que sólo se usa para lo que ningún
// otro camino permite: borrar y bloquear cuentas.
//
// No es un SDK: son las llamadas que esta aplicación hace, escritas a mano
// contra los endpoints de GoTrue 2.189 y probadas contra una instancia real.
// Los errores de GoTrue llegan como {code, error_code, msg}; aquí se conservan
// el código HTTP y el error_code, que es lo que decide qué se le dice a la
// persona sin contarle de más.
package gotrue

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client habla con una instancia de GoTrue.
type Client struct {
	base       string // http://supabase-kaicorplabs-gw/auth/v1, sin barra final
	anonKey    string
	serviceKey string
	http       *http.Client
}

// New crea el cliente. serviceKey puede ir vacío si no se van a usar las
// operaciones de administración.
func New(base, anonKey, serviceKey string) *Client {
	return &Client{
		base:       strings.TrimRight(base, "/"),
		anonKey:    anonKey,
		serviceKey: serviceKey,
		http:       &http.Client{Timeout: 15 * time.Second},
	}
}

// Error es un fallo devuelto por GoTrue.
type Error struct {
	Status    int    `json:"code"`
	ErrorCode string `json:"error_code"`
	Msg       string `json:"msg"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("gotrue %d %s: %s", e.Status, e.ErrorCode, e.Msg)
}

// Is permite errors.Is(err, gotrue.ErrUnauthorized) y compañía.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return (t.Status == 0 || t.Status == e.Status) && (t.ErrorCode == "" || t.ErrorCode == e.ErrorCode)
}

// Errores con nombre para lo que la interfaz distingue.
var (
	ErrUnauthorized    = &Error{Status: 401}
	ErrForbidden       = &Error{Status: 403}
	ErrInvalidLogin    = &Error{ErrorCode: "invalid_credentials"}
	ErrEmailNotConfirm = &Error{ErrorCode: "email_not_confirmed"}
	ErrOTPExpired      = &Error{ErrorCode: "otp_expired"}
	ErrRateLimited     = &Error{Status: 429}
	ErrWeakPassword    = &Error{ErrorCode: "weak_password"}
	ErrMFAFailed       = &Error{ErrorCode: "mfa_verification_failed"}
	ErrSignupDisabled  = &Error{ErrorCode: "signup_disabled"}
)

// call hace una petición. token vacío = sólo apikey; admin=true usa la clave de
// servicio como bearer. out puede ser nil.
func (c *Client) call(ctx context.Context, method, path string, token string, admin bool, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// GoTrue no es un navegador ni espera uno, pero delante puede haber un
	// borde que sí lo mira: la cabecera dice quién llama.
	req.Header.Set("User-Agent", "kaicorp-account/1 (+https://kaicorplabs.com)")
	key := c.anonKey
	if admin {
		if c.serviceKey == "" {
			return errors.New("gotrue: operación de administración sin clave de servicio")
		}
		key = c.serviceKey
		token = c.serviceKey
	}
	req.Header.Set("apikey", key)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gotrue: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(data, e)
		e.Status = resp.StatusCode
		if e.Msg == "" {
			e.Msg = strings.TrimSpace(string(data))
		}
		return e
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("gotrue: respuesta de %s %s ilegible: %w", method, path, err)
		}
	}
	return nil
}

// User es la persona tal como la ve GoTrue. Sólo lo que la app usa.
type User struct {
	ID               string          `json:"id"`
	Email            string          `json:"email"`
	EmailConfirmedAt string          `json:"email_confirmed_at"`
	ConfirmationSent string          `json:"confirmation_sent_at"`
	CreatedAt        string          `json:"created_at"`
	LastSignInAt     string          `json:"last_sign_in_at"`
	BannedUntil      string          `json:"banned_until"`
	UserMetadata     map[string]any  `json:"user_metadata"`
	AppMetadata      map[string]any  `json:"app_metadata"`
	Factors          []Factor        `json:"factors"`
	Raw              json.RawMessage `json:"-"`
}

// Name devuelve el nombre de user_metadata, o "".
func (u *User) Name() string {
	if u == nil || u.UserMetadata == nil {
		return ""
	}
	if n, ok := u.UserMetadata["name"].(string); ok {
		return n
	}
	return ""
}

// HasVerifiedFactor dice si la persona tiene algún segundo factor activo: es lo
// que obliga a pedirlo al entrar.
func (u *User) HasVerifiedFactor() bool {
	for _, f := range u.Factors {
		if f.Status == "verified" {
			return true
		}
	}
	return false
}

// Factor es un segundo factor (totp o webauthn).
type Factor struct {
	ID           string `json:"id"`
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
}

// Session son los tokens de GoTrue para una persona.
type Session struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

// Signup registra una cuenta nueva con nombre. Con la confirmación de correo
// activa GoTrue no devuelve sesión: devuelve la ficha con confirmation_sent_at.
// Para un correo que ya existe GoTrue contesta con una ficha falsa y sin error,
// a propósito: quien llama no puede distinguir «nuevo» de «ya estaba», y esta
// app tampoco se lo dice a nadie.
func (c *Client) Signup(ctx context.Context, email, password, name, redirectTo string) (*User, error) {
	body := map[string]any{"email": email, "password": password, "data": map[string]any{"name": name}}
	path := "/signup"
	if redirectTo != "" {
		path += "?redirect_to=" + url.QueryEscape(redirectTo)
	}
	var u User
	if err := c.call(ctx, http.MethodPost, path, "", false, body, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Login entra con correo y contraseña (aal1).
func (c *Client) Login(ctx context.Context, email, password string) (*Session, error) {
	var s Session
	err := c.call(ctx, http.MethodPost, "/token?grant_type=password", "", false,
		map[string]string{"email": email, "password": password}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Refresh renueva la sesión; GoTrue rota el refresh token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Session, error) {
	var s Session
	err := c.call(ctx, http.MethodPost, "/token?grant_type=refresh_token", "", false,
		map[string]string{"refresh_token": refreshToken}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// VerifyTokenHash canjea el token_hash de un enlace de correo (signup,
// recovery, email_change, invite, magiclink) por una sesión. Es el camino de
// servidor: el enlace trae {{ .TokenHash }} y nunca tokens en el fragmento.
func (c *Client) VerifyTokenHash(ctx context.Context, typ, tokenHash string) (*Session, error) {
	var s Session
	err := c.call(ctx, http.MethodPost, "/verify", "", false,
		map[string]string{"type": typ, "token_hash": tokenHash}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Recover pide un correo de recuperación. GoTrue contesta 200 exista o no la
// cuenta; esta app tampoco lo distingue hacia fuera.
func (c *Client) Recover(ctx context.Context, email, redirectTo string) error {
	body := map[string]any{"email": email}
	path := "/recover"
	if redirectTo != "" {
		path += "?redirect_to=" + url.QueryEscape(redirectTo)
	}
	return c.call(ctx, http.MethodPost, path, "", false, body, nil)
}

// Resend vuelve a mandar el correo de confirmación (type signup) o de cambio.
func (c *Client) Resend(ctx context.Context, typ, email string) error {
	return c.call(ctx, http.MethodPost, "/resend", "", false, map[string]string{"type": typ, "email": email}, nil)
}

// Me devuelve la ficha de la persona del token, con sus factores.
func (c *Client) Me(ctx context.Context, token string) (*User, error) {
	var u User
	if err := c.call(ctx, http.MethodGet, "/user", token, false, nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUser cambia contraseña, nombre o correo. Los campos vacíos no se tocan.
func (c *Client) UpdateUser(ctx context.Context, token string, password, name, email string) (*User, error) {
	body := map[string]any{}
	if password != "" {
		body["password"] = password
	}
	if name != "" {
		body["data"] = map[string]any{"name": name}
	}
	if email != "" {
		body["email"] = email
	}
	var u User
	if err := c.call(ctx, http.MethodPut, "/user", token, false, body, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Logout cierra la sesión de GoTrue: scope local (esta), others o global.
func (c *Client) Logout(ctx context.Context, token, scope string) error {
	if scope == "" {
		scope = "local"
	}
	return c.call(ctx, http.MethodPost, "/logout?scope="+url.QueryEscape(scope), token, false, nil, nil)
}

// ── Segundo factor ─────────────────────────────────────────────────────────

// EnrolledFactor es lo que devuelve alta de un factor TOTP: el QR y el secreto
// para quien no puede escanear.
type EnrolledFactor struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	FriendlyName string `json:"friendly_name"`
	TOTP         struct {
		// QRCode es el SVG del código tal cual (XML), no una URL de datos:
		// para un <img> hay que envolverlo (QRDataURL).
		QRCode string `json:"qr_code"`
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	} `json:"totp"`
}

// QRDataURL devuelve el QR como URL de datos para un <img>. En base64 y no en
// línea: una imagen no ejecuta scripts, un SVG incrustado en la página sí podría.
func (f *EnrolledFactor) QRDataURL() string {
	svg := strings.TrimSpace(f.TOTP.QRCode)
	if svg == "" {
		return ""
	}
	if strings.HasPrefix(svg, "data:") {
		return svg
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

// EnrollTOTP da de alta un factor TOTP (queda `unverified` hasta VerifyFactor).
func (c *Client) EnrollTOTP(ctx context.Context, token, friendlyName, issuer string) (*EnrolledFactor, error) {
	var f EnrolledFactor
	err := c.call(ctx, http.MethodPost, "/factors", token, false,
		map[string]string{"factor_type": "totp", "friendly_name": friendlyName, "issuer": issuer}, &f)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Challenge abre un reto para un factor.
type Challenge struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
}

// ChallengeFactor pide un reto para el factor.
func (c *Client) ChallengeFactor(ctx context.Context, token, factorID string) (*Challenge, error) {
	var ch Challenge
	if err := c.call(ctx, http.MethodPost, "/factors/"+url.PathEscape(factorID)+"/challenge", token, false, nil, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

// VerifyFactor responde al reto con el código; devuelve una sesión aal2.
func (c *Client) VerifyFactor(ctx context.Context, token, factorID, challengeID, code string) (*Session, error) {
	var s Session
	err := c.call(ctx, http.MethodPost, "/factors/"+url.PathEscape(factorID)+"/verify", token, false,
		map[string]string{"challenge_id": challengeID, "code": code}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteFactor retira un factor.
func (c *Client) DeleteFactor(ctx context.Context, token, factorID string) error {
	return c.call(ctx, http.MethodDelete, "/factors/"+url.PathEscape(factorID), token, false, nil, nil)
}

// ── Consentimiento OAuth ───────────────────────────────────────────────────

// Authorization son los detalles de una autorización pendiente, o el destino
// si GoTrue ya la aprobó solo porque había un grant previo.
type Authorization struct {
	AuthorizationID string `json:"authorization_id"`
	RedirectURI     string `json:"redirect_uri"`
	Scope           string `json:"scope"`
	Client          struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URI  string `json:"uri"`
		Logo string `json:"logo_uri"`
	} `json:"client"`
	// RedirectURL viene SOLO cuando GoTrue aprobó por un grant previo: ya lleva
	// el código, y la pantalla de consentimiento no debe mostrarse.
	RedirectURL string `json:"redirect_url"`
}

// AutoApproved dice si GoTrue ya emitió el código sin consentimiento.
func (a *Authorization) AutoApproved() bool { return a.RedirectURL != "" }

// Scopes separa el scope en palabras.
func (a *Authorization) Scopes() []string { return strings.Fields(a.Scope) }

// GetAuthorization lee los detalles. OJO: si la persona ya tiene grant para
// ese cliente, esta llamada APRUEBA y devuelve RedirectURL. La política de
// membresía hay que comprobarla ANTES, con el cliente sacado de la base.
func (c *Client) GetAuthorization(ctx context.Context, token, authorizationID string) (*Authorization, error) {
	var a Authorization
	if err := c.call(ctx, http.MethodGet, "/oauth/authorizations/"+url.PathEscape(authorizationID), token, false, nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Consent aprueba o deniega; devuelve a dónde mandar al navegador.
func (c *Client) Consent(ctx context.Context, token, authorizationID, action string) (string, error) {
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	err := c.call(ctx, http.MethodPost, "/oauth/authorizations/"+url.PathEscape(authorizationID)+"/consent", token, false,
		map[string]string{"action": action}, &out)
	if err != nil {
		return "", err
	}
	return out.RedirectURL, nil
}

// Grant es un cliente al que la persona autorizó.
type Grant struct {
	Client struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"client"`
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"`
}

// Grants lista las autorizaciones vigentes de la persona.
func (c *Client) Grants(ctx context.Context, token string) ([]Grant, error) {
	var gs []Grant
	if err := c.call(ctx, http.MethodGet, "/user/oauth/grants", token, false, nil, &gs); err != nil {
		return nil, err
	}
	return gs, nil
}

// RevokeGrant retira la autorización de un cliente: mata sus refresh y access tokens.
func (c *Client) RevokeGrant(ctx context.Context, token, clientID string) error {
	return c.call(ctx, http.MethodDelete, "/user/oauth/grants?client_id="+url.QueryEscape(clientID), token, false, nil, nil)
}

// ── Administración (clave de servicio) ────────────────────────────────────

// AdminDeleteUser borra la cuenta en el proveedor. Es el último paso de
// borrar-persona: los datos de cada herramienta van antes.
func (c *Client) AdminDeleteUser(ctx context.Context, userID string) error {
	return c.call(ctx, http.MethodDelete, "/admin/users/"+url.PathEscape(userID), "", true, nil, nil)
}

// AdminBanUser bloquea la cuenta el tiempo dado ("876000h" es «para siempre»;
// "none" levanta el bloqueo). Bloqueada, no puede entrar ni renovar tokens.
func (c *Client) AdminBanUser(ctx context.Context, userID, duration string) error {
	return c.call(ctx, http.MethodPut, "/admin/users/"+url.PathEscape(userID), "", true,
		map[string]string{"ban_duration": duration}, nil)
}

// GeneratedLink es lo que devuelve generate_link: sirve para probar el camino
// de verificación sin buzón, y para invitar.
type GeneratedLink struct {
	ActionLink  string `json:"action_link"`
	HashedToken string `json:"hashed_token"`
	Type        string `json:"verification_type"`
}

// AdminGenerateLink pide un enlace de acción (signup, recovery, invite, magiclink).
func (c *Client) AdminGenerateLink(ctx context.Context, typ, email, password string) (*GeneratedLink, error) {
	body := map[string]any{"type": typ, "email": email}
	if password != "" {
		body["password"] = password
	}
	var g GeneratedLink
	if err := c.call(ctx, http.MethodPost, "/admin/generate_link", "", true, body, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// Health comprueba que GoTrue responde.
func (c *Client) Health(ctx context.Context) error {
	return c.call(ctx, http.MethodGet, "/health", "", false, nil, nil)
}
