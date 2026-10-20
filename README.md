# KaiCorp Account

One account for the KaiCorp Labs tools: registration with email confirmation,
sign-in, second factor, OAuth consent, access requests with human approval, and
the administration of memberships. It is the user-facing half of a self-hosted
[Supabase Auth](https://supabase.com/docs/guides/auth) (GoTrue) instance acting
as an OpenID Connect provider: GoTrue keeps the accounts, passwords, factors and
sessions; this app keeps **who may enter what**, and paints every screen.

It is a single Go binary with the pages embedded. One script (passkeys need the browser's WebAuthn API), strict CSP,
server-rendered forms with CSRF.

## How it fits

```
browser ──▶ account.example.com (this app) ──▶ GoTrue /auth/v1  (login, factors, consent API)
                     │                              │
                     └──▶ Postgres: schema account ─┘ (memberships, requests, app sessions)
tool ──▶ OIDC authorize ──▶ GoTrue ──▶ /oauth/consent here ──▶ policy ──▶ approve/deny ──▶ back to the tool
```

- Each OAuth client (a tool) is linked to exactly one **group**. The consent
  page only approves if the person belongs to it. Nothing else in the tools
  changes: they are plain OIDC clients.
- The **first** tool a person asks for is approved by an administrator. Once a
  person has been approved for any tool, the next ones open automatically.
- The access token GoTrue issues carries a `groups` claim with the person's
  memberships (a Postgres hook, `db/bootstrap.sql`), for tools that want it.
- Revoking a membership also revokes the OAuth grant, so GoTrue stops approving
  on its own and the tool's refresh tokens die.
- MFA changes require the current password and, once a factor exists, a fresh
  assertion from a different factor. Removing the final factor also requires a
  same-session recovery email. Every completed MFA change rotates the current
  bearer and signs out all other app and provider sessions.

## Run it

```bash
cp .env.example .env            # and fill it in
docker build -t kaicorp-account .
docker run --rm --env-file .env -p 127.0.0.1:3467:3467 kaicorp-account
```

Before the first start, run `db/bootstrap.sql` against the Supabase
Postgres as a superuser, supplying both `account_password` and
`account_migration_password`. It creates a DML-only `account` login, a separate
`account_migrator` schema owner, and a no-login `account_hook` owner for the five
privileged provider functions. The hook owner can read only the three business
relations those functions consume. A second no-login helper role can lock only
the `version` columns of the two coordination rows needed for old snapshots.

When upgrading an existing installation, stop the app, reapply
`db/bootstrap.sql` as a superuser, and run `account migrar` once with
`ACCOUNT_MIGRATION_DATABASE_URL` set to the `account_migrator` connection.
Remove that variable before starting the server; startup rejects an environment
that still contains it. Normal startup only checks the migration ledger with
the runtime connection and cannot change schema.
The consent
guards coordinate provider writes with client binding changes, including writes
that finish after an HTTP timeout. Binding changes refuse to run without both
guards. Migration rejects invalid or duplicate UUID client bindings; resolve
those explicitly before retrying. Unlinking or replacing a client revokes all
of its existing grants; linking the same client preserves them. Previously lost
bindings cannot be reconstructed, so revoke any known orphaned grants separately.

GoTrue needs:

```
GOTRUE_OAUTH_SERVER_ENABLED=true
GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH=/oauth/consent
GOTRUE_SITE_URL=https://account.example.com
GOTRUE_URI_ALLOW_LIST=https://account.example.com/**
GOTRUE_MAILER_OTP_EXP=86400
GOTRUE_MAILER_TEMPLATES_CONFIRMATION=https://account.example.com/plantillas/confirmacion.html   # and recovery, email_change, invite, magic_link, reauthentication
GOTRUE_MAILER_TEMPLATE_RELOADING_ENABLED=true
```

Expose that same `GOTRUE_MAILER_OTP_EXP` value to the account service and set
`ACCOUNT_EMAIL_LINK_TTL_SECONDS` to it. The account service compares both at
startup, accepts at most 86400 seconds, and rejects expired pending hashes
before asking GoTrue to redeem them.

Before normal startup, load your groups with `account_migrator` (one row per
tool or role; see `db/grupos.example.sql`). Group kind is explicit: rows default
to a non-requestable `rol`, while an ordinary tool must opt into
`tipo='herramienta'` and `solicitable=true`. Startup refuses to run unless the
configured `ACCOUNT_ADMIN_GROUP` exists as a non-requestable role. Then link
each OAuth client to its tool group from `/admin` or with `account vincular`.
On the upgrade that introduces group kinds, the migration conservatively marks
every previously untyped row as a non-requestable role because historical roles
could also have URLs. Reapply your installation's group SQL with explicit
`tipo` values before normal startup to restore ordinary tools deliberately.

The binding regression tests use `psql` and a disposable PostgreSQL instance:
set `ACCOUNT_BINDING_TEST_DATABASE_URL` to its superuser PostgreSQL URL and run
`go test -race ./internal/store -run TestVincular`. They create and remove their
own databases and apply the real bootstrap and migrations.

Subcommands: `account migrar` (apply migrations with the one-off
`ACCOUNT_MIGRATION_DATABASE_URL` and exit), `account admin
<email>` (make an existing account an administrator), `account ver <email>`
(state, memberships, requests, sessions and grants, tab-separated), `account
invitar <email> [group…]` (invite with the groups already granted), `account
aprobar <email> <group>` and `account revocar <email> <group|todo>`, `account
bloquear` / `desbloquear <email>`, `account borrar <email> [--de-verdad]` (the
account and everything the app keeps about it; dry run without the flag),
`account purgar [--de-verdad]` (unconfirmed self-registered accounts older than
`ACCOUNT_UNCONFIRMED_DAYS`), `account vincular <group> <client_id>` (link an
OAuth client to its group), `account sonda` (health probe).

## Configuration

See [`.env.example`](.env.example). Every `ACCOUNT_*` variable is validated at
start; the app refuses to run half-configured.

`ACCOUNT_GOTRUE_URL` must use HTTPS in normal operation. The Go client validates
the server certificate chain and hostname against the system trust store and
does not follow redirects, because this hop carries passwords, session tokens,
the anon key, and the service-role key. An internal Docker or private network is
not a substitute for authenticated encryption. For a private CA, install its
root in the container trust store or point `SSL_CERT_FILE`/`SSL_CERT_DIR` at the
mounted trust material; the certificate SAN still has to match the URL host.
The app does not load an mTLS client certificate itself. Deployments requiring
mTLS should put an HTTPS gateway with a normally validated server certificate in
front of GoTrue and configure that gateway to authenticate upstream with mTLS.

For local development only, `ACCOUNT_GOTRUE_INSECURE_HTTP=1` permits an
`http://` GoTrue URL whose host is a literal loopback address in `127.0.0.0/8`
or `[::1]`. It deliberately rejects `localhost`, private/LAN addresses, Docker
service names, IPv4-mapped IPv6, and other alternate address spellings.

Attempt limits use the transport peer IP by default and ignore forwarding
headers. Behind a tunnel or reverse proxy, set both
`ACCOUNT_TRUSTED_PROXY_CIDRS` (comma-separated IPv4/IPv6 CIDRs for the immediate
proxy peers) and `ACCOUNT_CLIENT_IP_HEADER` (`CF-Connecting-IP` or `X-Real-IP`).
The proxy must overwrite that one header, removing client-supplied values.
Email-link capabilities travel in URL fragments and then only in protected POST
bodies. Keep that boundary at every deployment edge: access logs and tracing
must omit query strings and `Referer`, and request-body capture must be disabled
or redact `token_hash` and `token` on the confirmation endpoints. The app itself
logs paths only and rejects legacy links that put either capability in a query.
Only peers in those ranges may supply the selected header; other headers are
ignored. Missing, repeated, or invalid selected values from trusted peers
produce HTTP 400 on throttled actions. Keep the origin listener accessible only
to the intended proxies and use their actual transport addresses, including
container network addresses where applicable. Without this opt-in, visitors
behind one proxy share its attempt allowance.

Human-entered password checks also reserve a persistent budget in PostgreSQL
before contacting GoTrue. The budget combines a stable account aggregate with
the trusted client identity, is shared by sign-in, password change and MFA
authorization across all replicas, and returns a generic HTTP 429 with a capped
`Retry-After`. GoTrue and edge throttling remain additional layers, not the
primary account-level control.

## Development

```bash
go test ./...
go vet ./...
```

The design and its decisions: [`docs/DISENO.md`](docs/DISENO.md).

Consent approval and membership revocation are synchronized by the database.
Reapply `db/bootstrap.sql` with both role passwords before deploying this
version or running `account migrar`. Migration 0004 drains earlier provider transactions before
enabling atomic membership and grant revocation. Revocation fails without the
provider guards, preserving the membership.
Run the consent race integration tests only against a disposable PostgreSQL
instance with `psql` installed and a role allowed to create databases:

```bash
ACCOUNT_CONSENT_TEST_DATABASE_URL='postgres://test_admin@localhost/test?sslmode=disable' go test -race ./internal/httpapi -run TestConsentimiento
```
