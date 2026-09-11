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

## Run it

```bash
cp .env.example .env            # and fill it in
docker build -t kaicorp-account .
docker run --rm --env-file .env -p 127.0.0.1:3467:3467 kaicorp-account
```

Before the first start, run `db/bootstrap.sql` once against the Supabase
Postgres as a superuser: it creates the `account` role and schema, the scoped
grants on the `auth` schema, and the claims hook. GoTrue needs:

```
GOTRUE_OAUTH_SERVER_ENABLED=true
GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH=/oauth/consent
GOTRUE_SITE_URL=https://account.example.com
GOTRUE_URI_ALLOW_LIST=https://account.example.com/**
GOTRUE_MAILER_TEMPLATES_CONFIRMATION=http://<this app>/plantillas/confirmacion.html   # and recovery, email_change, invite, magic_link, reauthentication
GOTRUE_MAILER_TEMPLATE_RELOADING_ENABLED=true
```

Then load your groups (one row per tool or role; see `db/grupos.example.sql`)
and link each OAuth client to its group from `/admin` or with `account vincular`.

Subcommands: `account migrar` (apply migrations and exit), `account admin
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

## Development

```bash
go test ./...
go vet ./...
```

The design and its decisions: [`docs/DISENO.md`](docs/DISENO.md).
