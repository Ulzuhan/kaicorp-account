# Security policy

This application is a door. It holds no identity of its own — GoTrue does — but
it decides who gets through it: sign-in, the second factor, the OAuth consent
screen and the memberships that say which tool a person may open. A flaw here is
not a flaw in one tool; it is a flaw in all of them at once.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Ulzuhan/kaicorp-account/security/advisories/new)
on this repository. That channel stays private until we publish it together.

Please do not open a public issue for anything exploitable.

**What to expect:** an acknowledgement within 72 hours, an assessment within
7 days, and a fix or a written explanation of why there is not going to be one.
You will be credited in the advisory unless you would rather not be. There is no
bounty.

## What it is, in security terms

- **Consent is the gate.** Every tool is an OAuth client tied to exactly one
  group. The consent page approves only if the person belongs to that group. The
  first tool somebody asks for is approved by a human; after that the next ones
  open on their own.
- **Revoking a membership revokes the grant**, so the provider stops approving
  by itself and the tool's refresh tokens die. An access token already issued is
  bounded by its own expiry, not by the revocation.
- **The session key encrypts tokens at rest and signs session cookies and CSRF tokens.**
  Rotating it closes every session at once.
  Each access and refresh envelope is authenticated against its token kind,
  provider user ID, AAL, stable row reference, and current cookie bearer. Every
  load authenticates both envelopes and asks GoTrue to confirm the access-token
  subject, including AAL2; refresh responses are checked before storage. Session
  lifecycle updates use narrow `SECURITY DEFINER` operations instead of direct
  runtime `UPDATE` rights. The migration that introduces these envelopes closes
  existing local sessions once because legacy ciphertext has no trustworthy row
  binding; deploy it with legacy replicas stopped so no old process can publish
  another unbound envelope during the transition.
  Database session IDs alone cannot authenticate. Unsigned cookies from older
  versions are rejected; users must sign in again when signed cookies are introduced.
  Administrative sign-out advances a durable per-user generation and
  not-before cutoff under the session-publication lock. Pre-cutoff provider
  tokens cannot publish later, and every load rejects a surviving old row,
  including cached AAL2 sessions. Provider and local cleanup are idempotent and
  an incomplete cleanup is reported as a failure. The operation does not report
  success until a newly issued provider token can be strictly newer than the
  cutoff; administrative, CLI, and fail-closed security paths use the same
  primitive.
- **Choosing or changing a password needs fresh proof.** Self-registration stores
  only a server-random unknown credential until the mailbox is confirmed.
  A signup email also carries an encrypted, address-bound setup proof; links
  issued before that proof existed are rejected without confirming the account,
  and requesting a replacement rotates an old unconfirmed credential before the
  new email is sent. Onboarding (signup or invitation) and recovery then use
  distinct five-minute, single-purpose, one-use capabilities. Neither capability
  can authenticate as a normal session; that session exists only after the final
  password is saved. An app-generated, sealed and time-limited intent also
  binds password recovery to a recovery email;
  a raw token from the provider's shared magic-link storage is not enough. An
  email hash is never redeemed until the provider's authoritative
  `auth.one_time_tokens` row binds its exact purpose, normalized recipient,
  user and unconsumed state, and the matching issuance time is still live. The
  configured local lifetime must match GoTrue's email OTP lifetime and is capped
  at one day. Secure email change distinguishes the old-recipient hash from the
  new-recipient hash and serializes both arms for that user across replicas before
  accepting either partial confirmation. An
  ordinary change verifies the current password for the same provider user. A
  successful change rotates the app credential and closes the account's other sessions.
- **Password guesses have a durable shared budget.** Before every human-entered
  password reaches GoTrue, the app atomically reserves from a PostgreSQL-backed
  account budget and an account/client budget. The account key is the stable
  provider user ID when known; unknown addresses use an opaque digest with the
  same external behavior. Moving between IPs, processes, routes, or replicas
  cannot reset the account budget. Backoff grows to a capped 60 seconds and is
  returned as a generic HTTP 429 with `Retry-After`; provider and edge limits
  remain defense in depth.
- **The service key has three narrow jobs**: blocking and deleting accounts,
  and replacing pending passwords before a replacement signup email or while
  completing an administrator-issued invitation. It is not the key the app runs on.
- **Database authority is split by capability.** The long-running `account` login
  has explicit DML only, the one-off `account_migrator` login owns schema
  objects, and the no-login `account_hook` role owns the five provider-facing
  `SECURITY DEFINER` functions with three exact business-table reads. A second
  no-login role can lock only two coordination rows. Runtime credentials cannot
  replace relations or functions consumed by a privileged hook.
- **The second factor is optional and double**: a TOTP authenticator, and since
  0.7.0 passkeys, stored by GoTrue as `webauthn` factors with the app's public
  host as the relying party. Adding, verifying, or removing one requires a
  five-minute, one-use recent-authentication grant bound server-side to the
  user, initiating app session, purpose, and exact pending or removal target.
  It starts with the current password and, if a factor already exists, a fresh
  assertion from a different verified factor. Removing the final factor also
  requires a recovery email opened by that same signed-in session. A completed
  change rotates the active bearer and closes every other app and provider
  session; cancelling the exact unverified factor only rolls back its pending
  enrollment.
- **The app refuses to run half-configured.** Every `ACCOUNT_*` variable is
  validated at start, because an account app missing a piece is a door left ajar.
  The configured administrator group must also exist as a non-requestable role.
- **Roles are never self-service.** Group kind is stored explicitly and enforced
  by a database constraint. Groups default to non-requestable roles; an ordinary
  tool must opt in to both tool kind and requestability. The request transaction
  independently rejects every role and the configured administrator group even
  if stored flags are corrupt.
- **Two narrowly scoped scripts, no inline code.** `static/js/passkey.js` exists
  because WebAuthn only exists in the browser. `static/js/email-link.js` moves
  one-use mail capabilities from URL fragments into CSRF-protected forms and
  immediately removes the fragment from history. Neither makes network calls;
  the content policy is `script-src 'self'`.

### Registration-hardening rollout

Old signup links are rejected before token exchange. An owner can register again;
the replacement flow rotates any still-unconfirmed account to a new unknown
password before sending its new link. The app still cannot tell whether an account
confirmed before deployment was created by its mailbox owner or was already taken
over. A rollout after an exposure window therefore also needs an operator-led
response for those already-confirmed accounts: first randomize or otherwise
disable their old passwords, then revoke their app/provider sessions, and require
a new mailbox-bound password recovery before restoring access. Revocation alone
is not enough because an attacker who knows the old password can immediately sign
in again.

## In scope

- Approving consent without the membership that should be required, or reaching
  `/admin` without the administrator membership.
- Forging, fixing or replaying a session; CSRF against any state-changing form.
- Taking over an account through registration, recovery, e-mail change,
  invitation or the second-factor flows — including skipping the second factor.
- Consuming an e-mail link or changing the browser's effective account through
  GET or HEAD. Link navigation must remain inert; token exchange requires an
  explicit same-origin, CSRF-protected confirmation of the intended address.
- Reading another person's memberships, requests or e-mail address.
- Enumerating accounts: any response that confirms an address exists when it
  should not.
- Any path where a token, a code or the session key reaches a log, a URL or a
  third party.

## Out of scope

- Scanner output with no working exploit, or missing headers with no shown impact.
- Volumetric denial of service. A way *around* a documented limit is in scope;
  sending more traffic than a host can take is not.
- Misconfiguration of your own deployment, unless an unsafe default here causes it.
- Social engineering, and attacks that need physical access to the machine.

## What it does not claim

It is not the identity provider. GoTrue issues the tokens, keeps the factors and
enforces their verification; this app decides who may ask for one. A defect in
GoTrue belongs upstream, and we will say so and point you there.

## Supply chain

Dependencies are pinned by `go.mod` and `go.sum`; Renovate opens grouped updates
weekly and security updates immediately. Every GitHub Action is pinned by commit
SHA. The image is built with signed provenance — attested to this repository,
workflow and commit, and verified in the same run — carries an SBOM, and every
published digest is scanned with Trivy for fixable critical and high CVEs. A red
run is not deployed.
