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
- **The session key encrypts tokens at rest and signs the CSRF tokens.**
  Rotating it closes every session at once.
- **The service key is used for one thing**: blocking and deleting accounts. It
  is not the key the app runs on.
- **The second factor is optional and double**: a TOTP authenticator, and since
  0.7.0 passkeys, stored by GoTrue as `webauthn` factors with the app's public
  host as the relying party.
- **The app refuses to run half-configured.** Every `ACCOUNT_*` variable is
  validated at start, because an account app missing a piece is a door left ajar.
- **One script, no inline code.** `static/js/passkey.js` exists because WebAuthn
  only exists in the browser; the content policy is `script-src 'self'`.

## In scope

- Approving consent without the membership that should be required, or reaching
  `/admin` without the administrator membership.
- Forging, fixing or replaying a session; CSRF against any state-changing form.
- Taking over an account through registration, recovery, e-mail change,
  invitation or the second-factor flows — including skipping the second factor.
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
