# Partial audit remediation candidate — do not merge or deploy

This draft collects the seven local remediation commits and subsequent uncommitted fixes. It is a review candidate, not a claim that the audit is closed or that all regressions pass.

## Explicit validation scope

`tools/ci/partial-tests.json` contains a closed list of **154 allowed tests** and **24 deferred tests**. `tools/ci/deferred-tests.tsv` gives every deferred name, source file, reason and next step. `tools/ci/test-scope-review.json` records the inspection decision for all 178 tests. The runner checks inventory and selected-source hashes, rejects skips or unexpected tests, and runs the race detector only on the allowed selection. This is not the complete suite.

A prior dynamic validation restriction remains unresolved. The remaining groups are: **3** tests of automatic membership granting across revocation/stale loaded requests; **17** tests containing OAuth grant/consent invalidation, delayed writes or stale authority around membership/client revocation; **4** tests of granting/commands after administrator membership revocation. The last two groups remain deferred because of semantic overlap, not an individual platform denial. All tests remain in the source tree. Do not execute these groups until authoritative evidence clarifies the original decision and permitted scope; ordinary user approval does not lift a platform restriction.

The original selection of 80 tests passed locally and in GitHub CI with 149 subcases and no failures/skips. Inspection then separated **74 additional tests**: sessions/envelopes, MFA and password generations, email/registration, rate budgets, permission metadata and ordinary group/migration controls. Session-only cleanup/concurrency does not revoke tool membership or restore OAuth grants. Their database fixtures create a separate synthetic database per test on the job's ephemeral PostgreSQL service; provider calls use local mocks. The runner accepts only the explicit loopback job DSN and inherits no user database configuration. The session test helper now uses this existing per-test fixture instead of requiring a separately preinitialized shared database. No application code changed for this fixture repair. CI records the actual outcome of the expanded selection for each commit.

The first expanded run at `8923cf3` executed all 154 selected tests: 147 passed and seven session tests failed. The follow-up repairs their stale fixtures: timestamps are compared against the persisted PostgreSQL baseline, token assertions use the token actually created, and provider mocks accept the expected logout calls. Two concurrency tests call the session manager directly to exercise atomic promotion and closure by stable reference; the HTTP MFA flow now also serializes a single-use enrollment and closes other sessions, so it is not a barrier for those two manager operations. HTTP enrollment coverage remains in the selected tests. Failure-path checks distinguish an active session cookie from an intentional deletion cookie; stale-refresh checks still reject any cookie overwrite, including deletion. The selection remains 154/24, with no failed test removed or application code changed.

## Commit exception and merge block

The owner explicitly approved an **exception limited to this isolated draft PR and its validation follow-up commits**, with partial validation visible. The full-suite-before-commit instruction in `AGENTS.md` is unchanged. This does not authorize the previously restricted reproductions, merge, publication or deployment.

The CI workflow names its allowed test job as partial and deliberately fails a separate `BLOCKED — full validation pending` job. That failure is expected and must not be fixed by deleting the gate, suppressing excluded tests invisibly, or describing a partial green job as a complete pass. Keep the PR draft while the restriction and remaining validation are unresolved. Existing main/tag protections are unchanged.

The PR container job only builds, checks its runtime contract and scans locally on the runner; it does not push an image. Main/tag publication jobs are not run for this PR.

Before any later merge or release, resolve the permitted validation scope, complete the required checks, and review the resulting immutable commit and image. Deployment also needs coordinated identity backup/restore, TLS and TTL configuration, roles and one-shot migrations. Migration 0010 invalidates legacy Account sessions; a binary-only rollback is insufficient. None of those production operations is part of this draft.
