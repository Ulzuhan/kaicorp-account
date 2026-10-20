# Account remediation validation status

This document records the regression scope for PR #10. A green test suite is
evidence for the tested boundaries, not a substitute for reviewing the security
diff or planning a production migration.

## Current scope

`tools/ci/full-tests.json` inventories all **178** top-level Go tests, with
source hashes. `tools/ci/test-scope-review.json` records their review and
`docs/PRIOR-DEFERRED-TESTS.tsv` preserves the former 17 exclusions and their
reasons. No test remains excluded. The CI runner checks the inventory, rejects
test failures and skips, then runs `go test -race -json -count=1 -timeout=180s
-p=1 ./...` against a disposable PostgreSQL service. Each database fixture
creates and drops its own synthetic database. Provider HTTP calls use loopback
mocks. The runner accepts only the explicitly configured loopback CI database
URL and inherits no user database configuration.

On 2026-10-20 the full suite passed locally at `78d1619`: **178 top-level
tests and 200 subtests passed**, zero test failures or skips, and no race
warnings. Go reported two packages with no test files. The full CI result for
the commit that changes this workflow must be checked separately; a local pass
does not establish a green PR.

## Earlier restriction and resolution for this suite

An earlier synthetic dynamic reproduction of automatic membership
grant/revocation was stopped by a security review. Its literal reason could not
be recovered. The later 24, then 17, excluded repository tests were deferred
preventively; there is no evidence that each was rejected individually. The
original ad hoc reproduction harness was never executed and is not included in
this suite.

On 2026-10-20 the current account check reported Daybreak Blue access. That
check is advisory, so it was not treated as permission to route the stopped
operation through GitHub Actions. First, the existing focused regression
`TestRevocarTodoNoOmiteConcesionAutomaticaEnVuelo` was submitted to the current
execution review and allowed in a local disposable PostgreSQL lab. It passed
with the race detector. The remaining repository tests were then run in the
same local lab as the complete suite and passed. Their restoration to this PR
keeps the actual assertions and makes their result visible in GitHub Actions.
This does not claim that the earlier ad hoc harness was run or that the reason
for its rejection is known.

The prior stages remain recorded in Git history: 80 tests and 149 subtests in
the first selection; 154 and 188 at `316e7fc`; 161 and 190 at `78d1619`. The
seven failures seen at `8923cf3` were repaired in fixtures without removing
assertions. This workflow change does not modify application code or test
assertions.

## Review and release

The owner approved a commit exception for this isolated PR while full testing
was restricted. The repository's `AGENTS.md` still calls for `go test ./...`,
`go vet ./...` and `gofmt -l .` before a commit. Once the full PR checks finish,
review the final diff and their logs before marking the PR ready or merging.
The container PR job builds, checks its runtime contract and scans locally; it
does not publish an image. No merge, image publication or deployment is part of
this validation change.

Deployment requires a separate plan for identity backup/restore, TLS and TTL
configuration, roles, and one-shot migrations. Migration 0010 invalidates
legacy Account sessions; a binary-only rollback is insufficient.
