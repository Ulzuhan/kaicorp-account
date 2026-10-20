# Partial audit remediation candidate — do not merge or deploy

This draft collects the seven local remediation commits and subsequent uncommitted fixes. It is a review candidate, not a claim that the audit is closed or that all regressions pass.

## Explicit validation scope

`tools/ci/partial-tests.json` contains a closed list of **80 allowed tests** and **98 deferred tests**. `tools/ci/deferred-tests.tsv` gives every deferred name and source file. The runner checks the inventory and selected-source hashes before execution, rejects skips or unexpected tests, and does not run the complete suite or the race detector. Config, pure policy functions, templates, serialization, cookies and local mock-client checks form the selected scope; it does not initialize a database.

A prior dynamic validation restriction remains unresolved. The deferred set includes the related membership/grant/revocation regressions and cases involving persistent authority or concurrency that were not confidently separated. This is a deferral list, not a statement that each of the 98 tests was individually denied. All deferred tests remain in the source tree.

The allowed selection passed locally with Go 1.27.3: 80 top-level tests and 149 subcases, with no failures or skips, against matching compiled/embedded sources. Separate normal synthetic integration checks previously passed; they do not replace the deferred regressions or certify a production installation. CI reports its own results for this commit.

## Commit exception and merge block

The owner explicitly approved a **one-time exception** to the full-suite-before-commit instruction for this isolated draft PR, with partial validation visible. `AGENTS.md` is unchanged. This does not authorize the previously restricted reproductions, merge, publication or deployment.

The CI workflow names its allowed test job as partial and deliberately fails a separate `BLOCKED — full validation pending` job. That failure is expected and must not be fixed by deleting the gate, suppressing excluded tests invisibly, or describing a partial green job as a complete pass. Keep the PR draft while the restriction and remaining validation are unresolved. Existing main/tag protections are unchanged.

The PR container job only builds, checks its runtime contract and scans locally on the runner; it does not push an image. Main/tag publication jobs are not run for this PR.

Before any later merge or release, resolve the permitted validation scope, complete the required checks, and review the resulting immutable commit and image. Deployment also needs coordinated identity backup/restore, TLS and TTL configuration, roles and one-shot migrations. Migration 0010 invalidates legacy Account sessions; a binary-only rollback is insufficient. None of those production operations is part of this draft.
