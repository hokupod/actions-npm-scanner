---
status: accepted
date: 2026-08-06
decision-makers: hokupod
---

# Keep the @keyv Scope Out of the Confirmed Catalog and Scan npm-shrinkwrap.json

## Context and Problem Statement

The August 4, 2026 compromise started in the `keyv` and `cacheable` npm namespaces. The catalog covers the unscoped `keyv`, `cacheable`, and the four `@cacheable/*` packages, all payload-confirmed, but the `@keyv` scope had no entries. On that day the compromised account republished 17 `@keyv/*` packages as version `6.0.0` within about two and a half minutes, and every one of those versions was later removed from the registry.

Whether those releases belong in the catalog depends on the evidence threshold. The registry publish record proves that the versions were published in the incident window and later removed; it does not prove the tarballs carried the malicious `preinstall` payload. The payload-level analyses point the other way: Socket states the scoped `@keyv/*@6.0.0` tarballs lacked the malicious hook and classifies them as suspect, Socket's campaign CSV contains no `@keyv/*` row, and Snyk's tarball and manifest sweep concluded the other packages under the scope were not compromised. This tool has a single confidence level — every catalog entry is reported as `Found vulnerable package ...` and fails the scan — so listing a suspect release makes it indistinguishable from a confirmed one.

Sources (all accessed 2026-08-07):

- Socket analysis: <https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain>
- Socket campaign CSV: <https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv>
- Snyk analysis: <https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/>
- Aikido confirmed-package list: <https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack>
- npm lockfile precedence: <https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/#package-lockjson-vs-npm-shrinkwrapjson>

The catalog also names `file-entry-cache@11.1.6` for this campaign, matching the Socket CSV row (`npm,,file-entry-cache,11.1.6,...`) and Aikido's list. No source in the set above lists `11.1.7`, so no entry exists for it.

Separately, `npm-shrinkwrap.json` was never read. It uses the `package-lock.json` format and, unlike `package-lock.json`, is published inside the package tarball, so an action can ship one as its only dependency lockfile. npm also defines a precedence between the two files: when `npm-shrinkwrap.json` is present, npm installs from it and ignores `package-lock.json`.

## Decision

Keep the catalog confirmed-only, and read `npm-shrinkwrap.json` with the existing `package-lock.json` scanner, honoring npm's precedence.

In scope:

- Do not add the 17 `@keyv/*@6.0.0` releases. The evidence threshold for a catalog entry is payload-level confirmation by at least one published analysis, and none exists for these tarballs. A regression test pins the whole scope out of the catalog.
- Scan `npm-shrinkwrap.json` in `scanAction` and accept it in `scanDependencyFile`, reusing `scanPackageLockJSONOptimized` because the two formats are identical.
- When both files exist in a directory, scan only `npm-shrinkwrap.json`, because that is the file npm installs from; a stale `package-lock.json` next to it describes packages npm never installs.

Non-goals:

- Do not introduce a `suspect` / `unconfirmed` classification. That requires its own output format, exit-code policy, and tests, and is a separate decision. If payload evidence for the `@keyv/*@6.0.0` tarballs is published later, the entries can be added to the confirmed catalog in a single commit.
- Do not add a registry lookup at scan time. The catalog stays static and offline.
- Do not widen the `@cacheable` scope. Its monorepo publishes exactly the four scoped packages already listed.

## Consequences

- Good, because every catalog hit remains a confirmed compromise, so a finding can be acted on without re-verifying the underlying evidence.
- Good, because an action that ships only an `npm-shrinkwrap.json` is no longer skipped entirely.
- Good, because a directory with both npm lockfiles is judged by the file npm actually installs from, eliminating false positives from stale `package-lock.json` content.
- Bad, because if the `@keyv/*@6.0.0` tarballs are later confirmed malicious, lockfiles pinning them scan clean until the entries are added.
- Bad, because a stale vulnerable `package-lock.json` next to a safe shrinkwrap is no longer reported at all, even as a hint that the repository once pinned a compromised version.

## Alternatives Considered

- **Catalog the 17 `@keyv/*@6.0.0` releases based on the registry publish record**: rejected. Publication in the incident window plus later removal proves publication history, not payload execution. With a single-confidence catalog, every historical lockfile pinning one of these releases would produce a confirmed-looking false positive, which erodes the trust that makes a finding actionable.
- **Introduce a `suspect` classification and list them under it**: deferred. This is the right shape if unconfirmed IoCs should be surfaced, but it changes the catalog structure, the output, and the exit-code policy at once, and deserves its own ADR. Deferring costs little: the affected versions are removed from npm, so no fresh install can pull them.
- **Treat every incident-window publication as vulnerable**: rejected as a general policy for the same false-positive reason, and because it would commit the catalog to a threshold that no published analysis backs.
- **Scan both npm lockfiles when they coexist**: rejected. npm ignores `package-lock.json` when `npm-shrinkwrap.json` exists, so findings from the ignored file describe packages that are never installed.

## Implementation Plan

- **Affected paths**: `scanner.go`, `scanner_test.go`, `main_test.go`, `README.md`, `docs/adr/`.
- **Catalog** (`vulnerable_packages.go`): `GetVulnerableNpmPackages` carries no `@keyv/*` entries; the confirmed `keyv`, `cacheable`, `@cacheable/*`, and `file-entry-cache@11.1.6` entries are unchanged.
- **Scanner** (`scanner.go`): `scanAction` stats `npm-shrinkwrap.json` first and scans it with `scanPackageLockJSONOptimized`; only when it is absent does it scan `package-lock.json`. `scanDependencyFile` accepts the `npm-shrinkwrap.json` filename for single-file `--local` scans, where the caller names one file explicitly and no precedence applies.
- **Tests**: `TestKeyvScopeStaysOutOfConfirmedCatalog` pins the scope out of the catalog; `TestScanActionWithNpmShrinkwrapJSON` covers the shrinkwrap-only directory using the confirmed `keyv@6.0.0`; `TestScanActionNpmShrinkwrapTakesPrecedenceOverPackageLock` covers coexistence in both directions.

## Verification

- [ ] `gofmt`, `go vet ./...`, `go test ./... -count=1`, and `go test -race ./... -count=1` pass.
- [ ] Every npm catalog entry for this campaign traces to a payload-confirmed row in the Socket CSV or an equivalent published analysis; no `@keyv/*` entry exists (`TestKeyvScopeStaysOutOfConfirmedCatalog`).
- [ ] A directory with only `npm-shrinkwrap.json` is scanned (`TestScanActionWithNpmShrinkwrapJSON`).
- [ ] A safe shrinkwrap next to a vulnerable stale `package-lock.json` scans clean, and a vulnerable shrinkwrap next to a safe `package-lock.json` is detected (`TestScanActionNpmShrinkwrapTakesPrecedenceOverPackageLock`).
- [ ] No dependency is reported twice for a directory containing both npm lockfiles (covered by the same precedence test: exactly one finding).
- [ ] Verbose output names the lockfile pair once when neither exists (`TestMainVerboseIncludesDetailedOutputAndSummary`).
