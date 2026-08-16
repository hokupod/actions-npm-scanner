---
status: proposed
date: 2026-08-06
decision-makers: hokupod
---

# Scan pnpm Lockfile v6 to v9 and Isolate Per-File Scan Errors

## Context and Problem Statement

`PnpmLock.LockfileVersion` was typed as `int`. pnpm writes `lockfileVersion` as a number (`5.4`) up to lockfile v5, but as a quoted string (`'6.0'`, `'9.0'`) from v6 onwards, so decoding a v6+ lockfile failed with `cannot unmarshal !!str '9.0' into int`.

That failure was not contained to the lockfile. `scanAction` returned on the first error, so the whole directory scan was abandoned and the findings already collected from `package.json`, `package-lock.json`, and `yarn.lock` in the same directory were discarded. In workflow mode the failure only appeared as an `Error details` line on stdout and the process still exited `0`, so an automation that greps stdout could not tell a partial scan from a clean one.

Even with the version field decoded, the package keys of v6+ lockfiles were still unreadable. `extractPackageNameAndVersionFromPnpmPath` assumed the v5 `/name/version` shape, while v6 through v8 use `/name@version` and v9 uses `name@version` with the resolved graph moved to `importers` and `snapshots`. As a result no package from a v6+ lockfile was ever matched against the catalog.

## Decision

Read every pnpm lockfile version the tool is likely to encounter, and make a failing dependency file a per-file outcome rather than a per-directory one.

In scope:

- Decode `lockfileVersion` as a raw `yaml.Node` so both the numeric and the quoted-string form are accepted.
- Resolve package keys for lockfile v5 (`/name/version`), v6 to v8 (`/name@version`), and v9 (`name@version`), stripping the peer-dependency suffix in both the v5 (`_vue@2.6.14`) and v6+ (`(vue@3.0.0)`) form.
- Split a `name@version` key at the first `@` after the scope rather than the last one, and reject a version candidate containing `@` or `/`, so that a name starting with a digit (`@scope/7zip-bin`) or containing an underscore (`string_decoder`) is not silently mismatched against the catalog.
- Collect packages from `importers` (v6+) and `snapshots` (v9) in addition to `packages`, `dependencies`, and `devDependencies`, reporting each name/version pair once.
- Accept both the scalar and the `specifier`/`version` mapping form of a dependency entry, and ignore non-registry references such as `link:../shared`.
- Collect per-file failures in `actionScanResult.FileErrors` and keep scanning the remaining files in the directory.
- Report the number of unscanned files as `Files failed` in the summary and write error details to stderr.
- Add `--fail-on-error` to exit with status code `2` when the scan reported at least one error. Key the flag off the error count rather than `Files failed`, because an action that could not be downloaded was never scanned at all yet reaches none of its files, so it leaves `Files failed` at zero.
- Apply the flag to every error path, including a top-level failure that aborts the scan before a summary exists (for example an unparsable single `--local` file), and give the error exit precedence over the vulnerability exit when both apply: an incomplete scan may hide further findings, so `2` must not be masked by `1`.
- Report a dependency file whose directory entry exists but cannot be resolved (a symlink to a missing target) as a failed file instead of skipping it as "not found". Skip only when `os.Lstat` reports that the entry does not exist; record every other `os.Lstat` failure as a per-file error with its cause.

Non-goals:

- Do not change the default exit codes. For a completed scan, `1` still means a vulnerability was found and `0` still means the scan finished without one, whether or not some files failed. A top-level error that prevents the scan from producing a summary at all (a bad invocation, an unreadable path, or a failed single-file `--local` parse) keeps its pre-existing exit code `1`; only `--fail-on-error` changes it, to `2`.
- Do not scan pnpm workspace members outside the scanned directory; `importers` entries are read from the lockfile only.
- Do not resolve the peer-dependency variants of a package as separate findings; the base version is what the catalog matches.

## Consequences

- Good, because pnpm-based actions and repositories are actually scanned instead of silently failing; every pnpm lockfile from v5 to v9 is now readable.
- Good, because an unparsable file can no longer hide the findings of its neighbours, which was the failure mode with the largest blast radius.
- Good, because `Files failed` and the stderr error output give automation a way to distinguish a partial scan from a clean one, and `--fail-on-error` makes that distinction enforceable in CI.
- Good, because the default exit codes are unchanged, so existing pipelines keep working.
- Bad, because moving error details to stderr changes what a pipeline capturing only stdout sees; such a pipeline now observes the `Files failed` count instead of the error text.
- Bad, because `ScanAction` now returns findings together with an error, so callers that treat a non-nil error as "no results" will under-report until they read both values.

## Implementation Plan

- **Affected paths**: `scanner.go`, `main.go`, `scanner_test.go`, `main_test.go`, `README.md`, `docs/adr/`.
- **Dependencies**: no new dependencies; `gopkg.in/yaml.v3` already provides `yaml.Node` for the version field.
- **Lockfile parsing** (`scanner.go`): `PnpmLock.LockfileVersion` becomes a `yaml.Node`; `extractPackageNameAndVersionFromPnpmPath` resolves the v5, v6–v8, and v9 key shapes; `cleanPnpmVersion` strips both peer-suffix forms and rejects candidates containing `@` or `/`; `collectPnpmPackageEntries` gathers `packages`, `snapshots`, `importers`, and the top-level dependency maps, deduplicated.
- **Error isolation** (`scanner.go`): `scanAction` records each file's failure in `actionScanResult.FileErrors` and continues; `statDependencyFile` skips only an entry for which `os.Lstat` returns not-exist, records other `os.Lstat` failures with their cause, and records an unresolvable entry when `os.Lstat` succeeds but `os.Stat` fails, in both the npm and the Python lockfile loop.
- **Exit codes** (`main.go`): with `--fail-on-error`, a top-level scan error exits `2` instead of `1`, and after a completed scan the `HasErrors()` check runs before the `HasVulnerabilities()` check. Precedence with the flag set: error (`2`) > vulnerability (`1`) > clean (`0`). Without the flag the codes are unchanged: vulnerability (`1`) > clean (`0`), errors alone exit `0` after a completed scan.
- **Tests**: exit-code-specific assertions use a compiled binary (`runScannerBinary`), because `go run` reports its own exit code `1` for any non-zero child exit.

## Verification

- [x] `gofmt`, `go vet ./...`, and `go test ./...` pass.
- [x] `TestScanActionWithPnpmLockV9` / `TestLocalScanDirectoryWithPnpmV9Lockfile`: a v9 lockfile is scanned and the `package.json` findings next to it survive.
- [x] `TestExtractPackageNameAndVersionFromPnpmPath`: v5/v6–v8/v9 keys, both peer-suffix forms, digit-leading scoped names, underscore-containing names.
- [x] `TestScanActionKeepsFindingsWhenDependencyFileFails` / `TestLocalScanDirectoryKeepsFindingsWhenDependencyFileFails`: a broken lockfile does not discard neighbouring findings.
- [x] `TestFailOnErrorExitsWithDedicatedCode`: a failed workflow parse exits `2` with the flag.
- [x] `TestFailOnErrorAppliesToTopLevelScanError`: an unparsable single `--local` file exits `2` with the flag and `1` without.
- [x] `TestFailOnErrorTakesPrecedenceOverVulnerabilityExit`: a vulnerability plus a failed file exits `2` with the flag and `1` without.
- [x] `TestBrokenSymlinkDependencyFileIsReportedAsError`: a symlink to a missing target counts as a failed file in both the npm and the Python loop.
- [x] `TestWorkflowParseErrorAppearsInSummaryWithoutFailureExit`: without the flag, errors alone still exit `0`.

## Alternatives Considered

- Key `--fail-on-error` off `FilesFailed` instead of the error count: rejected because a failed action download leaves `FilesFailed` at zero while the action was never scanned at all, which is exactly the gap the flag exists to catch.
- Let the vulnerability exit (`1`) win over the error exit (`2`) when both apply: rejected because an incomplete scan may hide further findings; a pipeline that opts into `--fail-on-error` asks to be told about incompleteness first.
- Change the default exit code of a failed single-file `--local` scan from `1` to `0` to match the directory path: rejected because exiting `0` when the only requested target failed is weaker than the current behavior, and the wider bad-invocation/incomplete-scan exit-code contract is a separate decision.
- Treat a broken symlink as "not found": rejected because the directory entry exists; skipping it silently reports `Files failed: 0` for a directory whose lockfile was never read.
