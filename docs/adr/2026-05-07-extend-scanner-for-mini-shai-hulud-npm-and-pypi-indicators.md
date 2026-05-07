---
status: accepted
date: 2026-05-07
decision-makers: hokupod
---

# Extend Scanner for Mini Shai-Hulud NPM and PyPI Indicators

## Context and Problem Statement

The scanner originally focused on NPM packages identified in the Shai-Hulud supply-chain attack. The Mini Shai-Hulud campaign added a smaller but cross-ecosystem set of indicators that affect both NPM packages used by JavaScript-based GitHub Actions and the PyPI `lightning` package used by Python-based tooling.

The repository already has Go-based scanners for `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`, plus a static vulnerable package list and semver-based matching. The update must preserve the existing CLI surface and reporting behavior while adding enough ecosystem separation that future package ecosystems can be added without overloading the NPM list.

## Decision

Adopt an ecosystem-specific vulnerability catalog and extend action scanning to include Mini Shai-Hulud NPM and PyPI indicators.

In scope:

- Add NPM indicators: `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`, and `intercom-client@7.0.4`.
- Add PyPI indicators: `lightning==2.6.2` and `lightning==2.6.3`.
- Scan `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock` in downloaded action repositories.
- Treat `requirements*.txt` ranges that can resolve to a vulnerable PyPI version as potential matches.
- Keep the CLI arguments, normal output flow, and vulnerability exit-code behavior unchanged.

Non-goals:

- Do not add Composer/Packagist scanning for `intercom/intercom-php@5.0.2` in this change.
- Do not add static compromise-artifact scanning for files such as `.claude/settings.json` or `.vscode/tasks.json`.
- Do not add `--fail-on-vulnerability` or other CI-fail behavior.
- Do not introduce a new TOML parser dependency for `poetry.lock` or `uv.lock`.

## Consequences

- Good, because NPM and PyPI indicators are separated in `VulnerabilityCatalog`, so future ecosystem additions do not have to pretend to be NPM packages.
- Good, because the existing CLI remains compatible for current users.
- Good, because Python lockfiles and requirements files cover common dependency declaration formats used by actions.
- Bad, because `requirements*.txt` range checks are conservative and can report potential matches when the actual resolved version is unavailable.
- Bad, because the `poetry.lock` and `uv.lock` readers intentionally parse only the `[[package]]` name/version shape needed for this detection instead of becoming general TOML parsers.

## Implementation Plan

- **Affected paths**: `vulnerable_packages.go`, `scanner.go`, `main.go`, `scanner_test.go`, `README.md`, `AGENTS.md`, `docs/adr/`.
- **Dependencies**: do not add new dependencies; reuse `github.com/Masterminds/semver/v3` for comparable Python version strings.
- **Patterns to follow**: build O(1) lookup maps before scanning; keep scan helpers file-focused; return `[]string` findings and `error`; preserve existing console output style.
- **Patterns to avoid**: do not merge PyPI indicators into the NPM list; do not change CLI arguments; do not make vulnerability findings exit non-zero; do not add broad TOML parsing unless a future ADR accepts that dependency.
- **Catalog changes**: keep `GetVulnerablePackages()` as a compatibility wrapper for NPM packages, and use `GetVulnerabilityCatalog()` for new full scans.
- **Scanner changes**: call NPM scanners with the NPM map and Python scanners with a canonicalized PyPI map.
- **Documentation changes**: document Mini Shai-Hulud coverage and explicitly note Composer/Packagist as out of scope.

### Verification

- [ ] `go test ./...` passes.
- [ ] Mini Shai-Hulud NPM indicators are detected from `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
- [ ] `lightning==2.6.2` and `lightning==2.6.3` are detected from `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`.
- [ ] `lightning==2.6.1` is not detected.
- [ ] `lightning>=2.6.2,<2.6.4` is reported as a potential match.
- [ ] Running the CLI with the same arguments as before still works and does not change vulnerability exit-code behavior.

## Alternatives Considered

- NPM-only update: rejected because the Mini Shai-Hulud campaign includes PyPI `lightning`, and excluding it would leave a known affected ecosystem uncovered.
- Put PyPI indicators into the existing NPM list: rejected because it would blur ecosystem semantics and make future scanner behavior harder for agents to reason about.
- Add Composer scanning now: rejected because the current tool and implementation plan target NPM/PyPI only; Composer support needs separate lockfile parsing and scope review.
- Add a TOML dependency for Python lockfiles: rejected for this change because the required `[[package]]` name/version shape can be handled without expanding the dependency surface.

## More Information

- GMO Flatt Security: `https://blog.flatt.tech/entry/mini_shai_hulud`
- Socket campaign page: `https://socket.dev/supply-chain-attacks/mini-shai-hulud`
- Revisit this decision if Composer/Packagist scanning becomes in scope, if Python lockfile formats used by actions require richer TOML handling, or if the CLI adds configurable failure behavior.
