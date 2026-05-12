---
status: accepted
date: 2026-05-12
decision-makers: hokupod
---

# Track Mini Shai-Hulud NPM and PyPI Campaign Artifacts

## Context and Problem Statement

ADR 2026-05-07 added the first known Mini Shai-Hulud indicators for SAP CAP, Intercom, and PyPI `lightning`. Socket later expanded the campaign page to 408 affected artifacts, including 405 npm artifacts, 2 PyPI artifacts, and 1 Composer artifact.

The scanner already detects package name and version pairs from npm and Python dependency files. It does not scan Composer lockfiles, package tarball contents, or GitHub Actions workflow misconfiguration fingerprints.

## Decision

Extend the static Mini Shai-Hulud catalog to cover the npm and PyPI artifacts tracked by Socket as of 2026-05-12.

In scope:

- Add npm package/version artifacts from the Socket Mini Shai-Hulud campaign page.
- Preserve existing PyPI `lightning` 2.6.2 and 2.6.3 coverage.
- Merge static package lists by package name so repeated catalog updates add versions without overwriting older entries.
- Keep CLI arguments, output format, exit-code behavior, and catalog types unchanged.

Non-goals:

- Do not add Composer/Packagist scanning for `intercom/intercom-php@5.0.2`.
- Do not add runtime fetching of Socket campaign data.
- Do not scan file fingerprints such as `router_init.js`, `@tanstack/setup`, or `optionalDependencies`.
- Do not add GitHub Actions OIDC, cache-poisoning, or `pull_request_target` workflow audits.

## Consequences

- Good, because users get current Mini Shai-Hulud npm/PyPI coverage without changing CLI behavior.
- Good, because static data preserves offline, reproducible scans.
- Good, because package-list merging prevents duplicate package names from dropping earlier versions.
- Bad, because the catalog must still be manually refreshed when Socket adds new campaign artifacts.
- Bad, because Composer and non-package IoCs remain outside this scanner's current responsibility.

## Verification

- `go test ./...` passes.
- Representative TanStack, Mistral, Squawk, UiPath, SAP, Intercom, and PyPI indicators are covered by tests.
- A patched TanStack version is not reported as vulnerable.

## More Information

- Socket campaign page: `https://socket.dev/supply-chain-attacks/mini-shai-hulud`
- Socket TanStack report: `https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack`
- TanStack postmortem: `https://tanstack.com/blog/npm-supply-chain-compromise-postmortem`
- GitHub Security Advisory: `https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx`
