# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [0.2.0] - 2026-09-07

### Added

- Passive cookie metadata analysis with value redaction.
- Passive CORS, cache, transport, and technology-disclosure checks.
- Structured JSON sections for cookies, CORS, transport, and scan metadata.
- `--json`, `--min-score`, and `--fail-on` CLI options.

### Changed

- CSP analysis now evaluates directive-level hardening signals.
- Redirect targets are checked against the existing private-address policy.

## [0.1.1] - 2026-09-07

### Added

- Wheel and source-distribution validation in GitHub Actions.
- A GitHub Release-to-PyPI workflow using Trusted Publishing and OIDC.

### Changed

- Hardened package metadata and limited source-distribution contents to release-relevant files.
- Clarified PyPI and pipx installation guidance.

## [0.1.0] - 2026-09-07

### Added

- Initial defensive HTTP security-header scanner CLI.
- Explainable terminal and JSON reports with weighted scores.
- Bounded redirects, TLS verification, timeouts, and private-target protection.
- Unit and local HTTP integration tests, linting, and GitHub Actions CI.
