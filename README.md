# HeaderHound

[![CI](https://github.com/m-ramadan-sec/headerhound/actions/workflows/ci.yml/badge.svg)](https://github.com/m-ramadan-sec/headerhound/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HeaderHound is a defensive web-security posture auditor. It requests one authorized URL, follows a bounded redirect chain, and reports configuration signals in a readable terminal table or stable JSON. It is not a penetration-test or vulnerability-exploitation tool.

It is intended for systems you own or are authorized to assess. It does not crawl, exploit vulnerabilities, fuzz endpoints, or perform destructive actions.

## Install

HeaderHound requires Python 3.10 or newer. Once a release is published to PyPI, install it with either `pip` or `pipx`:

```bash
python -m pip install --upgrade headerhound
# or, for an isolated command-line application:
pipx install headerhound
```

For an unreleased source checkout, use `python -m pip install .` instead.

## Packaging and distribution

GitHub releases are the source of versioned distributions. The release workflow builds a wheel and source distribution, validates both, and publishes them to [PyPI](https://pypi.org/project/headerhound/) with PyPI Trusted Publishing. It uses GitHub Actions OIDC and does not store a PyPI API token in this repository.

After publication, install the latest release with:

```bash
python -m pip install --upgrade headerhound
pipx install headerhound
```

The published project page lists the exact wheel and source-distribution files for every release.

## Usage

```bash
headerhound https://example.com
headerhound https://example.com --format json
headerhound https://example.com --json --min-score 80
headerhound https://staging.example.com --fail-on high
headerhound https://example.com --format json --fail-under 80
headerhound https://service.internal --allow-private --timeout 15
```

Example terminal output:

```text
Target: https://example.com/
Final URL: https://example.com/
HTTP status: 200
Security score: 78/100 (grade C)

+----------+-----------------------------------+--------------------------------+
| Severity | Finding                           | Details                        |
+----------+-----------------------------------+--------------------------------+
| HIGH     | Content-Security-Policy missing   | The browser receives no policy |
+----------+-----------------------------------+--------------------------------+
```

Exit status is `0` for a completed scan and `2` for invalid input or retrieval failure. JSON errors are written to standard error as `{"error": "..."}`.
Use `--fail-under SCORE` to return exit status `1` when a completed scan is below a chosen CI threshold.
`--min-score` is an alias for `--fail-under`; `--fail-on low|medium|high` returns `1` when a finding meets that severity.

## Checks

HeaderHound assesses the presence and selected high-signal weak configurations of:

- `Content-Security-Policy` — including report-only mode, no `default-src`, wildcard sources, `unsafe-inline`, and `unsafe-eval`
- `Strict-Transport-Security` — HTTPS-only evaluation, invalid/disabled values, and short `max-age`
- `X-Content-Type-Options` and `X-Frame-Options`
- `Referrer-Policy` and `Permissions-Policy`
- `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Cross-Origin-Embedder-Policy`
- `Set-Cookie` attributes without exposing cookie values: `Secure`, `HttpOnly`, `SameSite`, parent-domain scope, and long lifetimes
- Passive CORS policy (`Access-Control-Allow-*`), including wildcard origin/method/header settings
- HTTP-to-HTTPS redirects, HSTS `max-age`, `includeSubDomains`, and `preload`
- Technology disclosure headers (`Server`, `X-Powered-By`, and ASP.NET version headers)
- Conservative cache signals when a response sets a session-like cookie

The score begins at 100 and subtracts the deduction attached to each finding in the report. It is deterministic and explainable, but it is a prioritization aid—not a compliance result or a substitute for application-specific review.

## JSON and CI/CD

JSON output has stable top-level `target`, `final_url`, `status`, `score`, `grade`, `headers`, `cookies`, `cors`, `transport`, `findings`, and `metadata` sections. Cookie values and `Set-Cookie` header values are never emitted. A CI job can scan an authorized staging endpoint with `headerhound "$STAGING_URL" --json --fail-on high`.

CORS and cache findings are passive configuration signals. HeaderHound does not send probing origins, credentials, exploit payloads, or destructive requests.

## Safety and network behavior

- Only `http` and `https` URLs are accepted; credentials embedded in URLs are rejected.
- By default, targets resolving to loopback, private, link-local, multicast, reserved, or unspecified addresses are rejected. Use `--allow-private` only on systems you are authorized to scan.
- TLS certificates are verified by default. `--insecure` exists only for authorized diagnostic use.
- The default timeout is 10 seconds, redirects are limited to 5, and the client disables environment proxy settings. Each redirect target is rechecked against the public-address policy.
- One request is made per invocation. `--min-interval` is available for integrations which reuse the client.

Private-address filtering is a useful guardrail, not a complete SSRF defense against DNS rebinding or hostile networks. Run scans from a suitably restricted network when targets may be untrusted.

## Architecture

```text
CLI → URL validation / target policy → bounded HTTP client → header analyzer → table or JSON renderer
```

- `safety.py`: URL validation and conservative public-target policy
- `client.py`: timeouts, redirect bound, TLS policy, and retrieval errors
- `analyzer.py`: pure, testable header checks and score calculation
- `output.py`: dependency-free terminal and JSON reports

## Limitations

HeaderHound evaluates one response (while reporting the redirect chain). It cannot determine whether headers are consistent on every route, whether a reflected CORS origin is authorized, whether a CSP is compatible with the application, whether TLS configuration is strong, or whether application behavior is secure. DNS-rebinding resistance also requires egress controls. Security headers are defense in depth.

## Release process

Maintainers run tests, linting, formatting, `python -m build`, and `python -m twine check dist/*` before creating a matching GitHub release tag. The release workflow uses PyPI Trusted Publishing; it does not use a stored PyPI API token.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [ROADMAP.md](ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
