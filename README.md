# HeaderHound

[![CI](https://github.com/m-ramadan-sec/headerhound/actions/workflows/ci.yml/badge.svg)](https://github.com/m-ramadan-sec/headerhound/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HeaderHound is a defensive, explainable command-line scanner for HTTP response security headers. It requests one URL, follows a bounded redirect chain, and reports missing or risky configurations in a readable terminal table or stable JSON.

It is intended for systems you own or are authorized to assess. It does not crawl, exploit vulnerabilities, fuzz endpoints, or perform destructive actions.

## Install

Requires Python 3.10 or newer.

```bash
pipx install headerhound
# or, from a source checkout:
python -m pip install .
```

## Usage

```bash
headerhound https://example.com
headerhound https://example.com --format json
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

## Checks

HeaderHound assesses the presence and selected high-signal weak configurations of:

- `Content-Security-Policy` — including report-only mode, no `default-src`, wildcard sources, `unsafe-inline`, and `unsafe-eval`
- `Strict-Transport-Security` — HTTPS-only evaluation, invalid/disabled values, and short `max-age`
- `X-Content-Type-Options` and `X-Frame-Options`
- `Referrer-Policy` and `Permissions-Policy`
- `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Cross-Origin-Embedder-Policy`

The score begins at 100 and subtracts documented weighted findings. It is a prioritization aid, not a compliance result or a substitute for application-specific review.

## Safety and network behavior

- Only `http` and `https` URLs are accepted; credentials embedded in URLs are rejected.
- By default, targets resolving to loopback, private, link-local, multicast, reserved, or unspecified addresses are rejected. Use `--allow-private` only on systems you are authorized to scan.
- TLS certificates are verified by default. `--insecure` exists only for authorized diagnostic use.
- The default timeout is 10 seconds, redirects are limited to 5, and the client disables environment proxy settings.
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

HeaderHound evaluates only the final HTTP response (while reporting the redirect chain). It cannot determine whether a header is consistently set on every route, whether a CSP is compatible with the application, whether TLS configuration is strong, or whether application behavior is secure. Security headers are defense in depth.

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
