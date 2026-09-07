# HeaderHound v0.2.0 release notes (draft)

## Added

- Passive Set-Cookie analysis with redacted cookie values and structured metadata.
- Passive CORS, cache-policy, transport, and technology-disclosure checks.
- Directive-aware CSP hardening findings.
- JSON sections for cookies, CORS, transport, and metadata.
- CI-friendly `--json`, `--min-score`, and `--fail-on` options.

## Security and compatibility

- Redirect destinations now pass through the existing public-address policy before fetching.
- Default TLS verification, request bounds, and private-address blocking remain unchanged.
- Existing `--format` and `--fail-under` options remain supported.

These checks are passive posture signals, not proof of exploitable vulnerabilities.
