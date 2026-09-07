"""Header-specific checks and score calculation."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .models import Finding, ScanResult, Severity

_HSTS_MIN_SECONDS = 15_552_000  # 180 days


def assess(
    *,
    target: str,
    final_url: str,
    status_code: int,
    headers: Mapping[str, str],
    redirects: tuple[str, ...],
) -> ScanResult:
    """Analyze a normalized response-header mapping without making network requests."""
    normalized = {key.lower(): value for key, value in headers.items()}
    findings = (
        *_check_csp(normalized),
        *_check_hsts(normalized, final_url),
        *_check_xcto(normalized),
        *_check_xfo(normalized),
        *_check_referrer_policy(normalized),
        *_check_permissions_policy(normalized),
        *_check_coop(normalized),
        *_check_corp(normalized),
        *_check_coep(normalized),
    )
    score = max(0, 100 - sum(finding.deduction for finding in findings))
    return ScanResult(
        target=target,
        final_url=final_url,
        status_code=status_code,
        headers=normalized,
        redirects=redirects,
        findings=tuple(findings),
        score=score,
        grade=_grade(score),
    )


def _finding(
    code: str,
    title: str,
    severity: Severity,
    deduction: int,
    description: str,
    remediation: str,
    evidence: str | None = None,
) -> Finding:
    return Finding(code, title, severity, deduction, description, remediation, evidence)


def _check_csp(headers: Mapping[str, str]) -> list[Finding]:
    value = headers.get("content-security-policy")
    if not value:
        if headers.get("content-security-policy-report-only"):
            return [
                _finding(
                    "CSP_REPORT_ONLY",
                    "CSP is report-only",
                    Severity.MEDIUM,
                    12,
                    "A report-only policy does not enforce restrictions.",
                    "Deploy an enforcing Content-Security-Policy after validating reports.",
                )
            ]
        return [
            _finding(
                "CSP_MISSING",
                "Content-Security-Policy missing",
                Severity.HIGH,
                20,
                "The browser receives no policy limiting trusted content sources.",
                "Define a restrictive Content-Security-Policy, beginning with default-src.",
            )
        ]
    lower = value.lower()
    findings: list[Finding] = []
    if "default-src" not in lower:
        findings.append(
            _finding(
                "CSP_NO_DEFAULT_SRC",
                "CSP has no default-src",
                Severity.MEDIUM,
                6,
                "Unspecified fetch directives may fall back to permissive browser defaults.",
                "Set default-src and explicitly allow only required origins.",
                value,
            )
        )
    if "'unsafe-inline'" in lower:
        findings.append(
            _finding(
                "CSP_UNSAFE_INLINE",
                "CSP permits inline code",
                Severity.MEDIUM,
                7,
                "'unsafe-inline' weakens XSS mitigation for scripts or styles.",
                "Use nonces or hashes for required inline code.",
                value,
            )
        )
    if "'unsafe-eval'" in lower:
        findings.append(
            _finding(
                "CSP_UNSAFE_EVAL",
                "CSP permits eval-like code",
                Severity.MEDIUM,
                8,
                "'unsafe-eval' permits dynamic code evaluation.",
                "Remove 'unsafe-eval' and refactor code that depends on it.",
                value,
            )
        )
    if re.search(r"(?:default-src|script-src)\s+[^;]*\*", lower):
        findings.append(
            _finding(
                "CSP_WILDCARD",
                "CSP allows wildcard sources",
                Severity.MEDIUM,
                7,
                "A wildcard source allows content from arbitrary origins.",
                "Replace * with the specific origins the application needs.",
                value,
            )
        )
    return findings or [
        _finding(
            "CSP_OK",
            "Content-Security-Policy present",
            Severity.INFO,
            0,
            "An enforcing CSP is present; review its directives for application-specific needs.",
            "Keep the policy under review as application resources change.",
        )
    ]


def _check_hsts(headers: Mapping[str, str], final_url: str) -> list[Finding]:
    value = headers.get("strict-transport-security")
    if not final_url.lower().startswith("https://"):
        return [
            _finding(
                "HSTS_NOT_APPLICABLE",
                "HSTS not evaluated over HTTP",
                Severity.INFO,
                0,
                "Browsers ignore HSTS delivered over HTTP.",
                "Serve the site over HTTPS and evaluate HSTS on its HTTPS response.",
            )
        ]
    if not value:
        return [
            _finding(
                "HSTS_MISSING",
                "Strict-Transport-Security missing",
                Severity.HIGH,
                15,
                "HTTPS visitors are not instructed to prefer future secure connections.",
                f"Set Strict-Transport-Security with max-age of at least "
                f"{_HSTS_MIN_SECONDS} seconds after testing.",
            )
        ]
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match or int(match.group(1)) == 0:
        return [
            _finding(
                "HSTS_DISABLED",
                "HSTS is disabled or invalid",
                Severity.HIGH,
                12,
                "The HSTS max-age is absent, invalid, or zero.",
                "Set a positive max-age after testing HTTPS across the site.",
                value,
            )
        ]
    if int(match.group(1)) < _HSTS_MIN_SECONDS:
        return [
            _finding(
                "HSTS_SHORT_MAX_AGE",
                "HSTS max-age is short",
                Severity.MEDIUM,
                6,
                f"The max-age is below the recommended {_HSTS_MIN_SECONDS} seconds.",
                "Increase max-age gradually after validating HTTPS operations.",
                value,
            )
        ]
    return [
        _finding(
            "HSTS_OK",
            "Strict-Transport-Security present",
            Severity.INFO,
            0,
            "HSTS has a substantial max-age.",
            "Consider includeSubDomains only when every subdomain supports HTTPS.",
            value,
        )
    ]


def _check_xcto(headers: Mapping[str, str]) -> list[Finding]:
    value = headers.get("x-content-type-options")
    if value and value.strip().lower() == "nosniff":
        return [
            _finding(
                "XCTO_OK",
                "X-Content-Type-Options present",
                Severity.INFO,
                0,
                "The response requests strict MIME-type handling.",
                "Keep this header on relevant responses.",
                value,
            )
        ]
    return [
        _finding(
            "XCTO_MISSING_OR_WEAK",
            "X-Content-Type-Options missing or weak",
            Severity.MEDIUM,
            8,
            "Browsers may MIME-sniff a response in some contexts.",
            "Send X-Content-Type-Options: nosniff.",
            value,
        )
    ]


def _check_xfo(headers: Mapping[str, str]) -> list[Finding]:
    value = headers.get("x-frame-options")
    if value and value.strip().lower() in {"deny", "sameorigin"}:
        return [
            _finding(
                "XFO_OK",
                "X-Frame-Options present",
                Severity.INFO,
                0,
                "The response sets a recognized frame-embedding restriction.",
                "Also use CSP frame-ancestors for modern, flexible framing control.",
                value,
            )
        ]
    if value:
        return [
            _finding(
                "XFO_WEAK",
                "X-Frame-Options has an unsupported value",
                Severity.MEDIUM,
                7,
                "Browsers may ignore this framing directive.",
                "Use DENY or SAMEORIGIN, and set CSP frame-ancestors where appropriate.",
                value,
            )
        ]
    return [
        _finding(
            "XFO_MISSING",
            "X-Frame-Options missing",
            Severity.MEDIUM,
            8,
            "The response has no legacy anti-clickjacking header.",
            "Use X-Frame-Options: DENY or SAMEORIGIN; CSP frame-ancestors is the "
            "modern complement.",
        )
    ]


def _policy_check(
    headers: Mapping[str, str],
    header: str,
    code: str,
    title: str,
    deduction: int,
    remediation: str,
    weak_values: set[str] | None = None,
) -> list[Finding]:
    value = headers.get(header)
    if not value:
        return [
            _finding(
                f"{code}_MISSING",
                f"{title} missing",
                Severity.LOW,
                deduction,
                f"The response does not declare {title}.",
                remediation,
            )
        ]
    if weak_values and value.strip().lower() in weak_values:
        return [
            _finding(
                f"{code}_WEAK",
                f"{title} is permissive",
                Severity.LOW,
                deduction,
                f"The configured {title} value is permissive.",
                remediation,
                value,
            )
        ]
    return [
        _finding(
            f"{code}_OK",
            f"{title} present",
            Severity.INFO,
            0,
            f"The response declares {title}.",
            "Review this policy as application requirements change.",
            value,
        )
    ]


def _check_referrer_policy(headers: Mapping[str, str]) -> list[Finding]:
    return _policy_check(
        headers,
        "referrer-policy",
        "REFERRER_POLICY",
        "Referrer-Policy",
        5,
        "Use strict-origin-when-cross-origin or a stricter policy.",
        {"unsafe-url", "no-referrer-when-downgrade"},
    )


def _check_permissions_policy(headers: Mapping[str, str]) -> list[Finding]:
    value = headers.get("permissions-policy")
    if not value:
        return _policy_check(
            headers,
            "permissions-policy",
            "PERMISSIONS_POLICY",
            "Permissions-Policy",
            4,
            "Explicitly disable unneeded browser features, for example geolocation=().",
        )
    if "=*" in value.replace(" ", ""):
        return [
            _finding(
                "PERMISSIONS_POLICY_WILDCARD",
                "Permissions-Policy delegates to all origins",
                Severity.LOW,
                4,
                "One or more features are allowed for every origin.",
                "Limit each feature to self or named, trusted origins.",
                value,
            )
        ]
    return [
        _finding(
            "PERMISSIONS_POLICY_OK",
            "Permissions-Policy present",
            Severity.INFO,
            0,
            "The response declares a Permissions-Policy.",
            "Review delegated features as application requirements change.",
            value,
        )
    ]


def _check_coop(headers: Mapping[str, str]) -> list[Finding]:
    return _policy_check(
        headers,
        "cross-origin-opener-policy",
        "COOP",
        "Cross-Origin-Opener-Policy",
        4,
        "Use same-origin when compatible with the application.",
        {"unsafe-none"},
    )


def _check_corp(headers: Mapping[str, str]) -> list[Finding]:
    return _policy_check(
        headers,
        "cross-origin-resource-policy",
        "CORP",
        "Cross-Origin-Resource-Policy",
        4,
        "Use same-origin or same-site where resource sharing permits.",
        {"cross-origin"},
    )


def _check_coep(headers: Mapping[str, str]) -> list[Finding]:
    return _policy_check(
        headers,
        "cross-origin-embedder-policy",
        "COEP",
        "Cross-Origin-Embedder-Policy",
        3,
        "Consider require-corp or credentialless after testing third-party resource compatibility.",
        {"unsafe-none"},
    )


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"
