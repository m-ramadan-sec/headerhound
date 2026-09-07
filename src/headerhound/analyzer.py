"""Passive response-header, cookie, CORS, cache, and transport posture checks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from .models import CookieMetadata, Finding, ScanResult, Severity

_HSTS_MIN_SECONDS = 15_552_000
_LONG_COOKIE_AGE = 34_560_000
_SENSITIVE_COOKIE_NAME = re.compile(r"(?:session|sess|auth|token|sid|jwt)", re.IGNORECASE)


def assess(
    *,
    target: str,
    final_url: str,
    status_code: int,
    headers: Mapping[str, str],
    redirects: tuple[str, ...],
    cookies: tuple[str, ...] = (),
    initial_url: str | None = None,
) -> ScanResult:
    """Assess one response passively; cookie values are intentionally never retained."""
    sensitive_headers = {
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
    normalized = {
        key.lower(): "[redacted]" if key.lower() in sensitive_headers else value
        for key, value in headers.items()
        if key.lower() != "set-cookie"
    }
    cookie_metadata = tuple(
        cookie for value in cookies if (cookie := _parse_cookie(value)) is not None
    )
    initial = initial_url or target
    findings = (
        *_check_csp(normalized),
        *_check_transport(normalized, initial, final_url, redirects),
        *_check_xcto(normalized),
        *_check_xfo(normalized),
        *_check_policy(
            normalized,
            "referrer-policy",
            "REFERRER_POLICY",
            "Referrer-Policy",
            5,
            "Use strict-origin-when-cross-origin or a stricter policy.",
            {"unsafe-url", "no-referrer-when-downgrade"},
        ),
        *_check_permissions(normalized),
        *_check_policy(
            normalized,
            "cross-origin-opener-policy",
            "COOP",
            "Cross-Origin-Opener-Policy",
            4,
            "Use same-origin when compatible with the application.",
            {"unsafe-none"},
        ),
        *_check_policy(
            normalized,
            "cross-origin-resource-policy",
            "CORP",
            "Cross-Origin-Resource-Policy",
            4,
            "Use same-origin or same-site where resource sharing permits.",
            {"cross-origin"},
        ),
        *_check_policy(
            normalized,
            "cross-origin-embedder-policy",
            "COEP",
            "Cross-Origin-Embedder-Policy",
            3,
            "Consider require-corp or credentialless after testing third-party resource compatibility.",
            {"unsafe-none"},
        ),
        *_check_cookies(cookie_metadata, final_url),
        *_check_cors(normalized),
        *_check_disclosure(normalized),
        *_check_cache(normalized, cookie_metadata),
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
        cookies=cookie_metadata,
        cors=_cors_metadata(normalized),
        transport=_transport_metadata(normalized, initial, final_url, redirects),
        metadata={
            "schema_version": "1.0",
            "analysis_mode": "passive",
            "header_count": len(normalized),
            "cookie_values_redacted": True,
        },
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
    return Finding(
        code, title, severity, deduction, description, remediation, _safe_evidence(evidence)
    )


def _safe_evidence(value: str | None) -> str | None:
    if value is None:
        return None
    return "".join(char if char.isprintable() and char not in "\r\n" else "?" for char in value)[
        :200
    ]


def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for item in value.split(";"):
        parts = item.strip().split()
        if parts and parts[0].lower() not in directives:
            directives[parts[0].lower()] = [part.lower() for part in parts[1:]]
    return directives


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
    directives = _parse_csp(value)
    sources = directives.get("script-src", directives.get("default-src", []))
    all_sources = [source for items in directives.values() for source in items]
    findings: list[Finding] = []
    if "default-src" not in directives:
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
    if "'unsafe-inline'" in all_sources:
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
    if "'unsafe-eval'" in all_sources:
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
    if "*" in all_sources:
        findings.append(
            _finding(
                "CSP_WILDCARD",
                "CSP allows wildcard script sources",
                Severity.MEDIUM,
                7,
                "A wildcard script/default source allows content from arbitrary origins.",
                "Replace * with the specific origins the application needs.",
                value,
            )
        )
    if "http:" in sources or "data:" in sources:
        findings.append(
            _finding(
                "CSP_RISKY_SCRIPT_SOURCE",
                "CSP permits broad script schemes",
                Severity.MEDIUM,
                6,
                "The script policy permits an HTTP or data scheme, which expands executable-source trust.",
                "Restrict script-src to HTTPS origins and nonce/hash-based inline scripts.",
                value,
            )
        )
    if "object-src" not in directives:
        findings.append(
            _finding(
                "CSP_NO_OBJECT_SRC",
                "CSP does not define object-src",
                Severity.INFO,
                0,
                "This is a defense-in-depth recommendation, not proof of an insecure policy.",
                "Consider object-src 'none' when plugins are not required.",
            )
        )
    if "base-uri" not in directives:
        findings.append(
            _finding(
                "CSP_NO_BASE_URI",
                "CSP does not define base-uri",
                Severity.INFO,
                0,
                "This is a defense-in-depth recommendation, not proof of an insecure policy.",
                "Consider base-uri 'self' or 'none' when compatible.",
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


def _check_transport(
    headers: Mapping[str, str], initial_url: str, final_url: str, redirects: tuple[str, ...]
) -> list[Finding]:
    initial_https = initial_url.lower().startswith("https://")
    final_https = final_url.lower().startswith("https://")
    findings: list[Finding] = []
    if not final_https:
        findings.append(
            _finding(
                "HTTPS_NOT_ENFORCED",
                "Final response is not HTTPS",
                Severity.HIGH,
                15,
                "The scan ended on HTTP, so transport confidentiality is not enforced.",
                "Serve the target over HTTPS and redirect HTTP requests to HTTPS.",
            )
        )
    elif not initial_https:
        findings.append(
            _finding(
                "HTTPS_REDIRECT",
                "HTTP redirects to HTTPS",
                Severity.INFO,
                0,
                "The initial HTTP target ultimately reached HTTPS.",
                "Keep redirects in place and validate all hostnames over HTTPS.",
            )
        )
    if initial_https and any(url.lower().startswith("http://") for url in redirects):
        findings.append(
            _finding(
                "HTTPS_DOWNGRADE_REDIRECT",
                "HTTPS redirect chain includes HTTP",
                Severity.HIGH,
                12,
                "A redirect from an HTTPS entry point passed through HTTP.",
                "Keep every redirect target on HTTPS.",
            )
        )
    hsts = headers.get("strict-transport-security")
    if not final_https:
        return findings + [
            _finding(
                "HSTS_NOT_APPLICABLE",
                "HSTS not evaluated over HTTP",
                Severity.INFO,
                0,
                "Browsers ignore HSTS delivered over HTTP.",
                "Evaluate HSTS on the HTTPS response.",
            )
        ]
    if not hsts:
        return findings + [
            _finding(
                "HSTS_MISSING",
                "Strict-Transport-Security missing",
                Severity.HIGH,
                15,
                "HTTPS visitors are not instructed to prefer future secure connections.",
                f"Set Strict-Transport-Security with max-age of at least {_HSTS_MIN_SECONDS} seconds after testing.",
            )
        ]
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if not match or int(match.group(1)) == 0:
        findings.append(
            _finding(
                "HSTS_DISABLED",
                "HSTS is disabled or invalid",
                Severity.HIGH,
                12,
                "The HSTS max-age is absent, invalid, or zero.",
                "Set a positive max-age after testing HTTPS across the site.",
                hsts,
            )
        )
    elif int(match.group(1)) < _HSTS_MIN_SECONDS:
        findings.append(
            _finding(
                "HSTS_SHORT_MAX_AGE",
                "HSTS max-age is short",
                Severity.MEDIUM,
                6,
                f"The max-age is below the recommended {_HSTS_MIN_SECONDS} seconds.",
                "Increase max-age gradually after validating HTTPS operations.",
                hsts,
            )
        )
    else:
        findings.append(
            _finding(
                "HSTS_OK",
                "Strict-Transport-Security present",
                Severity.INFO,
                0,
                "HSTS has a substantial max-age.",
                "Consider includeSubDomains only when every subdomain supports HTTPS.",
                hsts,
            )
        )
    if "includesubdomains" not in hsts.lower():
        findings.append(
            _finding(
                "HSTS_NO_SUBDOMAINS",
                "HSTS does not cover subdomains",
                Severity.INFO,
                0,
                "Subdomain coverage is optional and should only be enabled when every subdomain supports HTTPS.",
                "Consider includeSubDomains after verifying all subdomains.",
            )
        )
    if "preload" in hsts.lower():
        findings.append(
            _finding(
                "HSTS_PRELOAD",
                "HSTS preload token present",
                Severity.INFO,
                0,
                "The response requests preload eligibility; browser-list inclusion has separate requirements.",
                "Confirm preload-list requirements before relying on this token.",
            )
        )
    return findings


def _transport_metadata(
    headers: Mapping[str, str], initial_url: str, final_url: str, redirects: tuple[str, ...]
) -> dict[str, object]:
    hsts = headers.get("strict-transport-security", "")
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    return {
        "initial_scheme": urlsplit(initial_url).scheme.lower(),
        "final_scheme": urlsplit(final_url).scheme.lower(),
        "redirected_to_https": initial_url.lower().startswith("http://")
        and final_url.lower().startswith("https://"),
        "redirect_chain_has_http": any(url.lower().startswith("http://") for url in redirects[1:]),
        "hsts": {
            "present": bool(hsts),
            "max_age": int(match.group(1)) if match else None,
            "include_subdomains": "includesubdomains" in hsts.lower(),
            "preload": "preload" in hsts.lower(),
        },
    }


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
            "Use X-Frame-Options: DENY or SAMEORIGIN; CSP frame-ancestors is the modern complement.",
        )
    ]


def _check_policy(
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


def _check_permissions(headers: Mapping[str, str]) -> list[Finding]:
    value = headers.get("permissions-policy")
    if value and "=*" in value.replace(" ", ""):
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
    return _check_policy(
        headers,
        "permissions-policy",
        "PERMISSIONS_POLICY",
        "Permissions-Policy",
        4,
        "Explicitly disable unneeded browser features, for example geolocation=().",
    )


def _parse_cookie(value: str) -> CookieMetadata | None:
    first, *attributes = value.split(";")
    if "=" not in first:
        return None
    name = first.split("=", 1)[0].strip()
    if not name or any(not character.isprintable() or character in "\r\n" for character in name):
        return None
    parsed: dict[str, str | bool] = {}
    for attribute in attributes:
        key, separator, raw_value = attribute.strip().partition("=")
        if key:
            parsed[key.lower()] = raw_value.strip() if separator else True
    try:
        max_age = int(str(parsed["max-age"])) if "max-age" in parsed else None
    except ValueError:
        max_age = None
    return CookieMetadata(
        name=name,
        secure=bool(parsed.get("secure")),
        httponly=bool(parsed.get("httponly")),
        samesite=str(parsed["samesite"]).lower() if "samesite" in parsed else None,
        domain=str(parsed["domain"]).lstrip(".").lower() if "domain" in parsed else None,
        path=str(parsed["path"]) if "path" in parsed else None,
        max_age=max_age,
        expires="expires" in parsed,
    )


def _check_cookies(cookies: tuple[CookieMetadata, ...], final_url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = (urlsplit(final_url).hostname or "").lower()
    for cookie in cookies:
        sensitive = bool(_SENSITIVE_COOKIE_NAME.search(cookie.name)) or (
            cookie.max_age is None and not cookie.expires
        )
        label = f"Cookie '{cookie.name}'"
        if not cookie.secure:
            findings.append(
                _finding(
                    "COOKIE_SECURE_MISSING",
                    f"{label} missing Secure",
                    Severity.HIGH if sensitive else Severity.LOW,
                    10 if sensitive else 2,
                    "This cookie can be sent over an unencrypted HTTP request if one is reachable.",
                    "Set the Secure attribute; serve the application only over HTTPS.",
                )
            )
        if sensitive and not cookie.httponly:
            findings.append(
                _finding(
                    "COOKIE_HTTPONLY_MISSING",
                    f"{label} missing HttpOnly",
                    Severity.MEDIUM,
                    7,
                    "Scripts can read this session-like cookie if XSS occurs.",
                    "Set HttpOnly unless client-side JavaScript must read this cookie.",
                )
            )
        if not cookie.samesite:
            findings.append(
                _finding(
                    "COOKIE_SAMESITE_MISSING",
                    f"{label} missing SameSite",
                    Severity.MEDIUM if sensitive else Severity.LOW,
                    5 if sensitive else 1,
                    "The cookie has no explicit cross-site sending policy.",
                    "Set SameSite=Lax or Strict unless a cross-site flow requires None.",
                )
            )
        elif cookie.samesite == "none" and not cookie.secure:
            findings.append(
                _finding(
                    "COOKIE_SAMESITE_NONE_INSECURE",
                    f"{label} uses SameSite=None without Secure",
                    Severity.HIGH,
                    10,
                    "Modern browsers require Secure for SameSite=None; the configuration weakens transport safety and may be rejected.",
                    "Set Secure or use a more restrictive SameSite value.",
                )
            )
        if cookie.domain and host.endswith(f".{cookie.domain}") and cookie.domain != host:
            findings.append(
                _finding(
                    "COOKIE_BROAD_DOMAIN",
                    f"{label} is scoped to a parent domain",
                    Severity.LOW,
                    2,
                    "The cookie is available to sibling subdomains under its Domain attribute; this may be intentional.",
                    "Omit Domain to make the cookie host-only unless subdomain sharing is required.",
                    cookie.domain,
                )
            )
        if cookie.max_age is not None and cookie.max_age > _LONG_COOKIE_AGE:
            findings.append(
                _finding(
                    "COOKIE_LONG_LIFETIME",
                    f"{label} has a long lifetime",
                    Severity.LOW,
                    2,
                    "The cookie persists for more than 400 days; persistence should match the account/session risk.",
                    "Use the shortest practical Max-Age and rotate credentials as appropriate.",
                )
            )
    return findings


def _cors_metadata(headers: Mapping[str, str]) -> dict[str, object]:
    def split(name: str) -> list[str]:
        return [item.strip() for item in headers.get(name, "").split(",") if item.strip()]

    return {
        "allow_origin": headers.get("access-control-allow-origin"),
        "allow_credentials": headers.get("access-control-allow-credentials", "").lower() == "true",
        "allow_methods": split("access-control-allow-methods"),
        "allow_headers": split("access-control-allow-headers"),
        "vary_origin": "origin"
        in [item.strip().lower() for item in headers.get("vary", "").split(",")],
    }


def _check_cors(headers: Mapping[str, str]) -> list[Finding]:
    cors = _cors_metadata(headers)
    origin = cors["allow_origin"]
    findings: list[Finding] = []
    if origin == "*":
        severity, deduction = (
            (Severity.HIGH, 12) if cors["allow_credentials"] else (Severity.LOW, 3)
        )
        findings.append(
            _finding(
                "CORS_WILDCARD_ORIGIN",
                "CORS allows every origin",
                severity,
                deduction,
                "Wildcard CORS is contextual: it is often appropriate for public resources, but is risky for data intended for a restricted audience.",
                "Restrict Access-Control-Allow-Origin to trusted origins for non-public resources.",
                "*",
            )
        )
        if cors["allow_credentials"]:
            findings.append(
                _finding(
                    "CORS_WILDCARD_CREDENTIALS",
                    "CORS combines wildcard origin and credentials",
                    Severity.HIGH,
                    10,
                    "Browsers reject this combination, but it signals a contradictory and overly broad policy.",
                    "Use explicit trusted origins when allowing credentials.",
                )
            )
    if "*" in cors["allow_methods"]:
        findings.append(
            _finding(
                "CORS_WILDCARD_METHODS",
                "CORS allows all methods",
                Severity.LOW,
                2,
                "A wildcard method policy is broad and should be justified by the resource's intended audience.",
                "Allow only the methods the endpoint requires.",
            )
        )
    if "*" in cors["allow_headers"]:
        findings.append(
            _finding(
                "CORS_WILDCARD_HEADERS",
                "CORS allows all request headers",
                Severity.LOW,
                2,
                "A wildcard header policy is broad and should be justified by the resource's intended audience.",
                "Allow only the request headers the endpoint requires.",
            )
        )
    if origin and origin != "*" and cors["allow_credentials"]:
        findings.append(
            _finding(
                "CORS_CREDENTIALS_ENABLED",
                "CORS permits credentialed cross-origin requests",
                Severity.INFO,
                0,
                "This may be required by a trusted frontend; passive analysis cannot determine whether the allowed origin is appropriate.",
                "Review the allowed origin and credential requirement in application context.",
                str(origin),
            )
        )
    return findings


def _check_disclosure(headers: Mapping[str, str]) -> list[Finding]:
    names = {
        "server": "Server",
        "x-powered-by": "X-Powered-By",
        "x-aspnet-version": "X-AspNet-Version",
        "x-aspnetmvc-version": "X-AspNetMvc-Version",
    }
    return [
        _finding(
            "TECHNOLOGY_DISCLOSURE",
            f"{title} discloses technology details",
            Severity.LOW,
            2,
            "Technology headers are usually a hardening concern rather than proof of a vulnerability.",
            "Remove unnecessary version or framework disclosure where operationally practical.",
            headers[name],
        )
        for name, title in names.items()
        if headers.get(name)
    ]


def _check_cache(headers: Mapping[str, str], cookies: tuple[CookieMetadata, ...]) -> list[Finding]:
    cache_control = headers.get("cache-control", "").lower()
    pragma = headers.get("pragma", "").lower()
    sensitive = any(_SENSITIVE_COOKIE_NAME.search(cookie.name) for cookie in cookies)
    if not sensitive:
        return []
    if "public" in cache_control:
        return [
            _finding(
                "CACHE_PUBLIC_SENSITIVE",
                "Sensitive response permits public caching",
                Severity.MEDIUM,
                7,
                "A response setting a session-like cookie also declares public caching. This is a conservative signal, not proof that sensitive content is present.",
                "Use Cache-Control: private, no-store for authenticated or sensitive responses.",
                headers.get("cache-control"),
            )
        ]
    if not cache_control and "no-cache" not in pragma:
        return [
            _finding(
                "CACHE_POLICY_MISSING",
                "No cache policy on a session-like response",
                Severity.LOW,
                3,
                "The response sets a session-like cookie but provides no cache directive; content sensitivity cannot be inferred from headers alone.",
                "Use an explicit private or no-store policy for sensitive responses.",
            )
        ]
    return []


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
