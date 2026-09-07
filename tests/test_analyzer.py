from headerhound.analyzer import assess


def report(headers: dict[str, str], url: str = "https://example.test/"):
    return assess(target=url, final_url=url, status_code=200, headers=headers, redirects=())


def codes(headers: dict[str, str], url: str = "https://example.test/") -> set[str]:
    return {finding.code for finding in report(headers, url).findings}


def test_strong_headers_receive_top_score() -> None:
    result = report(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
    )
    assert result.score == 100
    assert result.grade == "A"


def test_missing_headers_are_scored_and_explained() -> None:
    result = report({})
    assert result.score < 50
    assert "CSP_MISSING" in {finding.code for finding in result.findings}
    assert "HSTS_MISSING" in {finding.code for finding in result.findings}


def test_weak_csp_is_flagged() -> None:
    finding_codes = codes({"content-security-policy": "script-src * 'unsafe-inline' 'unsafe-eval'"})
    assert {
        "CSP_NO_DEFAULT_SRC",
        "CSP_UNSAFE_INLINE",
        "CSP_UNSAFE_EVAL",
        "CSP_WILDCARD",
    } <= finding_codes


def test_hsts_is_not_scored_on_http() -> None:
    result = report({}, "http://example.test/")
    assert "HSTS_NOT_APPLICABLE" in {finding.code for finding in result.findings}
    assert "HSTS_MISSING" not in {finding.code for finding in result.findings}


def test_permissive_policies_are_flagged() -> None:
    finding_codes = codes(
        {
            "referrer-policy": "unsafe-url",
            "permissions-policy": "geolocation=*",
            "cross-origin-opener-policy": "unsafe-none",
            "cross-origin-resource-policy": "cross-origin",
            "cross-origin-embedder-policy": "unsafe-none",
        }
    )
    assert {
        "REFERRER_POLICY_WEAK",
        "PERMISSIONS_POLICY_WILDCARD",
        "COOP_WEAK",
        "CORP_WEAK",
        "COEP_WEAK",
    } <= finding_codes
