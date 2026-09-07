from headerhound.analyzer import assess


def _report(
    headers: dict[str, str], cookies: tuple[str, ...] = (), url: str = "https://app.example.test/"
):
    return assess(
        target=url, final_url=url, status_code=200, headers=headers, redirects=(), cookies=cookies
    )


def _codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


def test_cookie_values_are_redacted_and_weak_session_flags_are_found() -> None:
    result = _report({}, ("sessionid=super-secret; SameSite=None",))
    assert {
        "COOKIE_SECURE_MISSING",
        "COOKIE_HTTPONLY_MISSING",
        "COOKIE_SAMESITE_NONE_INSECURE",
    } <= _codes(result)
    payload = result.to_dict()
    assert "super-secret" not in str(payload)
    assert payload["cookies"][0]["name"] == "sessionid"


def test_cookie_metadata_and_domain_lifetime_checks() -> None:
    result = _report(
        {}, ("auth=secret; Secure; HttpOnly; SameSite=Lax; Domain=example.test; Max-Age=40000000",)
    )
    assert {"COOKIE_BROAD_DOMAIN", "COOKIE_LONG_LIFETIME"} <= _codes(result)


def test_malformed_cookie_is_ignored_and_sensitive_headers_are_redacted() -> None:
    result = _report({"Authorization": "Bearer should-not-leak"}, ("not-a-cookie",))
    assert result.cookies == ()
    assert result.to_dict()["headers"]["authorization"] == "[redacted]"


def test_cors_findings_are_contextual_and_structured() -> None:
    result = _report(
        {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "*",
        }
    )
    assert {"CORS_WILDCARD_ORIGIN", "CORS_WILDCARD_CREDENTIALS", "CORS_WILDCARD_METHODS"} <= _codes(
        result
    )
    assert result.to_dict()["cors"]["allow_origin"] == "*"


def test_transport_disclosure_cache_and_csp_hardening() -> None:
    result = assess(
        target="http://app.example.test/",
        initial_url="http://app.example.test/",
        final_url="https://app.example.test/",
        status_code=200,
        redirects=("http://app.example.test/",),
        headers={
            "strict-transport-security": "max-age=31536000; preload",
            "server": "nginx/1.0",
            "cache-control": "public",
            "content-security-policy": "script-src http: data:",
        },
        cookies=("session=secret; Secure; HttpOnly; SameSite=Lax",),
    )
    assert {
        "HTTPS_REDIRECT",
        "HSTS_NO_SUBDOMAINS",
        "HSTS_PRELOAD",
        "TECHNOLOGY_DISCLOSURE",
        "CACHE_PUBLIC_SENSITIVE",
        "CSP_RISKY_SCRIPT_SOURCE",
    } <= _codes(result)
    assert result.to_dict()["transport"]["redirected_to_https"] is True


def test_csp_uses_first_duplicate_directive_and_accepts_mixed_case() -> None:
    result = _report(
        {
            "content-security-policy": "ScRiPt-SrC 'self'; script-src *; object-src 'none'; base-uri 'self'"
        }
    )
    assert "CSP_WILDCARD" not in _codes(result)
