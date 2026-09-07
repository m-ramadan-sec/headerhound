import pytest

from headerhound.safety import TargetError, ensure_public_target, normalize_url


def test_normalize_url_strips_fragment() -> None:
    assert normalize_url("HTTPS://example.com/path?q=1#section") == "https://example.com/path?q=1"


@pytest.mark.parametrize(
    "url",
    ["example.com", "ftp://example.com", "https:///missing-host", "https://user:pass@example.com"],
)
def test_normalize_url_rejects_unsafe_forms(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_url(url)


def test_private_targets_require_opt_in() -> None:
    with pytest.raises(TargetError, match="non-public"):
        ensure_public_target("http://127.0.0.1/")


def test_allow_private_bypasses_resolution() -> None:
    ensure_public_target("http://127.0.0.1/", allow_private=True)
