"""Input validation and conservative target-safety checks."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit, urlunsplit


class TargetError(ValueError):
    """Raised when a target is malformed or is not allowed by policy."""


def normalize_url(value: str) -> str:
    """Validate an absolute HTTP(S) URL and remove its non-request fragment."""
    try:
        parsed = urlsplit(value.strip())
        _validate_parts(parsed)
        # Fragments are not sent in HTTP requests and should not affect reports.
        return urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
        )
    except (TypeError, ValueError) as exc:
        raise TargetError(
            f"Invalid URL: {value!r}. Supply an absolute http:// or https:// URL."
        ) from exc


def _validate_parts(parsed: SplitResult) -> None:
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetError("Only http:// and https:// targets are supported.")
    if not parsed.netloc or not parsed.hostname:
        raise TargetError("A target URL must include a host.")
    if parsed.username or parsed.password:
        raise TargetError("Credentials in target URLs are not supported.")
    # Accessing .port validates malformed and out-of-range port values.
    _ = parsed.port


def ensure_public_target(url: str, *, allow_private: bool = False) -> None:
    """Block resolved non-global addresses unless the caller explicitly opts in.

    This reduces accidental requests to loopback, private, link-local, and reserved
    services. DNS is resolved once here, so callers scanning sensitive environments
    should use an egress-controlled network as an additional safeguard.
    """
    if allow_private:
        return
    host = urlsplit(url).hostname
    assert host is not None  # normalize_url establishes this invariant.
    try:
        addresses = {
            record[4][0] for record in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve host {host!r}: {exc}") from exc
    if not addresses:
        raise TargetError(f"Could not resolve host {host!r}.")
    non_public = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if non_public:
        raise TargetError(
            "Refusing a target that resolves to a non-public address "
            f"({', '.join(non_public)}). Use --allow-private only for systems you are "
            "authorized to scan."
        )
