"""Bounded, defensive HTTP retrieval for HeaderHound."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .safety import ensure_public_target


class FetchError(RuntimeError):
    """A user-facing failure to retrieve a target."""


@dataclass(frozen=True)
class FetchedResponse:
    final_url: str
    status_code: int
    headers: dict[str, str]
    redirects: tuple[str, ...]
    cookies: tuple[str, ...] = ()
    initial_url: str | None = None


class ScanClient:
    """Fetch one resource with explicit bounds and a small request interval."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_redirects: int = 5,
        follow_redirects: bool = True,
        verify_tls: bool = True,
        min_interval: float = 0.2,
        allow_private: bool = False,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")
        if min_interval < 0:
            raise ValueError("min_interval cannot be negative")
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.follow_redirects = follow_redirects
        self.verify_tls = verify_tls
        self.min_interval = min_interval
        self.allow_private = allow_private
        self._last_request = 0.0

    def fetch(self, url: str) -> FetchedResponse:
        self._wait_for_interval()
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_tls,
                trust_env=False,
                headers={
                    "User-Agent": "HeaderHound/0.2.0 (+https://github.com/m-ramadan-sec/headerhound)",
                    "Accept": "*/*",
                },
            ) as client:
                current_url = url
                history: list[str] = []
                while True:
                    ensure_public_target(current_url, allow_private=self.allow_private)
                    with client.stream("GET", current_url) as response:
                        final_url = str(response.url)
                        status_code = response.status_code
                        response_headers = response.headers
                        response_cookies = tuple(response.headers.get_list("set-cookie"))
                        location = response.headers.get("location")
                    if (
                        not self.follow_redirects
                        or not location
                        or status_code
                        not in {
                            301,
                            302,
                            303,
                            307,
                            308,
                        }
                    ):
                        break
                    if len(history) >= self.max_redirects:
                        raise FetchError(f"Too many redirects (limit: {self.max_redirects}).")
                    history.append(final_url)
                    current_url = urljoin(final_url, location)
        except httpx.TooManyRedirects as exc:
            raise FetchError(f"Too many redirects (limit: {self.max_redirects}).") from exc
        except httpx.TimeoutException as exc:
            raise FetchError(f"Request timed out after {self.timeout:g} seconds.") from exc
        except httpx.ConnectError as exc:
            raise FetchError(f"Could not connect to target: {exc}") from exc
        except httpx.HTTPError as exc:
            raise FetchError(f"HTTP request failed: {exc}") from exc

        self._last_request = time.monotonic()
        return FetchedResponse(
            final_url=final_url,
            status_code=status_code,
            headers={
                key.lower(): value
                for key, value in response_headers.items()
                if key.lower() != "set-cookie"
            },
            redirects=tuple(history),
            cookies=response_cookies,
            initial_url=url,
        )

    def _wait_for_interval(self) -> None:
        remaining = self.min_interval - (time.monotonic() - self._last_request)
        if remaining > 0:
            time.sleep(remaining)
