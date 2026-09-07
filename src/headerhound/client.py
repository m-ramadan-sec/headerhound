"""Bounded, defensive HTTP retrieval for HeaderHound."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx


class FetchError(RuntimeError):
    """A user-facing failure to retrieve a target."""


@dataclass(frozen=True)
class FetchedResponse:
    final_url: str
    status_code: int
    headers: dict[str, str]
    redirects: tuple[str, ...]


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
        self._last_request = 0.0

    def fetch(self, url: str) -> FetchedResponse:
        self._wait_for_interval()
        try:
            with httpx.Client(
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_tls,
                trust_env=False,
                headers={
                    "User-Agent": "HeaderHound/0.1.0 (+https://github.com/m-ramadan-sec/headerhound)",
                    "Accept": "*/*",
                },
            ) as client:
                response = client.get(url)
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
            final_url=str(response.url),
            status_code=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            redirects=tuple(str(item.url) for item in response.history),
        )

    def _wait_for_interval(self) -> None:
        remaining = self.min_interval - (time.monotonic() - self._last_request)
        if remaining > 0:
            time.sleep(remaining)
