from __future__ import annotations

import json

from headerhound.cli import main
from headerhound.client import FetchedResponse, ScanClient


def test_cli_outputs_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr("headerhound.cli.ensure_public_target", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        ScanClient,
        "fetch",
        lambda self, url: FetchedResponse(
            final_url=url,
            status_code=200,
            headers={"content-security-policy": "default-src 'self'"},
            redirects=(),
        ),
    )
    assert main(["https://example.test", "--format", "json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["target"] == "https://example.test/"


def test_cli_returns_error_for_bad_url(capsys) -> None:
    assert main(["not-a-url", "--format", "json"]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_can_fail_an_automation_threshold(monkeypatch, capsys) -> None:
    monkeypatch.setattr("headerhound.cli.ensure_public_target", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        ScanClient,
        "fetch",
        lambda self, url: FetchedResponse(final_url=url, status_code=200, headers={}, redirects=()),
    )
    assert main(["https://example.test", "--fail-under", "90"]) == 1
    assert "Security score:" in capsys.readouterr().out
