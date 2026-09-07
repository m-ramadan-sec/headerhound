import json

from headerhound.analyzer import assess
from headerhound.output import render_json, render_table


def _result():
    return assess(
        target="https://example.test/",
        final_url="https://example.test/",
        status_code=200,
        headers={},
        redirects=(),
    )


def test_json_report_is_machine_readable() -> None:
    payload = json.loads(render_json(_result()))
    assert payload["score"] < 100
    assert payload["final_url"] == "https://example.test/"


def test_table_report_includes_key_context() -> None:
    output = render_table(_result())
    assert "Security score:" in output
    assert "Content-Security-Policy missing" in output
