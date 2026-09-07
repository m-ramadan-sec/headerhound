"""Human-readable and JSON report rendering."""

from __future__ import annotations

import json

from .models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def render_table(result: ScanResult) -> str:
    """Render a dependency-free table suitable for CI logs and terminals."""
    rows = [("Severity", "Finding", "Details")]
    for finding in result.findings:
        detail = finding.description
        if finding.evidence:
            detail = f"{detail} Value: {finding.evidence}"
        rows.append((finding.severity.value.upper(), finding.title, detail))

    widths = [
        max(len(_clip(row[column], 74 if column == 2 else 32)) for row in rows)
        for column in range(3)
    ]
    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [
        f"Target: {result.target}",
        f"Final URL: {result.final_url}",
        f"HTTP status: {result.status_code}",
        f"Security score: {result.score}/100 (grade {result.grade})",
    ]
    if result.redirects:
        lines.append(f"Redirects followed: {len(result.redirects)}")
    lines.extend(["", separator, _row(rows[0], widths), separator])
    lines.extend(
        _row(tuple(_clip(cell, 74 if index == 2 else 32) for index, cell in enumerate(row)), widths)
        for row in rows[1:]
    )
    lines.append(separator)
    return "\n".join(lines)


def _row(row: tuple[str, str, str], widths: list[int]) -> str:
    return (
        "|" + "|".join(f" {cell:<{width}} " for cell, width in zip(row, widths, strict=True)) + "|"
    )


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"
