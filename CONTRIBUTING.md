# Contributing to HeaderHound

Thanks for improving a defensive security tool. Please keep changes narrowly scoped, documented, and testable.

## Development setup

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest
```

## Pull requests

1. Open an issue first for substantial changes so the scope can be discussed.
2. Add or update tests for behavior changes.
3. Keep public findings explainable and avoid presenting heuristics as certainty.
4. Do not add active exploitation, broad crawling, credential collection, evasion, or destructive features.
5. Ensure CI passes and complete the pull request template.

## Reporting quality

New checks should state the browser/security rationale, include a conservative remediation, avoid false certainty, and preserve JSON compatibility. If a check changes scoring, document that in the changelog.
