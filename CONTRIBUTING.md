# Contributing to AI Runtime Monitor

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Quick Setup

```bash
git clone https://github.com/rajan-cforge/ai-runtime-monitor.git
cd ai-runtime-monitor
make dev       # Install with dev dependencies
make test      # Run tests
make lint      # Check code style
```

## Development Workflow

We use a trunk-based workflow with short-lived feature branches:

1. **Fork** the repo and clone your fork
2. **Branch** from `main`: `git checkout -b feat/my-feature`
3. **Code** your changes
4. **Test**: `make test` — all tests must pass
5. **Lint**: `make lint` — code must be clean
6. **Commit** using [Conventional Commits](#commit-messages)
7. **Push** and open a PR against `main`

## Branch Naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation only |
| `refactor/` | Code restructuring |
| `test/` | Test additions/fixes |
| `chore/` | Tooling, CI, dependencies |

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(dashboard): add session replay controls
fix(monitor): resolve duplicate process rows in detail view
docs: update installation instructions
test(api): add browser session endpoint tests
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

Breaking changes: add `BREAKING CHANGE:` in the commit footer or `!` after the type.

## Code Style

- **Formatter/Linter:** [Ruff](https://docs.astral.sh/ruff/) (configured in `pyproject.toml`)
- **Line length:** 120 characters
- **Python:** 3.9+ compatible
- Run `make format` to auto-fix style issues

## Testing

```bash
make test                          # Full suite
pytest tests/test_api.py -v       # Specific file
pytest -k "test_browser"          # By keyword
pytest --cov=claude_monitoring    # With coverage
```

All new features and bug fixes should include tests.

## Architecture Overview

```
src/claude_monitoring/
├── monitor.py        # Backend: HTTP server, SQLite, scanners (network/process/filesystem)
├── watch.py          # mitmproxy addon for deep API traffic interception
├── dashboard.html    # Frontend: single-file inline HTML/CSS/JS dashboard
└── watch_dashboard.html  # Watch-mode dashboard
```

**Key design decisions:**
- Single-file dashboard (inline HTML/CSS/JS) — served directly from Python via `importlib.resources`
- SQLite with WAL mode for concurrent read/write from scanner threads
- Zero external runtime dependencies beyond `psutil` and `watchdog`

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Update tests for any behavior changes
- Don't break backward compatibility without discussion
- The CI must pass before merge (lint + test matrix)

## Reporting Bugs

Use the [Bug Report](https://github.com/rajan-cforge/ai-runtime-monitor/issues/new?template=bug_report.yml) issue template.

## Requesting Features

Use the [Feature Request](https://github.com/rajan-cforge/ai-runtime-monitor/issues/new?template=feature_request.yml) issue template.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
