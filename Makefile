.PHONY: install dev test lint format clean start stop status help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install ai-runtime-monitor (one-click setup)
	pip install -e .

dev: ## Install with dev dependencies (linting, testing)
	pip install -e ".[dev]"

start: ## Start the monitor + dashboard
	ai-monitor --start

stop: ## Stop the monitor
	@lsof -ti :9081 2>/dev/null | xargs kill -9 2>/dev/null && echo "Stopped." || echo "Not running."

status: ## Check if the monitor is running
	@curl -sf http://localhost:9081/api/stats > /dev/null 2>&1 && echo "Running on http://localhost:9081" || echo "Not running."

test: ## Run the test suite
	pytest

lint: ## Run linter checks
	ruff check src/ tests/
	ruff format --check src/ tests/

format: ## Auto-format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .coverage htmlcov coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
