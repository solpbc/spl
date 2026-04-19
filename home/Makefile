# home — python tunnel module
# Embeds in solstone. Opens listen WS to spl-relay, terminates TLS inside the tunnel.

.PHONY: install test ci format clean dev lint typecheck

install:
	uv sync

test:
	uv run pytest

ci: format-check lint typecheck test

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

format-check:
	uv run ruff format --check src/ tests/

lint:
	uv run ruff check src/ tests/

typecheck:
	uv run mypy src/

dev:
	uv run python -m spl.tunnel

clean:
	rm -rf .venv/ build/ dist/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
