.PHONY: test test-suites lint up down logs

test:
	uv run pytest

test-suites:
	uv run pytest test_suites -rxX

lint:
	uv run ruff check .

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f
