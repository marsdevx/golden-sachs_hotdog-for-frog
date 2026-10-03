.PHONY: test lint up down logs

test:
	uv run pytest

lint:
	uv run ruff check .

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f
