# SQLAlchemy async over one DATABASE_URL: Postgres in Compose, SQLite in tests

Audit Events, budget counters and metrics live in a relational store accessed through SQLAlchemy 2.0 async and a single `DATABASE_URL`. Docker Compose runs Postgres (the "stateless firewall instances + shared state" scaling story). Tests and local development use SQLite (`sqlite+aiosqlite`), so judges can run the whole suite with one command and no running services. We rejected JSONL plus in-memory counters (cannot scale past one instance, hard to query from the dashboard) and Redis (an extra moving part for little gain at hackathon scale).

## Consequences

- Only portable SQL: no Postgres-specific types or features unless guarded.
- Schema is created with `metadata.create_all` at startup. No migration tool.
