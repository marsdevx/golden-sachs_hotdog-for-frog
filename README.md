# AI Control Layer

An AI firewall that sits between internal Agents, LLMs and Resources and governs every interaction against one centrally managed **Policy**. Vocabulary (Policy, Control, Mode, Preset, Stage, Check, Verdict, Decision, Finding, Agent, Owner, User, Resource, Audit Event, Upstream) is defined in [`CONTEXT.md`](CONTEXT.md).

This repository contains the **core**: the Check pipeline, the hot-reloaded Policy, Agent identity, the audit store, both transports, the admin API, a dashboard skeleton, and one reference Control (`keyword_blocklist`). The real security Controls are tickets in [`docs/backlog.md`](docs/backlog.md); adding one takes one file, see [`docs/CONTRIBUTING-controls.md`](docs/CONTRIBUTING-controls.md).

## Architecture

```text
                          policies/standard.yaml  (hot reloaded, edited by hand or by the dashboard)
                                     |
 Agent (check API mode)              v
   POST /v1/check/{stage} ---->  +---------------------------------------------+
   X-Agent-Key                   |  Firewall :8001                             |
                                 |                                             |
 Agent (proxy mode, any          |  identity --> Check --> pipeline            |
 OpenAI SDK)                     |                         Control 1 (Mode)    |
   POST /v1/chat/completions --> |                         Control 2 (Mode)    |
   Bearer <agent key>            |                         ...  --> Decision   |
                                 |                                     |       |
                                 |  proxy only: forward to Upstream    |       |
                                 |  (Ollama, OpenAI-compatible, mock)  v       |
                                 |                           Audit Event       |
                                 +-------------------------------|-------------+
                                       ^ /v1/admin/*             v
                       Dashboard :8501 |                   Postgres (Compose)
                                       |                   SQLite (tests, local)
```

- **One pipeline, two transports** ([ADR 0001](docs/adr/0001-one-pipeline-two-transports.md)). In **check API** mode the Agent asks the firewall around its own LLM and tool calls, at four Stages: `input`, `output`, `tool_call`, `tool_result`. In **proxy** mode the Agent only changes its `base_url`; the firewall runs the `input` Check, calls the Upstream, runs the `output` Check. Controls never know which transport delivered a Check.
- **Policy** (`policies/*.yaml`): which Controls run, in which order, at which Mode (`off`, `monitor`, `redact`, `block`), with which params; plus Agents and their Owners, Upstreams, allowed models and audit settings. Saved changes apply on the next Check, no restart. An invalid file keeps the last good Policy and reports the error. Three Presets: `permissive`, `standard`, `strict`.
- **Decision**: the most severe action wins (`block` > `review` > `redact` > `allow`), with an explanation naming the Control that decided. The caller must enforce `block` and `review`, and use the returned content.
- **Audit Events**: one per Check (allowed ones too), with Agent, Owner, User, model, Decision, every Verdict (raw and effective action, latency), Policy version, tokens, and content per `audit.store_content`. Storage is SQLAlchemy async over `DATABASE_URL` ([ADR 0002](docs/adr/0002-sqlalchemy-postgres-in-compose-sqlite-in-tests.md)).

Services are independent (own `pyproject.toml`, `uv.lock`, Dockerfile) and never import each other:

| Service | Port | What |
|---|---|---|
| `firewall/` | 8001 | Check API, proxy, admin API |
| `chat/` | 8000 | Demo chat Agent (LangGraph), calls LLMs only through the firewall proxy |
| `dashboard/` | 8501 | Streamlit dashboard over the admin API only |
| `postgres` | internal | Audit Events (Compose only) |

The demo chat uses this path for every model call:

```text
User → Chat / LangGraph → Firewall input check → Upstream LLM
User ← Chat / LangGraph ← Firewall output check ← Upstream LLM
```

An input `block` or `review` stops the call before the model; `output_decision` is then
`null`. Otherwise both decisions and provider-reported `usage` are returned by `/v1/chat`.
Mock token counts are word counts, not model tokenization. `/health/firewall` checks
firewall availability only; `/health/llm` is a deprecated alias and does not probe the model.

Compose places chat on an internal network with the firewall; the firewall has
an upstream network connection. A separate Nginx ingress publishes the chat API on
`127.0.0.1:8000` and forwards requests to chat over the internal network. Local processes need deployment-level network restrictions
for equivalent isolation. Tool Check endpoints remain available, but this demo has no tool
executor: tool execution is not yet enforced by the gateway.

### Migration from the direct-provider chat

Set `LLM_MODEL=mock` or `LLM_MODEL=qwen3:4b` in the chat environment. Old `LLM_PROVIDER`,
`OLLAMA_MODEL`, `OLLAMA_BASE_URL`, `LLM_TIMEOUT_SECONDS` and `FIREWALL_ENABLED` settings
are no longer used by chat. Existing `.env` files must be updated; they are not rewritten.
Configure upstream URLs and API key environment names in the firewall Policy. Presets use
`OLLAMA_API_BASE` when set, otherwise `http://localhost:11434/v1`; Compose defaults to
`http://host.docker.internal:11434/v1`. Provider credentials belong to firewall only.
The chat timeout now covers both checks and the model call (default 130 seconds).

## Run

### Docker (everything)

```bash
cp .env.example .env      # optional; defaults work
docker compose up --build # or: make up
```

- Chat: <http://localhost:8000/docs> · Firewall: <http://localhost:8001/docs> · Dashboard: <http://localhost:8501>
- `./policies` is mounted read-write: edit `policies/standard.yaml` on the host and the next Check uses it. Switch Preset with `POLICY_PATH=/policies/strict.yaml` in `.env`.
- Ports already in use? Set `CHAT_PORT`, `FIREWALL_PORT`, `DASHBOARD_PORT` in `.env`.
- `make down` stops; `docker compose down -v` also drops the Postgres volume.

Try it:

```bash
# Blocked by the reference Control, with an explanation
curl -s localhost:8000/v1/chat -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Any update on Project Falcon?"}]}'

# Dashboard -> Controls -> keyword_blocklist -> monitor -> Apply, then repeat: it passes,
# and both Checks show up under Events.
```

### Locally (no Docker)

```bash
# Firewall (SQLite file in firewall/)
cd firewall && uv sync --locked
POLICY_PATH=../policies/standard.yaml uv run uvicorn firewall_app.main:create_app --factory --reload --port 8001

# Chat
cd chat && uv sync --locked
uv run uvicorn app.main:app --reload --port 8000      # LLM_MODEL=qwen3:4b for a local model

# Dashboard
cd dashboard && uv sync --locked
FIREWALL_URL=http://localhost:8001 uv run streamlit run app.py
```

Environment variables: see each service's `.env.example` (`POLICY_PATH`, `DATABASE_URL`, `ADMIN_KEY`, `UPSTREAM_TIMEOUT_SECONDS` for the firewall; `AGENT_KEY`, `FIREWALL_URL`, `LLM_MODEL`, `FIREWALL_TIMEOUT_SECONDS` for the chat). Env files are not loaded automatically: export them or pass `--env-file`.

## The contract

### Check API

`POST /v1/check/{stage}`, header `X-Agent-Key: <agent key>`. One body shape; fields not relevant to the Stage are rejected with 422.

| Stage | Required | Optional |
|---|---|---|
| `input` | `messages` | `user`, `metadata` |
| `output` | `message` | `usage {model, prompt_tokens, completion_tokens}`, `user`, `metadata` |
| `tool_call` | `tool {resource, action, args}` | `user`, `metadata` |
| `tool_result` | `tool`, `tool_result` | `user`, `metadata` |

```bash
curl -s localhost:8001/v1/check/input -H 'X-Agent-Key: demo-agent-key' \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"project falcon?"}],"user":"bob"}'
```

```json
{
  "check_id": "…", "policy_version": "79a88f44b427",
  "decision": {
    "action": "block",
    "reason": "Blocked by keyword_blocklist: forbidden phrase 'project falcon'",
    "risk_score": 1.0,
    "findings": [{"control": "keyword_blocklist", "type": "forbidden_phrase",
                  "detail": "message 0 contains 'project falcon'", "span": [0, 14]}],
    "verdicts": [{"control": "keyword_blocklist", "action": "block", "effective_action": "block",
                  "mode": "block", "latency_ms": 0.1, "...": "..."}],
    "policy_version": "79a88f44b427", "latency_ms": 0.2
  },
  "messages": [{"role": "user", "content": "project falcon?"}]
}
```

The response carries the content **after** the firewall (redacted when a Control redacted it) in the Stage's content fields. A missing or unknown key follows `defaults.unknown_agent`; a block is a normal Decision (HTTP 200) with reason `unknown agent`.

### OpenAI-compatible proxy

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8001/v1", api_key="demo-agent-key")
client.chat.completions.create(model="mock", messages=[{"role": "user", "content": "Hi"}])
```

The Agent key is accepted as `Authorization: Bearer` or `X-Agent-Key`. Models outside `allowed_models` are blocked. Blocked requests return a normal completion with `finish_reason: "content_filter"` and the explanation as content; every response has an extra `firewall` object with the input and output Decisions. Upstream failure → 502 (and an Audit Event). `stream: true` is not supported yet. The built-in `mock` model echoes the last user message.

### Admin API (dashboard)

Protected by `X-Admin-Key` when `ADMIN_KEY` is set.

| Endpoint | |
|---|---|
| `GET /v1/admin/policy` | `{yaml, parsed, version, loaded_at, last_error}` |
| `PUT /v1/admin/policy` | YAML body; validated, written atomically; 422 with errors if invalid |
| `GET /v1/admin/controls` | every Control: description, supported stages, mode, params, params JSON schema |
| `PATCH /v1/admin/controls/{id}` | `{mode?, params?}`; edits the Policy file (comments are not preserved) |
| `GET /v1/admin/events` | `stage, agent_id, action, since, limit`; newest first |
| `GET /v1/admin/events/export` | `format=jsonl|csv` (same filters), streamed download |
| `GET /v1/admin/metrics` | totals by action, Control, Agent; tokens; p50/p95 latency |

The chat fails closed: any firewall error (connection, timeout, HTTP error, malformed response, missing content) → HTTP 503, and model output never leaks. There is no firewall bypass or local model provider in the chat service.

## Tests

```bash
uv sync --locked
uv run pytest            # or: make test   (no services, network or API keys needed)
uv run ruff check .      # or: make lint
```

Tests use ASGI transports, a mock Upstream and SQLite in a temp dir. They cover every pipeline rule, Policy hot reload and last-good behaviour, identity, all four Stages, the proxy, the audit store and export, the admin API, the dashboard client, and the chat's fail-closed boundary.

## Docs

- [`CONTEXT.md`](CONTEXT.md): glossary
- [`docs/adr/`](docs/adr/): architecture decisions
- [`docs/CONTRIBUTING-controls.md`](docs/CONTRIBUTING-controls.md): add a Control in 15 minutes
- [`docs/backlog.md`](docs/backlog.md): tickets for the team
- [`docs/implementation-prompt-core.md`](docs/implementation-prompt-core.md) and [`docs/implementation-plan-core.md`](docs/implementation-plan-core.md): the core spec and its build log
- [`docs/context/`](docs/context/): challenge brief, rules, mentor guidance, scope, judging playbook, decisions

## Model provider modules

The firewall selects `model → policy upstream → provider adapter`. The built-in registry
contains `ollama`, `openai_compatible` and `mock`. Ollama uses its `/v1` compatible endpoint;
all adapters run between the same input and output checks.

```yaml
upstreams:
  - models: ["qwen3:4b"]
    provider: ollama
    base_url: http://localhost:11434/v1
```

Add the model to `allowed_models` as well. To support a different protocol, implement
an adapter in `firewall/firewall_app/providers/`, register it in `providers/__init__.py`
and add its model route. Compatible servers only need a new route.
See [Adding a model provider](docs/CONTRIBUTING-providers.md) for the contract and tests.

## Optional Phoenix observability

Telemetry is implemented once in the provider manager, using OpenTelemetry and
OpenInference attributes. Adapters only return `ModelResponse.usage`; adding a new adapter
requires no Phoenix code. There is no automatic framework instrumentation to double-count calls.

Start Phoenix and enable the firewall's background OTLP/HTTP exporter:

```bash
TELEMETRY_OTLP_ENDPOINT=http://phoenix:6006/v1/traces \
  docker compose --env-file .env.example --profile observability up --build -d
```

Open <http://localhost:6006> and select project `ai-control-layer`. Send a request to
`/v1/chat/completions` and allow a few seconds for batch export. Model spans show duration,
errors, requested/returned model, adapter name, agent ID, input check ID, policy version,
and reported input/output/total tokens. Text, keys and arbitrary request metadata are not exported.
A blocked input creates no model span; a blocked output still records the model's usage.
Mock usage is labeled `firewall.usage_source=mock_word_count`; it is not real tokenization.
Unknown usage is omitted, not replaced with zero. Failed calls may have unreported consumption.

For local firewall processes use `TELEMETRY_OTLP_ENDPOINT=http://localhost:6006/v1/traces`.
The endpoint can target another OTLP/HTTP collector without changing adapters or checks.
An empty endpoint disables export. To persist the setting, put it in the env file used by Compose;
otherwise subsequent Compose invocations must include the same environment override.

Exports use a bounded background queue and a short network timeout. Collector outages do not
block generation; telemetry may be dropped. The existing audit database remains independent.
Currently these are model-call spans, not a full distributed trace of chat and all checks.
Cost pricing, budget enforcement and CPU/GPU metrics are not implemented by this integration.

References: [Phoenix deployment](https://arize.com/docs/phoenix/self-hosting/deploying-phoenix),
[OpenInference LLM attributes](https://github.com/Arize-ai/openinference/blob/main/spec/llm_spans.md).
