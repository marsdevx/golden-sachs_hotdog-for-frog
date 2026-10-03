# Implementation prompt: AI Control Layer core

> Paste everything below the line into a fresh Claude Code session at the repo root.

---

You are implementing the **core** of the AI Control Layer (an "AI firewall") in this repo. The core is the base that the rest of the team will build features on, one Control per developer, without touching the core. **Do not implement the real security Controls** (PII, injection, budgets, R4 signatures, resource access). Each of those becomes a ticket in the backlog you write at the end.

**Work is tracked in `docs/implementation-plan-core.md`.** Follow its steps in order, verify and commit each step, and update its checkboxes and Session log before the session ends. This file is the spec; the plan is the order and the handoff.

## Read first (in this order)

1. `CONTEXT.md`: the glossary. Use these exact terms in code, docs and tests (Policy, Control, Mode, Preset, Stage, Check, Verdict, Decision, Finding, Agent, Owner, User, Resource, Audit Event, Upstream). Never use the `_Avoid_` words as identifiers.
2. `docs/adr/0001-one-pipeline-two-transports.md`, `docs/adr/0002-sqlalchemy-postgres-in-compose-sqlite-in-tests.md`
3. `docs/context/07-decisions-and-open-questions.md` (bottom table = decisions for this work), `docs/context/05-feature-scope.md`, `docs/context/06-judging-playbook.md`
4. Existing code: `README.md`, `chat/`, `firewall/`, `tests/`, `compose.yaml`, root `pyproject.toml`.

## Existing constraints to keep

- `chat/` and `firewall/` are independent services. **Neither imports the other.** Each has its own `pyproject.toml`, `uv.lock`, Dockerfile. The root project exists for dev and integration tests only (`pythonpath = ["chat", "firewall"]`).
- The chat fails closed: any firewall error → HTTP 503, model output never leaks. `block` and `review` are enforced by the caller. Keep all of this and its tests (`tests/test_service_boundary.py`).
- Python ≥3.11, FastAPI, Pydantic v2, httpx, ruff (line length 100, rules E,F,I,UP), pytest. Use `uv` and update lockfiles (`uv lock`) when adding dependencies.
- Tests must run with `uv run pytest` and **no running services, no network, no API keys** (ASGI transport, mock Upstream, SQLite).

## Target layout (firewall)

```
firewall/firewall_app/
  main.py              # create_app(policy_path=None, database_url=None, upstream_transport=None): wiring only
  settings.py          # env: POLICY_PATH, DATABASE_URL, ADMIN_KEY, UPSTREAM_TIMEOUT_SECONDS
  domain.py            # Stage, Mode, Action, Message, ToolCall, Usage, Check, Finding, Verdict, Decision
  policy/
    schema.py          # Pydantic models of policy.yaml
    loader.py          # PolicyStore: mtime hot reload, last-good on error, version hash, write()
  controls/
    __init__.py        # imports every control module so they self-register
    base.py            # Control base class, @control decorator, registry
    keyword_blocklist.py   # the ONE reference Control (template for the team)
  pipeline.py          # run_check(check, policy) -> Decision
  identity.py          # X-Agent-Key -> Agent (+ Owner, team); unknown-agent handling
  storage/
    db.py              # SQLAlchemy async engine/session from DATABASE_URL, create_all on startup
    audit.py           # AuditStore: append(event), query(filters), export jsonl/csv
  api/
    check.py           # POST /v1/check/{stage}
    proxy.py           # POST /v1/chat/completions (OpenAI-compatible, non-streaming)
    admin.py           # policy GET/PUT, controls list, events, export, metrics
policies/
  permissive.yaml  standard.yaml  strict.yaml
```

Place `policies/` at the repo root and mount it into the firewall container. Default `POLICY_PATH=policies/standard.yaml`.

## Domain model (`domain.py`)

- `Stage`: `input | output | tool_call | tool_result`
- `Mode` (per Control, in the Policy): `off | monitor | redact | block`
- `Action` (Verdict/Decision): `allow | redact | review | block`. Severity order `block > review > redact > allow`.
- `Message {role: system|user|assistant|tool, content}`
- `ToolCall {resource: str, action: str, args: dict}`. `action` is a free string (e.g. `read`, `write`, `book_trade`); the Policy classifies it later.
- `Usage {model: str | None, prompt_tokens: int | None, completion_tokens: int | None}`
- `Check` (what every Control receives): `check_id`, `stage`, `agent` (resolved Agent with `id`, `owner`, `team`), `user: str | None`, `messages: list[Message]` (input), `message: Message | None` (output), `tool: ToolCall | None`, `tool_result: str | None`, `usage: Usage | None`, `labels: list[str]` (data sensitivity labels; empty for now, reserved for the information-barrier Control), `metadata: dict`, `transport: check_api | proxy` (for the audit log only; **Controls must not branch on it**).
- `Finding {control: str, type: str, detail: str, span: tuple[int,int] | None}`
- `Verdict {control, action, reason, risk_score 0..1, findings, rewritten: Check-content | None, latency_ms}`. A Control rewrites content by returning the modified messages/message/tool/tool_result.
- `Decision {action, reason, risk_score (max), findings (all), verdicts (per control), policy_version}`

## Policy (`policy.yaml`)

The Policy must be readable by non-engineers. Use comments and a `description` on every Control. Shape:

```yaml
version_note: "standard preset"          # free text, shown in dashboard
defaults:
  unknown_agent: block                   # block | allow (allow => anonymous Agent "unknown")
  on_error: block                        # default for Controls that raise
agents:
  - key: "demo-agent-key"                # value of X-Agent-Key
    id: "research-assistant"
    owner: "alice@bank.example"
    team: "markets-research"
upstreams:                               # proxy mode; model name -> OpenAI-compatible base URL
  - models: ["qwen3:4b"]
    base_url: "http://localhost:11434/v1"
    api_key_env: null                    # name of env var holding a key, never the key itself
allowed_models: ["qwen3:4b", "mock"]     # proxy rejects others with a block Decision
controls:                                # ORDER MATTERS: pipeline runs top to bottom
  keyword_blocklist:
    mode: block                          # off | monitor | redact | block
    stages: [input, output]              # optional override; must be a subset of the Control's supported stages
    on_error: block                      # optional, else defaults.on_error
    description: "Blocks messages containing forbidden phrases."
    params:
      keywords: ["project falcon"]
```

- `PolicyStore` checks the file's mtime on every `get()`. It reloads if the mtime changed and validates the whole document, including each Control's `params` against that Control's `Params` model and stage overrides against its supported stages. Unknown Control ids are an error.
- **An invalid file keeps the last good Policy.** Log the error and expose it via `GET /v1/admin/policy` (`last_error`).
- `policy_version` = short sha256 of the file bytes. It is stamped on every Decision and Audit Event.
- `write(new_yaml_text)` validates first, then writes atomically (temp file + rename). It is used by `PUT /v1/admin/policy` and by control toggles.
- The three Presets are complete files: `permissive` (reference Control `monitor`), `standard` (`block`), `strict` (`block` plus extra keywords, `unknown_agent: block`). Keep them valid against the schema. The team will add sections to them as Controls land.

## Control interface (`controls/base.py`)

```python
@control("keyword_blocklist")
class KeywordBlocklist(Control):
    stages = {Stage.input, Stage.output}          # supported stages
    class Params(BaseModel):
        keywords: list[str] = []
    async def evaluate(self, check: Check, params: Params) -> Verdict: ...
```

- The registry maps id → class. `controls/__init__.py` imports every module. Adding a Control means one file, one import line, and one test file.
- Controls are stateless objects. Any state they need (budget counters, later) goes through an injected store (`self.ctx.db`), never module globals.

## Pipeline semantics (`pipeline.py`), all mandatory and each covered by a test

1. Controls run in Policy order. Only those with `mode != off` whose effective stages include `check.stage` run.
2. **Redactions chain**: if a Verdict carries `rewritten` content and the action is `redact`, later Controls see the rewritten Check.
3. **Short-circuit on the first effective `block`** (skip the remaining Controls).
4. **Errors**: an exception in a Control produces a Verdict with action `block` or `allow` per `on_error`, reason `"control error: <type>"`, and is logged. It never surfaces as an HTTP 500.
5. **Mode caps the action**: `monitor` → the effective action is always `allow` (raw Verdict still recorded). `redact` → `block` is downgraded to `redact` only if the Verdict has rewritten content, else stays `allow` and is recorded. `block` → the Verdict's action is used as is. Record both the raw and effective action per Verdict.
6. The Decision is the most severe effective action, max risk score, all Findings, and a human-readable reason naming the Control that decided it (explained denials).
7. Measure `latency_ms` per Control and the total.
8. Persist one **Audit Event per Check** (including allowed ones): `check_id, ts, stage, transport, agent_id, owner, team, user, model, decision action, reason, risk_score, findings, verdicts (raw+effective, latency), policy_version, total_latency_ms, prompt/completion tokens`, and the content before and after the firewall. Content storage is a Policy setting `audit.store_content: full | redacted | none`, default `redacted` (store only the post-firewall content).

## HTTP API

### Check API (`api/check.py`), the integration contract for Agents

`POST /v1/check/{stage}` with header `X-Agent-Key`. One body shape for all stages; fields not relevant to the stage are rejected with 422:

```json
{"messages": [...], "message": {...}, "tool": {"resource": "crm", "action": "read", "args": {}},
 "tool_result": "...", "user": "bob", "usage": {...}, "metadata": {}}
```

- `input` needs `messages`. `output` needs `message` (+ optional `usage`). `tool_call` needs `tool`. `tool_result` needs `tool` + `tool_result`.
- The response is `{check_id, policy_version, decision: {...}, messages|message|tool|tool_result: <content after firewall>}`.
- A missing or unknown key follows `defaults.unknown_agent`. A block here is a normal Decision with HTTP 200 and reason `"unknown agent"`, plus an Audit Event.
- Remove the old `/v1/check/input|output` request shapes. **Rename `violations` → `findings` (structured).** Drop `modified_content` (the content fields carry it).

### Proxy (`api/proxy.py`)

`POST /v1/chat/completions`, OpenAI request/response shape, `stream: true` → 400 "not supported yet". Agent identity comes from `X-Agent-Key` **or** `Authorization: Bearer <agent key>`, so stock OpenAI SDKs work by setting `base_url` + `api_key`.

Flow: model not in `allowed_models` → block. Run the `input` Check → if blocked, return an OpenAI-shaped response whose assistant content is the explanation, with `finish_reason: "content_filter"` and an extra top-level `firewall` object holding the Decision. Otherwise forward the (possibly redacted) messages to the Upstream for that model, fill `usage` from the Upstream response, run the `output` Check, and return the (possibly redacted) completion with the `firewall` object.

Add a built-in Upstream `mock` (base_url `mock://`) that echoes, for tests and demo. Use an injectable httpx transport for tests. Upstream failure → 502, with an Audit Event.

### Admin API (`api/admin.py`)

Protected by `X-Admin-Key` when `ADMIN_KEY` is set; open otherwise (dev).

- `GET /v1/admin/policy` → `{yaml, parsed, version, loaded_at, last_error}`
- `PUT /v1/admin/policy` (text/yaml body) → validate, write, return the new version. 422 with errors if invalid.
- `GET /v1/admin/controls` → registry + Policy view: id, description, supported stages, current mode, stages, params JSON schema (the dashboard renders toggles from this)
- `PATCH /v1/admin/controls/{id}` `{mode?, params?}` → edits the Policy file (same validation path)
- `GET /v1/admin/events?stage=&agent_id=&action=&since=&limit=` → Audit Events, newest first
- `GET /v1/admin/events/export?format=jsonl|csv` → streamed download
- `GET /v1/admin/metrics` → totals by action, by Control (fired/blocked/redacted), by Agent; tokens by Agent; p50/p95 latency per Control and total

`GET /health` stays.

## Chat service changes

- `FirewallClient` speaks the new contract: `check(stage, payload)`. Send `X-Agent-Key` from env `AGENT_KEY` (default `demo-agent-key`), and send `usage` + `model` on the output Check (MockLLM reports token counts as a word count; OllamaLLM reads `prompt_eval_count` / `eval_count`).
- Keep the chat's own public API (`/v1/chat`) and its fail-closed behavior. Map `findings` into its response decision models.
- **Do not** add fake tools to the agent. That's a backlog ticket. Just make `check_tool_call` / `check_tool_result` available on the client.

## Dashboard skeleton (`dashboard/`, new independent service)

Streamlit, its own `pyproject.toml` / `uv.lock` / Dockerfile, talks **only** to the admin API (`FIREWALL_URL`, `ADMIN_KEY`). Three pages, minimal but working:

1. **Controls**: one row per Control: description, mode selector (off/monitor/redact/block), "Apply" → `PATCH`.
2. **Events**: table of recent Audit Events with filters and an export button.
3. **Overview**: metric tiles from `/v1/admin/metrics` (checks, blocked, redacted, tokens, p95 latency).

No styling work. The dashboard owner will take it from there.

## Infra

- `compose.yaml`: add `postgres` (16, healthcheck, volume), `firewall` (`DATABASE_URL=postgresql+asyncpg://...`, `POLICY_PATH=/policies/standard.yaml`, `./policies` mounted **read-write** so admin edits persist and judges can edit the file on the host), `dashboard` (port 8501), and `chat` (`AGENT_KEY`).
- Firewall deps: `sqlalchemy[asyncio]`, `aiosqlite`, `asyncpg`, `pyyaml`, `httpx`. Keep the SQL portable (JSON columns via SQLAlchemy `JSON`).
- Update `.env.example` files.
- Add a `Makefile` with `test`, `lint`, `up`, `down`.

## Tests (`tests/`), all offline

- `test_policy.py`: loads each Preset. Hot reload: write the file, change mtime, behavior changes **without restarting the app**. An invalid edit keeps the last good Policy and reports `last_error`. Unknown Control id and bad params are rejected. `PUT`/`PATCH` round-trip.
- `test_pipeline.py`: one test per pipeline rule 1–8 above, using small test-only Controls registered in the test (e.g. always-redact, always-block, raises).
- `test_identity.py`: known key, missing key, unknown key under both `unknown_agent` settings.
- `test_check_api.py`: each of the 4 Stages, valid and invalid bodies, and the response shape.
- `test_proxy.py`: happy path through the mock Upstream, disallowed model, input block (Upstream not called), output redact, Upstream failure → 502, and the bearer-token identity form.
- `test_audit.py`: one event per Check, filters, JSONL + CSV export, `store_content` modes.
- `test_keyword_blocklist.py`: **the template every Control test copies**: ≥1 allowed and ≥1 blocked case per supported Stage, plus the `monitor` mode case.
- Update `test_api.py` / `test_service_boundary.py` to the new contract. All fail-closed tests must still pass.
- Use a `conftest.py` with fixtures: `tmp_policy(yaml_text)`, `firewall_app` (SQLite in a tmp file), `chat_app` (wired to `firewall_app` via ASGI transport), `agent_headers`.

## Docs to write

- `docs/CONTRIBUTING-controls.md`: "Add a Control in 15 minutes": the file skeleton, registering it, the Policy section, reading `Check` fields per Stage, returning Findings and rewritten content, the test template, adding it to the three Presets, and the do's and don'ts (no state in globals, never branch on transport, use glossary terms).
- `docs/backlog.md`: one ticket per feature from `docs/context/05-feature-scope.md`. Each ticket has the Control id, Stages, `Params` sketch, Policy snippet, acceptance tests (positive + negative), dependencies, and suggested owner role. At minimum:
  - `pii_filter`: the showcase, with strictness levels PII → + credit/card → + secrets
  - `secrets_detector`
  - `injection_heuristics` (deterministic)
  - `injection_classifier` (semantic; Ollama + mock; threshold; fail behavior)
  - `token_budget` (per Agent/team, tokens + cost, works for local models)
  - `loop_detector`
  - `resource_access` (default deny, read vs write/irreversible, `review` for risky actions)
  - `attack_signatures` (R4: external feed file/URL, hot reload)
  - `information_barrier` (stretch; uses `user` + `labels`)
  - demo agent fake tools (`crm.read_client`, `trading.book_trade`, `wiki.edit`) + synthetic M&A/trading data
  - proxy streaming
  - hash-chained audit log + "proof by negation" query (stretch)
  - post-hoc threat detection (anomaly on Audit Events)
  - dashboard polish (management vs security views)
  - architecture diagram
  - latency benchmark script (p50/p95 with and without Controls)
- Update `README.md`: the new architecture (both transports), how to run, the contract, and links to `CONTEXT.md`, the ADRs, the contributing guide and the backlog.

## Done means

- `uv run pytest` and `uv run ruff check .` are green from the repo root.
- `docker compose up --build` brings up postgres, firewall, chat and dashboard. A chat message containing a blocklisted keyword is blocked with an explanation. Toggling the Control to `monitor` in the dashboard lets the next message through, without restarting anything, and both show up in Events.
- Commit on the current feature branch in logical steps (domain + policy, pipeline, storage, APIs, chat, dashboard, docs). Don't push.

If something in this prompt contradicts `CONTEXT.md` or an ADR, stop and ask instead of guessing.
