# Implementation plan: AI Control Layer core

This file is the **living tracker** for building the core across multiple Claude Code sessions. The spec it implements is `docs/implementation-prompt-core.md` ("the spec"). This file says **in what order**, **how to verify each step**, and **where we stopped**.

## How to use this file (read at the start of every session)

1. Read, in order: `CONTEXT.md` → `docs/adr/*` → the spec → this file.
2. Find the first step not marked `[x]` in **Steps**. Read the latest entry in **Session log**.
3. Run `git log --oneline -15` and `uv run pytest -q` to confirm the repo matches what the log says.
4. Work **one step at a time**: implement → run that step's **Verify** → commit → tick the box → move on.
5. **Before the session ends** (or context gets long), update this file: tick boxes, add a **Session log** entry, record any decision in **Decisions made during implementation**. Commit it. This file is the handoff; anything not written here is lost.

### Rules

- The spec, `CONTEXT.md` and the ADRs win over this file. If they conflict, stop and ask the user.
- Use glossary terms only (Policy, Control, Mode, Preset, Stage, Check, Verdict, Decision, Finding, Agent, Owner, User, Resource, Audit Event, Upstream).
- One commit per step (or smaller), message `core(<step id>): <what>`, on branch `feature/denis/core`. Never push unless the user asks.
- The test suite must be green at the end of every step. If a step deliberately breaks something until a later step, say so in the step's notes and in the session log.
- Don't implement real security Controls (PII, injection, budgets, R4, access). They are backlog tickets.
- Prefer small, verifiable progress over big untested batches.

## Status at a glance

| Phase | Steps | Status |
|---|---|---|
| 0. Prep | S0 | ✅ |
| 1. Firewall domain and Policy | S1–S3 | ✅ |
| 2. Pipeline and Controls | S4–S5 | ✅ |
| 3. Identity and storage | S6–S7 | ✅ |
| 4. HTTP surfaces | S8–S10 | ✅ |
| 5. Chat migration | S11 | ✅ |
| 6. Dashboard | S12 | ✅ |
| 7. Infra | S13 | ✅ |
| 8. Docs and backlog | S14–S15 | ✅ |
| 9. End-to-end acceptance | S16 | ✅ |

Update the Status column (☐ / ◐ / ✅) when a phase starts and finishes.

## Dependency graph

```
S0 ─ S1 ─ S2 ─ S3 ─ S4 ─ S5 ─┬─ S8 (check API) ─┬─ S11 (chat) ─┐
           │                  │                  │              │
           └─ S6 (identity) ──┤                  │              ├─ S13 (infra) ─ S16
              S7 (storage) ───┼─ S9 (proxy) ─────┤              │
                              └─ S10 (admin) ────┴─ S12 (dash) ─┘
S14, S15 (docs) can start once S5 is done; finish after S10.
```

## Steps

Each step lists **Do** (what to build; details are in the spec), **Files**, **Verify** (the exact command and expected result) and **Done when**.

---

### Phase 0: Prep

- [x] **S0: Baseline and dependencies**
  - **Do:** Confirm `uv run pytest` and `uv run ruff check .` are green on the current code. Add firewall deps (`sqlalchemy[asyncio]`, `aiosqlite`, `asyncpg`, `pyyaml`, `httpx`) to `firewall/pyproject.toml` **and** the root `pyproject.toml`. Add test deps if needed (`pytest-asyncio` or anyio). Run `uv lock` in `firewall/` and the root.
  - **Files:** `firewall/pyproject.toml`, `firewall/uv.lock`, `pyproject.toml`, `uv.lock`
  - **Verify:** `uv sync --locked && uv run pytest -q` → all existing tests pass.
  - **Done when:** the lockfiles are updated and the baseline is green. Commit `core(S0): add core dependencies`.

### Phase 1: Firewall domain and Policy

- [x] **S1: Domain model**
  - **Do:** `firewall_app/domain.py` with Stage, Mode, Action (+ severity order helper), Message, ToolCall, Usage, Agent, Check, Finding, Verdict, Decision, exactly as in the spec's "Domain model". Don't wire them into the API yet; the old endpoints keep using `models.py`.
  - **Files:** `firewall/firewall_app/domain.py`, `tests/test_domain.py`
  - **Verify:** `uv run pytest tests/test_domain.py -q` covers severity ordering (`block > review > redact > allow`) and model validation.
  - **Done when:** green, committed.

- [x] **S2: Control base and registry, plus the reference Control**
  - **Do:** `controls/base.py` (`Control` base class with `stages`, nested `Params`, `async evaluate(check, params) -> Verdict`, `@control(id)` decorator, registry with `get(id)` / `all()`). Add `controls/keyword_blocklist.py` and `controls/__init__.py` importing it. Policy validation needs the registry, so this comes before S3.
  - **Files:** `firewall/firewall_app/controls/{__init__,base,keyword_blocklist}.py`, `tests/test_keyword_blocklist.py` (unit level: call `evaluate` directly for each Stage, plus an allowed case and a blocked case)
  - **Verify:** `uv run pytest tests/test_keyword_blocklist.py -q`
  - **Done when:** the registry lists `keyword_blocklist`. Committed.

- [x] **S3: Policy schema, PolicyStore and Presets**
  - **Do:** `policy/schema.py` (all sections from the spec, including `audit.store_content`), with validation of each Control's `params` against its registered `Params` and stage overrides ⊆ supported stages, and an error on unknown ids. `policy/loader.py` `PolicyStore`: mtime-based `get()`, last-good on error with `last_error`, `version` = short sha256 of the file bytes, `loaded_at`, atomic `write(text)` that validates first. Add the Presets `policies/{permissive,standard,strict}.yaml` with comments and a `description` on every Control.
  - **Files:** `firewall/firewall_app/policy/*`, `policies/*.yaml`, `tests/test_policy.py`, `tests/conftest.py` (add the `tmp_policy` fixture)
  - **Verify:** `uv run pytest tests/test_policy.py -q`. All three Presets load. A changed file + changed mtime → new version. Invalid YAML / unknown Control / bad params → last good kept and `last_error` set. `write` with invalid text leaves the file untouched.
  - **Done when:** green, committed.

### Phase 2: Pipeline

- [x] **S4: Pipeline**
  - **Do:** `pipeline.py` `run_check(check, policy, registry) -> Decision`. It implements rules 1–7 from the spec's "Pipeline semantics": Policy order, redaction chaining, short-circuit on block, `on_error`, Mode capping (raw + effective action), the most-severe aggregation with an explained reason, and per-Control + total latency. Audit persistence (rule 8) is added in S7.
  - **Files:** `firewall/firewall_app/pipeline.py`, `tests/test_pipeline.py` (register test-only Controls inside the test module: always-allow, always-redact (rewrites), always-block, raises, records-what-it-saw)
  - **Verify:** `uv run pytest tests/test_pipeline.py -q`, with **one named test per rule**, e.g. `test_rule2_redactions_chain`, `test_rule5_monitor_never_changes_outcome`.
  - **Done when:** green, committed.

- [x] **S5: Firewall app wiring (no new routes yet)**
  - **Do:** `settings.py` (env: `POLICY_PATH`, `DATABASE_URL`, `ADMIN_KEY`, `UPSTREAM_TIMEOUT_SECONDS`). `main.create_app(policy_path=None, database_url=None, upstream_transport=None)` builds the PolicyStore and stores it on `app.state`. The old `/v1/check/input|output` endpoints still work unchanged.
  - **Files:** `firewall/firewall_app/{settings,main}.py`
  - **Verify:** the full `uv run pytest -q` stays green, and so do the old tests.
  - **Done when:** committed. From here on, S14 (contributing guide) can be written in parallel.

### Phase 3: Identity and storage

- [x] **S6: Agent identity**
  - **Do:** `identity.py` resolves `X-Agent-Key` **or** `Authorization: Bearer <key>` to an `Agent(id, owner, team)` from the Policy. A missing or unknown key follows `defaults.unknown_agent` (`allow` → anonymous Agent `unknown`; `block` → the caller produces a block Decision with reason `"unknown agent"`).
  - **Files:** `firewall/firewall_app/identity.py`, `tests/test_identity.py`
  - **Verify:** `uv run pytest tests/test_identity.py -q` covers a known key, a bearer key, a missing key and an unknown key under both settings.
  - **Done when:** green, committed.

- [x] **S7: Storage and Audit Events**
  - **Do:** `storage/db.py` (async engine from `DATABASE_URL`, default `sqlite+aiosqlite:///./firewall.db`, `create_all` on startup via the app lifespan). `storage/audit.py` `AuditStore`: `append(event)`, `query(stage, agent_id, action, since, limit)`, `export(format)` (jsonl/csv, streamed), and `metrics()` (totals by action, by Control, by Agent; tokens by Agent; p50/p95 latency per Control and total, computed in Python for portability). Hook persistence into the pipeline flow (rule 8), respecting `audit.store_content`.
  - **Files:** `firewall/firewall_app/storage/*`, `tests/test_audit.py`, `tests/conftest.py` (`firewall_app` fixture using a tmp SQLite file)
  - **Verify:** `uv run pytest tests/test_audit.py -q` checks one event per Check (including allowed ones), filters, both export formats, the three `store_content` modes and the metrics shape.
  - **Done when:** green, committed. Portable SQL only (ADR 0002).

### Phase 4: HTTP surfaces

- [x] **S8: Check API (breaking contract change)**
  - **Do:** `api/check.py` `POST /v1/check/{stage}` with the unified body, per-stage required fields (422 otherwise), identity, pipeline, audit, and the response `{check_id, policy_version, decision, <content fields>}`. Remove the old input/output endpoints and `models.py` shapes. Rename `violations` → `findings`.
  - **Files:** `firewall/firewall_app/api/check.py`, `firewall/firewall_app/main.py`, delete/trim `firewall/firewall_app/models.py`, `tests/test_check_api.py`
  - **⚠ Known breakage:** `tests/test_api.py` and `tests/test_service_boundary.py` (the chat ↔ firewall tests) will fail until S11. Mark them `@pytest.mark.xfail(reason="contract migration, fixed in S11", strict=True)` in this step and remove the marks in S11. Note it in the session log.
  - **Verify:** `uv run pytest tests/test_check_api.py -q` covers all 4 Stages, valid and invalid bodies, the unknown agent case, and a hot-reload-through-HTTP case (edit the policy file, the next Check behaves differently).
  - **Done when:** green (with the xfails), committed.

- [x] **S9: OpenAI-compatible proxy**
  - **Do:** `api/proxy.py` `POST /v1/chat/completions`, non-streaming (`stream: true` → 400). Covers `allowed_models`, the input Check, forwarding to the Upstream from the Policy `upstreams` (built-in `mock://` echo Upstream, injectable httpx transport), filling `usage` from the response, the output Check, the `firewall` object in the response, a blocked → `finish_reason: "content_filter"` response with the explanation, and Upstream failure → 502 + an Audit Event. Audit Events record `transport: proxy`.
  - **Files:** `firewall/firewall_app/api/proxy.py`, `tests/test_proxy.py`
  - **Verify:** `uv run pytest tests/test_proxy.py -q` covers the happy path, a disallowed model, an input block (Upstream **not** called), output redaction, an Upstream failure and bearer identity. Optional manual check: the `openai` Python SDK with `base_url=http://localhost:8001/v1` works against the mock Upstream.
  - **Done when:** green, committed.

- [x] **S10: Admin API**
  - **Do:** `api/admin.py`, with all endpoints from the spec, `X-Admin-Key` enforced only when `ADMIN_KEY` is set, and `PATCH /controls/{id}` editing the Policy file through `PolicyStore.write`. The YAML is rewritten via a parse → modify → dump round-trip. Comments are lost on a PATCH; note this in the docs.
  - **Files:** `firewall/firewall_app/api/admin.py`, `tests/test_admin.py`
  - **Verify:** `uv run pytest tests/test_admin.py -q` covers the policy GET/PUT round-trip, PUT invalid → 422 with the file unchanged, PATCH mode → the next Check reflects it, the controls listing includes the params JSON schema, events filters, the export download, metrics, and admin key enforcement on/off.
  - **Done when:** green, committed.

### Phase 5: Chat migration

- [x] **S11: Chat speaks the new contract**
  - **Do:** `FirewallClient.check(stage, payload)` plus helpers `check_input`, `check_output`, `check_tool_call`, `check_tool_result`. It sends `X-Agent-Key` from `AGENT_KEY` (default `demo-agent-key`). The output Check carries `usage` + `model` (MockLLM: word counts; OllamaLLM: `prompt_eval_count` / `eval_count`). Update the chat `ControlDecision` model to `findings`. Keep `/v1/chat` and all fail-closed behavior. Remove the S8 xfail marks and update both test files to the new contract.
  - **Files:** `chat/app/{config,firewall_client,models}.py`, `chat/app/llm/providers.py`, `chat/app/agent/graph.py`, `tests/test_api.py`, `tests/test_service_boundary.py`, `tests/conftest.py` (`chat_app` fixture wired to `firewall_app` via ASGI)
  - **Verify:** `uv run pytest -q` → **everything green, no xfails left.** Add a test: a chat message with a blocklisted keyword → blocked with an explanation, and an Audit Event exists with the correct `agent_id` and tokens.
  - **Done when:** committed.

### Phase 6: Dashboard

- [x] **S12: Streamlit dashboard skeleton**
  - **Do:** a new `dashboard/` service (own `pyproject.toml`, `uv.lock`, Dockerfile, `.env.example`). It talks **only** to the admin API (`FIREWALL_URL`, `ADMIN_KEY`). Pages: Overview (metric tiles), Controls (mode selector + Apply → PATCH), Events (filters, table, export). Put the HTTP calls in one small `api.py` so they can be tested without Streamlit.
  - **Files:** `dashboard/**`, `tests/test_dashboard_api.py` (the `api.py` client against the firewall ASGI app)
  - **Verify:** `uv run pytest tests/test_dashboard_api.py -q`. Manual: `cd dashboard && uv run streamlit run app.py` with the firewall running locally. Toggling a Control changes `policies/standard.yaml`.
  - **Done when:** committed.

### Phase 7: Infra

- [x] **S13: Compose, env, Makefile**
  - **Do:** `compose.yaml` with `postgres:16` (healthcheck, volume), `firewall` (`DATABASE_URL=postgresql+asyncpg://...`, `POLICY_PATH=/policies/standard.yaml`, `./policies:/policies` read-write, depends on a healthy postgres), `dashboard` (8501), and `chat` (`AGENT_KEY`). Update all `.env.example` files. Add a `Makefile`: `test`, `lint`, `up`, `down`, `logs`.
  - **Verify:** `docker compose up --build -d`, then `curl localhost:8001/health`, a chat request via `curl localhost:8000/v1/chat`, and `curl localhost:8001/v1/admin/events` showing the event stored in Postgres. `docker compose down`.
  - **Done when:** works from a clean `docker compose down -v`. Committed.

### Phase 8: Docs and backlog

- [x] **S14: Contributing guide for Controls**
  - **Do:** `docs/CONTRIBUTING-controls.md`, written per the spec. Validate it by actually following it: add a throwaway Control in a scratch branch or temp dir and time it, then delete it.
  - **Done when:** committed.

- [x] **S15: Backlog and README**
  - **Do:** `docs/backlog.md`, with every ticket listed in the spec, each having the Control id, Stages, `Params` sketch, Policy snippet, acceptance tests, dependencies and suggested owner role. Rewrite `README.md` for the new architecture (diagram in text, both transports, run instructions, contract, links to `CONTEXT.md`, ADRs, contributing guide, backlog, this plan).
  - **Done when:** committed.

### Phase 9: Acceptance

- [x] **S16: End-to-end acceptance (the spec's "Done means")**
  - **Verify, in order:**
    1. `uv run pytest -q` and `uv run ruff check .` are green from the repo root.
    2. `docker compose up --build`.
    3. A chat message with a blocklisted keyword → blocked with an explanation naming `keyword_blocklist`.
    4. Dashboard → Controls → set `keyword_blocklist` to `monitor` → the same message passes, **no restart**.
    5. Dashboard → Events shows both Checks, and the export downloads JSONL and CSV.
    6. Edit `policies/standard.yaml` on the host by hand (set the mode back to `block`) → the next message is blocked again.
    7. The proxy works: the `openai` SDK or curl to `/v1/chat/completions` with `model: "mock"` and the agent key as bearer.
  - **Done when:** all 7 pass. Record the results in the Session log, tick every phase, and tell the user the base is ready for the team.

## Decisions made during implementation

Record anything decided while coding that isn't in the spec (library choice, a contract detail, a deviation and why). If it's hard to reverse **and** surprising **and** a real trade-off, also write an ADR in `docs/adr/`.

| Date | Step | Decision | Why |
|---|---|---|---|
| 2026-10-03 | S0 | Work on `feature/denis/core` (the plan said `feature/denis/pi`). Installed `uv` into `~/.local/bin`. | The session started on that branch; `uv` was missing on the machine. |
| 2026-10-03 | S0 | `pytest-asyncio` in auto mode for async tests. | Plain `async def test_...` with no markers keeps the Control test template short. |
| 2026-10-03 | S1 | `Verdict` carries `action` (raw), `effective_action`, `mode`, `error`; the pipeline stamps `control` and `latency_ms`. `Content` is the rewritable part of a Check. | Rule 5 asks for raw and effective action per Verdict; Controls only set what they know. |
| 2026-10-03 | S2 | The registry is a `Registry` object (`REGISTRY` global + `control = REGISTRY.control`). Tests build their own `Registry` for test-only Controls. | Test Controls don't leak into the real Policy validation. |
| 2026-10-03 | S2 | `keyword_blocklist` returns `rewritten` content with its `block` Verdict. | Shows Control authors how to make a Control usable in `redact` Mode. |
| 2026-10-03 | S3 | Unknown `params` keys are an error (in addition to the `Params` model validation); all Policy sections forbid unknown keys. An invalid file at startup fails fast. | Typos in a hand-edited Policy must not be silently ignored. |
| 2026-10-03 | S3 | An unquoted `mode: off` (YAML 1.1 boolean `false`) is accepted as `off`. | Judges will type it unquoted. |
| 2026-10-03 | S3 | `PolicyStore.write` copies mode and owner of the old file onto the new one. | The container runs as root; edits through the dashboard must stay editable on the host. |
| 2026-10-03 | S4 | An error Verdict (`on_error`) is not capped by `redact` Mode, only by `monitor`. | `on_error` is the explicit fail behaviour; `monitor` never changes the outcome. |
| 2026-10-03 | S4 | `run_check` returns `PipelineResult(decision, before, after)`, not just a Decision. | Callers need the post-firewall content, the audit log needs both. |
| 2026-10-03 | S5 | No module-level `app` in the firewall; run with `uvicorn firewall_app.main:create_app --factory`. | Building the app at import would load the Policy from the CWD on every import. |
| 2026-10-03 | S7 | `firewall_app/service.py` `CheckService` (identity gate → pipeline → Audit Event) is shared by both transports. A failed audit write raises (fails closed). | One place for rule 8; no Check without evidence. |
| 2026-10-03 | S7 | SQLite uses `NullPool`; `AuditStore` creates tables lazily as well as in the lifespan. Timestamps stored as naive UTC. Metrics and percentiles computed in Python. | aiosqlite connections are loop-bound and ASGI test transports skip the lifespan; portable SQL (ADR 0002). |
| 2026-10-03 | S8 | `usage` is rejected on `input` Checks (only allowed on `output`), per the spec. | Strict per-Stage bodies. Relax if `token_budget` needs a pre-call estimate. |
| 2026-10-03 | S9 | Unknown Agent and disallowed model in the proxy → HTTP 200 completion with `finish_reason: content_filter` (like the check API's normal block). Upstream failure → 502 with an `output`-Stage Audit Event (`control: upstream`). The mock Upstream is an httpx transport mounted on `mock://`. | Consistent "block is a normal Decision"; the mock goes through the same code path as real Upstreams. |
| 2026-10-03 | S10 | `PATCH /controls/{id}` edits the last good Policy, so it overwrites a currently invalid file. Comments are lost (backlog #17). | Simplest correct behaviour; documented in the contributing guide and README. |
| 2026-10-03 | S11 | `LLMProvider.chat` returns `LLMReply(message, usage)`. The chat sends `metadata.user` as the Check `user`. | Usage must reach the output Check; no shared mutable state on the provider. |
| 2026-10-03 | S13 | Host ports configurable via `CHAT_PORT`, `FIREWALL_PORT`, `DASHBOARD_PORT` (defaults unchanged). | Port 8000 was taken on the dev machine. |

## Open issues / blockers

Things that need the user's input or are deferred. Remove them when resolved.

- Dashboard toggles drop comments from the Policy file (backlog #17, `ruamel.yaml`). Visible in the demo if someone opens the file after toggling.
- The Presets' `qwen3:4b` Upstream points at `localhost:11434`, which is wrong inside Docker (backlog #18). The demo uses `model: mock` for the proxy.
- `PUT`/`PATCH` round-trip tests live in `tests/test_admin.py` (the spec listed them under `test_policy.py`).

## Session log

Newest entry on top. Template:

```
### Session N: YYYY-MM-DD
- Completed: S?, S?
- In progress: S? (what's done, what's left, exact next action)
- Tests: <pass/fail counts, any xfails and why>
- Gotchas / notes for next session:
- Last commit: <hash> <message>
```

### Session 1: 2026-10-03
- Completed: S0–S16 (all steps).
- In progress: none. **The core is ready for the team; next work is `docs/backlog.md`.**
- Tests: 149 passed, 0 xfail; `ruff check .` clean; `uv lock --check` ok for firewall, chat, dashboard.
- S16 acceptance (docker compose, chat on `CHAT_PORT=8010` because 8000 was taken on this machine): 1 tests/lint green; 2 stack up (postgres, firewall, chat, dashboard healthy); 3 "Project Falcon" chat blocked with "Blocked by keyword_blocklist: forbidden phrase 'project falcon'"; 4 toggled to `monitor` by driving `dashboard/app.py` (Streamlit AppTest, Apply button) → same message passed, no restart; 5 all Checks in Events, JSONL + CSV export work, rows present in Postgres for both transports; 6 hand edit on the host back to `block` → blocked again; an invalid hand edit kept the last good Policy and showed `last_error`; 7 proxy via curl with `Authorization: Bearer demo-agent-key`, `model: mock` → completion + `firewall` object, and a blocked one with `content_filter`. The `openai` SDK itself was not run.
- Gotchas: YAML `off` is a boolean (handled). `pkill -f <pattern>` kills your own shell if the pattern is in the command. The acceptance run rewrote `policies/standard.yaml` via PATCH; it was restored with `git checkout`.
- Last commit: see `git log` (`core(S16): ...` plan update).

### Session 0: 2026-10-03 (planning)
- Completed: grilling session; `CONTEXT.md`, ADR 0001 + 0002, decisions log in `docs/context/07-...`, spec (`docs/implementation-prompt-core.md`), this plan.
- In progress: none. **Next action: S0.**
- Tests: existing suite green (passthrough stub).
- Gotchas: the docs are not committed yet. Commit them first in S0 (`docs: core design, glossary, ADRs, plan`).
- Last commit: 39da513 Merge pull request #1
