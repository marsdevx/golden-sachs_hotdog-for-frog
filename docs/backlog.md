# Backlog

One ticket per feature on top of the core. Every Control ticket follows `docs/CONTRIBUTING-controls.md`: one file in `firewall/firewall_app/controls/`, one import line, one test file (allowed + blocked/redacted case per Stage, plus a `monitor` case), and a section in all three Presets. Requirement ids (R1–R6) refer to `docs/context/01-challenge-brief.md`; the scope map is `docs/context/05-feature-scope.md`.

Owner roles: **Controls dev** (deterministic Controls), **ML dev** (semantic Controls), **Platform dev** (core, proxy, storage, infra), **Dashboard dev**, **Demo/pitch lead**.

| # | Ticket | Kind | Priority | Owner role |
|---|---|---|---|---|
| 1 | `pii_filter` (showcase) | Control | P0 | Controls dev |
| 2 | `secrets_detector` | Control | P1 | Controls dev |
| 3 | `injection_heuristics` | Control | P1 | Controls dev |
| 4 | `injection_classifier` | Control | P1 | ML dev |
| 5 | `token_budget` | Control | P1 | Platform dev |
| 6 | `loop_detector` | Control | P1 | Platform dev |
| 7 | `resource_access` | Control | P1 | Controls dev |
| 8 | `attack_signatures` (R4) | Control | P1 | Controls dev |
| 9 | `information_barrier` | Control | P2 (stretch) | Controls dev |
| 10 | Demo Agent fake tools + synthetic data | Demo | P0 | Demo/pitch lead |
| 11 | Proxy streaming | Core | P2 | Platform dev |
| 12 | Hash-chained audit log + proof by negation | Core | P2 (stretch) | Platform dev |
| 13 | Post-hoc threat detection | Dashboard/analysis | P1 | Dashboard dev |
| 14 | Dashboard polish: management vs security views | Dashboard | P1 | Dashboard dev |
| 15 | Architecture diagram | Deliverable | P0 | Demo/pitch lead |
| 16 | Latency benchmark script | Deliverable | P1 | Platform dev |
| 17 | Keep Policy comments on dashboard edits | Core | P2 | Platform dev |
| 18 | Upstream `base_url` from env (Ollama in Docker) | Core | P2 | Platform dev |

---

## 1. `pii_filter` (showcase Control)

The mentor's demo: output filtering with a strictness slider. Do this one *really* well.

- **Stages:** `output`, `tool_result` (supported: also `input`).
- **Params sketch:**
  ```python
  class Params(BaseModel):
      level: Literal["pii", "pii_financial", "pii_financial_secrets"] = "pii"
      replacement: str = "[{type}]"          # e.g. "[EMAIL]", "[IBAN]"
      allow_domains: list[str] = []          # e.g. internal email domains that may pass
  ```
  - `pii`: emails, phone numbers (international formats), national ids, postal addresses (best effort).
  - `pii_financial`: + payment card numbers (Luhn-checked), IBAN (checksum), account numbers.
  - `pii_financial_secrets`: + everything `secrets_detector` finds (reuse its detectors as a library function, don't duplicate).
  - Robust to obfuscation judges will try: spaces/dashes inside numbers, `name [at] domain [dot] com`, full-width digits.
- **Policy snippet:**
  ```yaml
  pii_filter:
    mode: redact
    stages: [output, tool_result]
    description: "Removes personal and financial data from what the AI returns."
    params:
      level: pii_financial
  ```
- **Acceptance tests:** positive: email/phone redacted at `pii`; a valid card number passes at `pii` but is redacted at `pii_financial`; an API key is redacted only at `pii_financial_secrets`; obfuscated email and spaced card number are caught; Findings carry `type` and `span` but **not** the value. Negative: a 16-digit number failing Luhn is not a card; normal prose untouched; `monitor` records Findings without changing content.
- **Dependencies:** core. Shares detectors with #2.
- **Dashboard:** expose `level` as a slider in the Controls page (params JSON schema already exposes the enum).

## 2. `secrets_detector`

- **Stages:** `input`, `output`, `tool_call`, `tool_result`.
- **Params sketch:** `detectors: list[str] = ["aws_key", "github_token", "openai_key", "anthropic_key", "private_key", "jwt", "generic_high_entropy"]`, `entropy_threshold: float = 4.0`, `min_length: int = 20`.
- **Policy snippet:**
  ```yaml
  secrets_detector:
    mode: redact
    description: "Stops API keys, tokens and private keys from leaving or entering the AI."
    params:
      detectors: [aws_key, github_token, openai_key, private_key, jwt]
  ```
- **Acceptance tests:** positive: each detector's sample is found and redacted (use fake keys with valid shapes); a secret inside `tool.args` at `tool_call` is found. Negative: UUIDs, git SHAs and base64 images are not flagged by `generic_high_entropy` at the default threshold.
- **Dependencies:** core. Expose detectors as plain functions for #1.

## 3. `injection_heuristics` (deterministic)

- **Stages:** `input`, `tool_result` (indirect injection from Resources).
- **Params sketch:** `patterns_file: str | None = None` (extra patterns), `decode: list[Literal["base64", "rot13", "unicode_escape"]] = ["base64"]`, `languages: list[str] = ["en", "de", "fr", "es", "cs", "ru"]`, `score_threshold: float = 0.5`.
- **Policy snippet:**
  ```yaml
  injection_heuristics:
    mode: block
    stages: [input, tool_result]
    description: "Blocks known prompt-injection phrasing, including encoded and translated variants."
    params:
      decode: [base64]
  ```
- **Acceptance tests:** positive: "ignore all previous instructions", its base64, a non-English variant, and an injection hidden in a `tool_result`. Negative: a user legitimately asking "what is prompt injection?" with low score; normal instructions in a system message.
- **Dependencies:** core. Put it **before** #4 in the Presets (cheap fast path first).

## 4. `injection_classifier` (semantic)

- **Stages:** `input`, `tool_result`.
- **Params sketch:**
  ```python
  class Params(BaseModel):
      backend: Literal["ollama", "anthropic", "mock"] = "ollama"
      model: str = "qwen3:4b"
      base_url: str = "http://localhost:11434"
      api_key_env: str | None = None
      threshold: float = 0.7
      timeout_seconds: float = 5.0
      skip_if_previous_risk_below: float | None = None   # run only when cheap Controls are unsure
  ```
- **Fail behaviour:** when the backend is down or times out, raise. The pipeline applies `on_error` (fail-closed `block` or fail-open `allow`), which is a Policy decision the judges can see.
- **Policy snippet:**
  ```yaml
  injection_classifier:
    mode: block
    on_error: allow          # fail open if the local model is down; strict preset uses block
    description: "Asks a language model whether the text tries to hijack the AI."
    params:
      backend: ollama
      threshold: 0.7
  ```
- **Acceptance tests (offline):** `mock` backend (deterministic scores) above/below threshold → block/allow; backend raises → Verdict per `on_error` both ways; timeout respected. An optional `@pytest.mark.ollama` test is skipped when Ollama is not reachable.
- **Dependencies:** core, ideally #3 (ordering).

## 5. `token_budget`

- **Stages:** `input` (pre-check: is the Agent already over budget?) and `output` (account usage from `check.usage`).
- **Params sketch:**
  ```python
  class Budget(BaseModel):
      tokens_per_day: int | None = None
      cost_per_day_usd: float | None = None
  class Params(BaseModel):
      per_agent: dict[str, Budget] = {}
      per_team: dict[str, Budget] = {}
      default: Budget = Budget()
      prices_per_1k: dict[str, tuple[float, float]] = {}   # model -> (prompt, completion) USD
      local_cost_per_1k: float = 0.0                       # notional cost so local models count
  ```
- **State:** a `budget_counters` table via `self.ctx.db` (portable SQL; add the table to `storage/db.py`). Never module globals.
- **Policy snippet:**
  ```yaml
  token_budget:
    mode: block
    description: "Stops an Agent or team that exceeds its daily token or money budget."
    params:
      default: {tokens_per_day: 200000}
      per_team: {trading-desk: {cost_per_day_usd: 25}}
      prices_per_1k: {"qwen3:4b": [0.0, 0.0]}
      local_cost_per_1k: 0.001
  ```
- **Acceptance tests:** under budget → allow; exceeding tokens → next `input` Check blocked with the budget in the reason; cost budget with prices; local model counted via `local_cost_per_1k`; per-team aggregates two Agents; works identically for usage from the check API and from the proxy (same Check fields).
- **Dependencies:** core. Dashboard #14 shows budget usage.

## 6. `loop_detector`

- **Stages:** `input`, `tool_call`.
- **Params sketch:** `window_seconds: int = 60`, `max_similar: int = 5`, `similarity: float = 0.9`, `max_calls_per_window: int = 30`.
- **State:** recent fingerprints per Agent via `self.ctx.db`.
- **Policy snippet:**
  ```yaml
  loop_detector:
    mode: block
    description: "Stops runaway Agents repeating the same request or tool call."
    params: {window_seconds: 60, max_similar: 5}
  ```
- **Acceptance tests:** 5 near-identical inputs in the window → the 6th is blocked; the same count spread over time → allowed; different Agents don't share counters; repeated identical `tool_call` loops are caught.
- **Dependencies:** core.

## 7. `resource_access`

Default deny for Resources, read vs write/irreversible, `review` for risky actions.

- **Stages:** `tool_call` (supported: also `tool_result` for size/row limits later).
- **Params sketch:**
  ```python
  class Rule(BaseModel):
      resource: str                  # "crm", "trading", "wiki", glob allowed
      actions: list[str]             # "read", "write", "book_trade", "*"
      agents: list[str] = ["*"]
      teams: list[str] = ["*"]
      effect: Literal["allow", "review", "block"] = "allow"
  class Params(BaseModel):
      rules: list[Rule] = []
      action_classes: dict[str, Literal["read", "write", "irreversible"]] = {}
      default: Literal["block"] = "block"           # default deny
      irreversible_effect: Literal["review", "block"] = "review"
  ```
- **Policy snippet:**
  ```yaml
  resource_access:
    mode: block
    description: "Agents may only use the Resources and actions explicitly allowed here."
    params:
      action_classes: {read_client: read, edit: write, book_trade: irreversible}
      rules:
        - {resource: crm, actions: [read_client], teams: [markets-research]}
        - {resource: wiki, actions: [edit], agents: ["*"]}
        - {resource: trading, actions: [book_trade], teams: [trading-desk], effect: review}
  ```
- **Acceptance tests:** unlisted Resource → block (default deny); read allowed, write on the same Resource blocked; `book_trade` → `review`; team scoping; reason names the rule. Negative: an allowed read passes with no Findings.
- **Dependencies:** core, #10 for the demo.

## 8. `attack_signatures` (R4: historical attacks)

- **Stages:** `input`, `tool_call`, `tool_result`.
- **Params sketch:** `feed: str` (file path or `https://` URL), `refresh_seconds: int = 60`, `categories: list[str] = ["deserialization", "code_exec", "malicious_repo", "jailbreak"]`.
- **Feed format:** YAML/JSON list of `{id, category, pattern (regex), description, reference}`; hot reloaded like the Policy (mtime for files, ETag/interval for URLs; last good feed kept on error). Ship `policies/signatures.yaml` with: pickle/`torch.load` payload markers, `__reduce__`, `os.system`/`subprocess`/`eval(`/`exec(` in tool args, known malicious model-hub URLs (placeholder list, verify before citing), well-known jailbreak strings.
- **Policy snippet:**
  ```yaml
  attack_signatures:
    mode: block
    description: "Blocks payloads matching known historical attacks (updated from an external feed)."
    params:
      feed: /policies/signatures.yaml
  ```
- **Acceptance tests:** each category has a positive exploit test; Finding cites the signature id; editing the feed file changes behaviour without restart; a broken feed keeps the last good one. Negative: code discussing `eval` in prose at `input` is below threshold or allowed per category config.
- **Dependencies:** core.

## 9. `information_barrier` (stretch)

The M&A ↔ trading Chinese wall, presented as conceptual with synthetic data.

- **Stages:** `tool_result`, `output`.
- **Uses:** `check.user`, `check.agent.team`, and `check.labels` (sensitivity labels on data; Resources or the demo Agent attach them, e.g. `mna:project-falcon`).
- **Params sketch:** `walls: list[{name, sides: [{teams, users, labels}]}]`; a side may not receive content labelled for the other side.
- **Policy snippet:**
  ```yaml
  information_barrier:
    mode: block
    description: "Keeps M&A deal information away from traders (Chinese wall)."
    params:
      walls:
        - name: mna-trading
          sides:
            - {teams: [mna-advisory], labels: ["mna:*"]}
            - {teams: [trading-desk], labels: ["trading:*"]}
  ```
- **Acceptance tests:** a trading-desk Agent receiving an `mna:` labelled tool result → block with the wall name; same content for M&A → allow; unlabelled content → allow.
- **Dependencies:** core; labels need an API field (`labels` is on the Check but not yet accepted by the check API body: add it in this ticket), #10.

## 10. Demo Agent fake tools + synthetic data

- Add tools to the chat's LangGraph Agent: `crm.read_client`, `trading.book_trade`, `wiki.edit`. Each call goes through `FirewallClient.check_tool_call` before and `check_tool_result` after (both already exist). `block`/`review` are enforced by the Agent.
- Synthetic M&A/trading dataset (LLM-generated, clearly fictional names), with PII and card numbers sprinkled in for #1, and labels for #9.
- **Acceptance tests:** a forbidden tool call never reaches the fake Resource; a tool result with PII comes back redacted; the whole demo script (`docs/context/06-judging-playbook.md`) runs on the mock LLM.
- **Dependencies:** core; demo value grows with #1, #7, #9.

## 11. Proxy streaming

- `stream: true` on `/v1/chat/completions`. Run the `input` Check first; buffer the Upstream stream, run the `output` Check, then emit SSE chunks (simple, safe) or chunk-wise with a sliding window for redaction (stretch).
- **Acceptance tests:** an OpenAI SDK streaming client gets the same content as non-streaming; a blocked output never streams a partial leak; usage from the final chunk is recorded.
- **Dependencies:** core proxy.

## 12. Hash-chained audit log + "proof by negation" (stretch)

- Add `prev_hash` and `hash` columns to `audit_events` (sha256 of the canonical JSON of the event + `prev_hash`). Verification endpoint `GET /v1/admin/events/verify` reports the first broken link.
- "Proof by negation": `GET /v1/admin/events/proof?agent_id=&resource=&since=` shows that no allowed Check matched, with the chain head as evidence.
- **Acceptance tests:** an untouched chain verifies; editing one row in the DB is detected; concurrent appends keep a single chain (serialize appends per instance; document the multi-instance caveat).
- **Dependencies:** core storage.

## 13. Post-hoc threat detection

- A job (CLI + admin endpoint) over Audit Events: call volume per Agent vs its baseline (e.g. 10x), spikes of blocks, a new Resource for an Agent, the same User blocked repeatedly, off-hours activity.
- **Acceptance tests:** synthetic event sets trigger each detector; a normal set triggers none.
- **Dependencies:** core storage; shown in #14.

## 14. Dashboard polish: management vs security views

- **Management:** trends, cost and tokens per team/Agent, budget usage (#5), Controls posture.
- **Security:** event drill-down (verdicts, Findings, content per `store_content`), blocked threats list, #13 alerts, export.
- Params editing: render forms from `params_schema` (e.g. the `pii_filter` level slider), Preset switcher (`PUT /v1/admin/policy` with a Preset file).
- **Dependencies:** admin API (exists), #5, #13.

## 15. Architecture diagram

- Required deliverable. Show: Agents (check API and proxy), the one pipeline, Controls in order, Policy file with hot reload, Postgres, dashboard, Upstreams, Resources. Keep it consistent with `CONTEXT.md` names and ADR 0001/0002.
- **Dependencies:** none.

## 16. Latency benchmark script

- `scripts/benchmark.py`: N Checks against an in-process app (ASGI) and against a running firewall, with all Controls off, the deterministic set on, and with the semantic Control on. Report p50/p95 per Control (from Audit Events) and end to end.
- **Acceptance:** one command, prints a table and writes JSON for slides.
- **Dependencies:** core; more meaningful after #1–#4.

## 17. Keep Policy comments on dashboard edits

- `PATCH /v1/admin/controls/{id}` currently re-serializes the YAML and drops comments, which hurts readability for non-engineers. Use `ruamel.yaml` round-trip editing so a mode toggle only changes that line.
- **Acceptance tests:** PATCH a mode in a commented Preset → every comment survives and only the `mode:` line differs.
- **Dependencies:** core admin API.

## 18. Upstream `base_url` from env

- The Presets map `qwen3:4b` to `http://localhost:11434/v1`, which is wrong inside Docker. Allow `${VAR:-default}` expansion in `upstreams[].base_url` (e.g. `${OLLAMA_URL:-http://localhost:11434}/v1`) so the same Policy works locally and in Compose.
- **Acceptance tests:** expansion with and without the env var; no expansion of other fields.
- **Dependencies:** core proxy.
