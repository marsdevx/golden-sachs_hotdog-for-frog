# Test suites (acceptance layer)

The judge-facing suite. `tests/` holds the core's unit and integration tests (one team member's job per Control, see `docs/CONTRIBUTING-controls.md`). This folder holds the **acceptance suites**: every requirement R1-R6 proven end to end through the real Policy Presets, with a positive and a negative case per Control, budgets, exploit mitigation, hot reload, audit and latency.

Status: **plan only, no test code yet.** This file is the catalog to agree on first.

## Principles

- **Runs offline, no keys.** In-process ASGI app, temp Policy, temp SQLite, built-in `mock` model (it echoes the last user message) or an `httpx.MockTransport` upstream for canned replies. One command, one report.
- **Test-first for Controls that do not exist yet.** A test marked `needs("injection_heuristics")` is skipped with "control not implemented yet" until the Control is registered, then runs by itself. The report lists what is still skipped.
- **Scenarios load the real Policy** (`policy.yaml`) and change Modes by writing a temporary copy of the Policy file (no API writes the Policy). Renaming a param does not break the suite.
- **Data apart from code.** Attack strings, card numbers, exploit payloads live in `data/*.yaml`. Adding a judge's idea is one line.
- **Every test carries** a requirement (`R1`-`R6`), a priority (`P0` must pass, `P2` stretch) and the stakeholder it serves (see the use-case matrix).
- **Block vs redact assertions:** on `block` the caller must enforce, the returned content is not cleaned, so assert `decision.action` and `reason`. On `redact` assert the returned content no longer holds the value.
- **Blocks are HTTP 200** (`finish_reason: "content_filter"` in the proxy, `decision.action` in the check API), not 403.

## Layout (planned)

```text
test_suites/
  README.md              this catalog
  harness/               fixtures: app on temp Policy, clients, events, report plugin
  data/                  pii.yaml, secrets.yaml, injections.yaml, exploits.yaml
  smoke/                 10-second "is it alive" checks
  functional/            one file per Control
  integration/           multi-Control scenarios, the demo script
  policy_and_audit/      hot reload, Presets, judge edits, audit, export
  performance/           latency p50/p95
  live/                  optional, real Ollama or cloud key, skipped by default
```

Commands (planned): `make test-acceptance`, `make smoke`, `make test-perf`, `make test-live`. `make test` keeps running `tests/` only.

## Catalog

"Now" = runs today with the core and the Controls already built. "Ticket n" = needs that backlog ticket; skipped until it lands. "Done (…)" = the Control exists; unit tests named there already cover these cases, the acceptance version is still to write.

### A. Smoke (P0, Now)

| ID | Test | Req |
|---|---|---|
| SM-01 | Firewall and chat health endpoints answer | R6 |
| SM-02 | Clean request through the proxy passes unchanged, `firewall` object present | R2 |
| SM-03 | Forbidden phrase is blocked with a reason before the model is called | R2.1 |
| SM-04 | Both checks (allowed and blocked) appear as Audit Events | R5 |
| SM-05 | Policy is readable through the settings API | R1 |

### B. Functional, per Control (positive + negative + monitor, per supported Stage)

| ID | Control | Cases | Needs |
|---|---|---|---|
| FN-KW | `keyword_blocklist` | allow, block, redact, monitor, case-insensitive, empty list | Now |
| FN-PII | `sensitive_data` (personal and payment categories) | email, phone, national id, IBAN, Luhn card; obfuscated (spaces, dashes, `[at]`, full-width digits); non-Luhn 16 digits and normal prose untouched; Findings hold type and span, never the value; switching categories with `enabled` | Done (`tests/test_sensitive_data*.py`) |
| FN-SEC | `sensitive_data` (secret categories) | AWS, GitHub, OpenAI, Anthropic, private key, JWT; UUID, git SHA, base64 image not flagged. Not covered: secrets in `tool_call` args (Stage not supported) | Done (`tests/test_sensitive_data*.py`) |
| FN-INJ | `injection_heuristics` | "ignore previous instructions" en/pl/de/es, base64, role spoofing, injection inside `tool_result`; benign: "ignore the typo", "what is prompt injection" | Ticket 3 |
| FN-CLS | `injection_classifier` | mock backend above/below threshold; backend down with `on_error` block and allow; timeout respected | Ticket 4 |
| FN-BUD | `token_budget` | under budget allows; over tokens blocks the next input; per-user and per-run limits; `warn_at` warning before the block; Agents isolated; same result via check API and proxy. (Money budgets and team totals were dropped by team decision.) | Done (`tests/test_token_budget.py`) |
| FN-LOOP | `loop_detector` | similar input over `max_similar` blocked; same count spread over time allowed; Agents isolated; repeated `tool_call` caught; circuit breaker opens and is reset through the settings API | Done (`tests/test_loop_detector.py`) |
| FN-LIM | `request_limits` | too many messages and oversized prompt blocked without quoting it; `max_tokens` above the ceiling lowered (check API and proxy); long reply and long tool result truncated; oversized tool args blocked | Done (`tests/test_request_limits.py`) |
| FN-RES | `resource_access` | path outside every folder blocked (default deny); read allowed, write blocked in a read-only folder; deeper `none` wins; `..` traversal blocked; Windows paths; reason names the rule | Done (unit tests in `tests/test_resource_access.py`) |
| FN-SIG | `attack_signatures` | pickle / `torch.load`, `__reduce__`, `os.system`, `eval`, shell, `trust_remote_code`, malicious model URL, known jailbreak; benign `weights_only=True`, `evaluate_model(...)`; Finding cites the signature id and OWASP ASI code | Done (`test_suites/functional/test_uc07_historical_attacks.py`, data in `data/exploits.yaml`) |
| FN-BAR | `information_barrier` | trading agent gets an M&A-labelled result blocked; M&A agent allowed; unlabelled allowed | Ticket 9 (+ `labels` in check API) |

### C. Integration (P0 for the demo)

| ID | Test | Req | Needs |
|---|---|---|---|
| IN-01 | **Category demo:** same agent, no code change: all Controls off leaks; enabling the `email` category redacts email; `card` also redacts card; a secret category blocks a key | R1, R2.1 | Now |
| IN-02 | Defense in depth: cheap deterministic Control decides first, semantic one is not called | R2.1/2.2 | Ticket 3, 4 |
| IN-03 | Incident 1, information barrier: trader never receives M&A data, audit shows who asked and which rule fired | R2.1, R5 | Ticket 9, 10 |
| IN-04 | Incident 2, unauthorised access: the AI reading a `none` folder or writing outside its folders is blocked and the file tool never runs | R2.1 | Ticket 7 (done), 10 |
| IN-05 | Incident 3, cost loop: repeated calls stop, budget block carries the owner | R3 | Now |
| IN-06 | The 8-step demo script from `docs/context/06-judging-playbook.md` end to end on the mock model | all | Ticket 1, 3, 7, 10 |
| IN-07 | Indirect injection: injection inside a `tool_result` is stopped before the next model call | R2.1, R4 | Done via `attack_signatures` (`test_uc07_historical_attacks.py`); deeper heuristics in Ticket 3 |
| IN-08 | Tool calls are not checked by the proxy (documents the known gap; model `tool_calls` return an upstream error) | R2.1 | Now |

### D. Policy, Presets and audit

| ID | Test | Req | Needs |
|---|---|---|---|
| PA-01 | Hot reload: block to monitor to off changes the next request, no restart | R1 | Now |
| PA-02 | Broken YAML keeps the last good Policy and reports `last_error`; the service stays up | R1 | Now |
| PA-03 | Judge edits: remove a Control, change a threshold, change a Mode, add an Agent, narrow `allowed_models`; each takes effect on the next request | R1 | Now (grows with Controls) |
| PA-04 | Strictness ladder: one fixed attack set run on `permissive`, `standard`, `strict`; blocks never decrease with strictness | R1 | Ticket 1-4 |
| PA-05 | Unknown or missing agent key follows `defaults.unknown_agent` both ways; owner and team recorded | R2.1 | Now |
| PA-06 | `allowed_models`: other model blocked, reason names the model | R1 | Now |
| PA-07 | Fail behaviour: a Control that raises follows `on_error` block and allow, per Control override | R2.2 | Now |
| PA-08 | Every denial names the Control, the Finding type and position; the sensitive value is never in `reason` | R2 | Now |
| PA-09 | Audit: one Event per Check including allowed; required fields present; filters work | R5 | Now |
| PA-10 | Audit never stores a raw secret or card number in `redacted` and `none` modes | R5 | Now |
| PA-11 | Export: JSONL and CSV parse, row counts match, filters apply | R5 | Now |
| PA-12 | Metrics: totals by action, Control and Agent match the events; p50/p95 present | R5 | Now |
| PA-13 | Hash-chained log verifies, an edited row is detected; proof by negation | R5 | Ticket 12 (stretch) |
| PA-14 | Post-hoc detection flags a 10x volume spike, none on normal traffic | R5 | Ticket 13 |

### E. Performance (P1)

| ID | Test | Req | Needs |
|---|---|---|---|
| PF-01 | Overhead: p50/p95 of the proxy path vs the same call straight to the mock upstream, all Controls off | R6 | Now |
| PF-02 | p50/p95 with the deterministic set on, and with the semantic Control on (mock backend) | R6 | Ticket 1-4 |
| PF-03 | Per-Control latency from Audit Events; result written to `reports/latency.json` | R5 | Now |
| PF-04 | Concurrent requests (e.g. 50 at once) keep correct decisions and counters | R3 | Now |

### F. Live (optional, skipped without Ollama or a key)

| ID | Test | Needs |
|---|---|---|
| LV-01 | Proxy to a real Ollama model, same base_url change as the demo ("Monday rollout") | Ollama running |
| LV-02 | Real classifier separates a real attack from a benign question | Ticket 4 + Ollama |
| LV-03 | Cloud model through the `openai_compatible` adapter | an API key in the env |

## Report

`make test-acceptance` writes `reports/acceptance-summary.md`: pass, skip and fail counts per requirement R1-R6 and per suite, plus the list of skipped tests with the missing Control. This is the slide material and the honest status for judges.

## Open points for the team

1. The proxy rejects a model reply that contains `tool_calls`; tool Checks exist only through the check API. Keep, or open a ticket?
2. `labels` is not accepted by the check API yet (Ticket 9).
3. Who owns `tests/` vs `test_suites/`, and which branch (`feature/acceptance-suite`)?
4. Controls devs: please reuse `data/*.yaml` cases in your own unit tests so both layers agree.
