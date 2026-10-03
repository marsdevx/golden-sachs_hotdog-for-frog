# 05. Feature scope

Source: `our features.txt` (team's list), mapped to the official requirements (R1-R6, see `01-challenge-brief.md`).

## Team feature list
### Dashboard
- **Metrics gathering**: token spend, response times. → R5, perf telemetry
- **Interaction logging**: full input and output logs. → R5 (audit), compliance evidence
- **Threat detection**: post-analysis tooling over logs to detect dangerous patterns and policy violations. → R5, mentor's "post-hoc analysis" idea

### Guardrails
- **Input validation**: prompt-injection protection, filtering malicious user prompts. → R2.1 + R2.2
- **Output filtering**: removing sensitive data (personal data, credit/card data) from agent responses. → R2.1 (regex/PII) + R1 (Block vs Redact). This is the mentor's checkbox+slider demo.
- **Token-spend rate limiting**: prevent runaway costs and infinite loops. → R3

### Control
- **Resource access control**: restrict access to specific databases, APIs, MCP servers.
  - Defined in a **config file with hard restrictions**. The AI has **no access unless explicitly allowed** (default deny). Resources effectively live in separate environments. → R2.1, CISO read/write boundary
- **Dynamic policy controls**: toggles and sliders for IT teams to switch features on/off **without changing developer code**. → R1 + hot reload (judges edit config live)

### Integrations
- **Modular architecture**: pluggable support for different LLMs (Claude, Gemini, local models). → R3 (budgets for both commercial and local), mentor's modularity advice

## Coverage check against requirements
| Req | Covered by | Gap / to do |
|---|---|---|
| R1 policy engine | Dynamic policy controls, config file | Must include: Block/Redact/Allow modes, adherence % thresholds, **allowed-models list**, budgets. **Hot reload.** Sample config with **several strictness levels** (e.g. `permissive` / `standard` / `strict` presets). |
| R2.1 deterministic | Output filtering (regex PII), access control | Add **secrets detection** (API keys, tokens), identity check (which agent/owner is calling: API key per agent). |
| R2.2 semantic | Input validation | Use an LLM classifier (local via Ollama + optional cloud) for injection/jailbreak/intent. Configurable threshold. Fail-safe behaviour when the classifier is down. |
| R3 budgets | Token-spend rate limiting | Per-agent / per-team budgets in tokens **and** money; works for local models too (count tokens/compute time, not only provider bills); loop detection (repeated similar calls). |
| R4 historical attacks | **NOT COVERED** | Signature feed (externally managed file/URL, hot-reloaded): e.g. pickle/unsafe deserialization payloads, `os.system`/`eval`/shell in tool args, malicious model-repo URLs, known jailbreak strings. Needs tests. |
| R5 reporting | Dashboard, logging, threat detection | **Exportable** audit log (JSONL/CSV), security posture view, blocked threats list, budget usage. Every entry: agent, owner, rule fired, action, reason. Tamper evidence (hash chain) is a cheap compliance win. |
| R6 tests | **NOT LISTED** | Positive + negative case for **every** control, plus budget-limit tests, exploit tests, hot-reload test. One command to run. |
| Architecture diagram | **NOT LISTED** | Required deliverable. |

## Priority (follow the mentor: one control excellent, others present)
1. Proxy skeleton + central policy engine with hot reload + audit log (everything else depends on these).
2. **Showcase control** (do it really well): output filtering / sensitive-data control with Block vs Redact and a strictness slider (PII → + credit data → + secrets), or the information-barrier control (M&A vs trading). Decide in `07`.
3. Input validation (deterministic + semantic), token budgets + loop detection, resource access control (default deny, read vs write).
4. R4 signature feed.
5. Dashboard, test suite, diagram, slides. Test suite and dashboard together are worth 35-40%, so don't leave them to the last hour.
