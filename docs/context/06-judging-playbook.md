# 06. Judging playbook

How to turn the criteria into concrete things judges can see. Weights: see `02-competition-rules.md` (test suite may be 15% or 20%).

## Criterion → evidence checklist
### Robustness and quality of guardrails (30%)
- [ ] Hybrid: deterministic fast path first, semantic (LLM) check second, only when needed (cheap and fast).
- [ ] Each control has modes **allow / redact / block / flag (log only)** and a threshold, all in config.
- [ ] Survives ad-hoc judge prompts: obfuscated PII (spaces, dashes), base64/encoded injections, multilingual injections, indirect injection inside tool/MCP results, not only user input.
- [ ] Default deny for resources. Read vs write/irreversible distinction. Risk-weighted actions (book trade >> edit wiki).
- [ ] Clear fail behaviour if the semantic model is down (configurable fail-open vs fail-closed).
- [ ] Every block returns an **explanation**: rule id, reason, what was attempted.

### Architecture and performance efficiency (20%)
- [ ] Simple architecture diagram (required).
- [ ] Latency overhead measured and shown (p50/p95 per control, with and without semantic check).
- [ ] Transparent integration: agent only changes its base URL / endpoint (OpenAI-compatible API is the easiest drop-in).
- [ ] Pluggable provider adapters (Claude, Gemini, Ollama) and pluggable controls (a control = small module with a common interface).

### Security reporting (20%)
- [ ] Dashboard: security posture, active controls (toggles), blocked threats, budget usage per agent/team, cost, latency.
- [ ] **Exportable** audit logs (JSONL/CSV): timestamp, agent, owner, user, model, request/response (or redacted), rules evaluated, decision, reason, tokens, cost, latency, policy version.
- [ ] Separate views for **management** (numbers, trends, cost) and **security** (events, details, export).
- [ ] Post-hoc threat-detection pass over logs (anomalies, e.g. call volume 10x baseline).
- [ ] Optional strong differentiator: tamper-evident log (hash chain) and "proof by negation" query.

### Completeness of self-testing suite (15-20%)
- [ ] One command runs everything (e.g. `make test`), readable output.
- [ ] For **each** control: ≥1 allowed case and ≥1 blocked/redacted case.
- [ ] Budget-limit tests (exceed tokens/cost/rate → blocked). Loop-detection test.
- [ ] Exploit-mitigation tests (R4 signatures: deserialization, code execution, malicious repo).
- [ ] **Hot-reload test**: change config at runtime → behaviour changes without restart.
- [ ] Tests run without paid API keys (mock or local model for semantic checks).

### Practical implementability and scalability (10-15%)
- [ ] "Monday rollout" story: docker compose up, point agents at the gateway, done.
- [ ] Config is readable by non-engineers (comments, plain-language rule descriptions).
- [ ] Scaling story: stateless proxy instances + shared state for budgets/logs; central gateway or micro-gateways next to resources.

## Demo script (live pitch, matches mentor's suggested shape)
1. Show the architecture diagram (30 s).
2. Agent works through the layer with **all controls off**: leaks PII, obeys an injection, calls a forbidden tool.
3. IT person toggles **output filtering** on → PII redacted. Moves slider to stricter → credit card data also redacted. No agent code changed.
4. Enable **input validation** → injection blocked, with explanation.
5. Enable **resource access control** → forbidden DB/MCP call denied (write blocked, read allowed).
6. Trigger a **runaway loop** → budget/rate limit stops it, alert on dashboard.
7. Show the use-case story (M&A ↔ trading information barrier, synthetic data) in the audit log: who asked, what was read, which rule fired.
8. Run the test suite live. Show the export of audit logs.

## Threat reference (from model knowledge; verify against owasp.org before citing in slides)
OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data and Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector and Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.
OWASP also publishes agentic-AI threat guidance (e.g. tool misuse, memory poisoning, privilege compromise, identity spoofing). Check the current version.

Historical attack classes for R4 signatures: unsafe deserialization of model files (Python pickle in `.pt`/`.pkl`, `torch.load`), malicious models uploaded to public model hubs, code execution via LLM-generated code / tool args (`eval`, `exec`, `os.system`, `subprocess`), exposed AI infra (e.g. unauthenticated Ray clusters, "ShadowRay"), known jailbreak strings. **Verify specific CVE numbers before using them.**
