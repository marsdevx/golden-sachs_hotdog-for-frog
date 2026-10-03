# 07. Decisions and open questions

Keep this file current. Add a dated line whenever the team decides something (stack, architecture, showcase control, demo scenario).

## Decisions made
| Date | Decision | Why |
|---|---|---|
| 2026-10-03 | Everything (code, docs, UI, slides) in English | Challenge requirement |
| 2026-10-03 | We may use our own paid APIs (Claude, Gemini...) | Team decision (from `stakeholders.md`). The brief says no paid subscriptions are provided and the system must run on our own setup, so **keep a local Ollama path** for every AI-based control and make tests runnable without keys. |
| 2026-10-03 | Scope is internal (employees/internal agents), not external attackers | Mentor guidance |
| 2026-10-03 | Resource access is default-deny, set by hard restrictions in config | `our features.txt` |
| 2026-10-03 | Main use case candidate: M&A ↔ trading information barrier, with LLM-generated synthetic data, presented as conceptual | Mentor called it "a really good use case" |

## Not decided yet
- [ ] Tech stack (language, proxy framework, dashboard framework, storage for logs/budgets).
- [ ] Integration surface: OpenAI-compatible HTTP proxy? MCP proxy? SDK wrapper? (Mentor values transparent, zero-code integration.)
- [ ] Which control is the "really, really good" showcase: output filtering with strictness slider, or the information-barrier control?
- [ ] Config format (YAML?) and hot-reload mechanism (file watcher vs dashboard writes to config).
- [ ] Semantic classifier model (local: which Ollama model; cloud: which provider).
- [ ] Format and source of the R4 external signature feed.
- [ ] Demo agent: build our own or use an existing one.

## Open questions for mentors
- Scoring weights conflict: test suite 15% (brief) vs 20% (rules)? Practicality 15% vs 10%?
- Do judges run the project on their own machines or watch it on ours? Are external API keys acceptable?
- Prevention or provability: which matters more for evaluation?
- How are information barriers currently implemented for AI assistants?
- Which existing products have they tried, and why were they not enough?
- Who signs off on buying such a solution: CISO, compliance, platform?
- Rules PDF says work starts "no earlier than 11:00 PM on October 3rd". Confirm that's a typo (11:00 AM).

## Core architecture decisions (2026-10-03, grilling session)
| Date | Decision | Why |
|---|---|---|
| 2026-10-03 | One transport-agnostic Check pipeline with two adapters: check API (4 Stages) + OpenAI-compatible proxy | ADR 0001 |
| 2026-10-03 | Stages: `input`, `output`, `tool_call`, `tool_result` | Covers LLM and resource interactions incl. indirect injection |
| 2026-10-03 | Policy = `policy.yaml`, Pydantic-validated, mtime hot reload, last-good on error; Presets `permissive`/`standard`/`strict` as full files | Judges edit config live |
| 2026-10-03 | Agent identity via `X-Agent-Key` header mapped in the Policy to agent + Owner | CISO: owner per agent |
| 2026-10-03 | Storage: SQLAlchemy async, Postgres in Compose, SQLite in tests | ADR 0002 |
| 2026-10-03 | Dashboard is a separate Streamlit service over the firewall admin API | Independent ownership |
| 2026-10-03 | Showcase Control: output filtering with strictness levels; `user` and `labels` on the Check from day 1 so the information barrier can be added later | Mentor's demo sketch |
| 2026-10-03 | Vocabulary fixed in `CONTEXT.md` (Policy, Control, Mode, Check, Verdict, Decision, Finding, Agent, Owner...) | Shared language across devs |
