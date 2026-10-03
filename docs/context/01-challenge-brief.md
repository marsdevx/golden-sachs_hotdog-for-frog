# 01. Official challenge brief (authoritative)

Source: `CRIETRIA AI Control Layer.pdf`, plus the teaser in `info_from_site.txt`. Sponsor: **Goldman Sachs**. Event: **HackYeah 2026**. Prize pool: 15,000 PLN.

## Tagline
"Build a flexible AI control layer to secure and govern interactions with Agentic AI systems (AI agents, MCP services, LLMs, APIs). This layer will help organizations protect data, apply required guardrails, manage API budgets, and block emerging exploits while maintaining developer speed. Create the ultimate hybrid defense system for the generative AI era!"

Teaser framing: AI is moving from answering questions to **taking actions**, accessing organisational resources and automating business workflows. This brings sensitive data exposure, unauthorised actions and unpredictable costs. *How can organisations keep control without slowing innovation or developer productivity?*

## 1. Risks named in the brief (examples only; we must go beyond them)
- **Authentication and access control for agents.** Without local enforcement, agents access resources they should not, impersonate other actors, and perform harmful or **irreversible** actions.
- **Input validation / output filtering.** AI interprets natural language as execution logic, so prompt injection is possible. Without output filtering, AI returns sensitive data.
- **Memory and resource consumption.** Persistent context or shared memory enables unauthorised retrieval. Agents get stuck in **runaway loops**. Non-determinism leads to unexpectedly high resource use.
- The layer must **inspect, redact or block unsafe interactions in real time**, using a hybrid of traditional policy enforcement and AI-supported enforcement.
- Explicit instruction: analyse the ecosystem deeply (e.g. **OWASP**) and add the controls a **comprehensive, production-ready** defence needs.

## 2. The task
- Build a **lightweight, flexible AI Control Layer**: a gateway, proxy, middleware or SDK wrapper that intercepts and governs interactions with AI systems.
- Enforce security, privacy and resource controls defined in a **centralised configuration source** (e.g. a "control catalog").
- Generate **reporting for security teams and for management** (UI or otherwise).
- **Hybrid defence architecture:** both non-AI (deterministic) and AI-based (semantic) controls, balancing speed against deep semantic understanding.
- Budgets must work for **both external commercial APIs and locally hosted models**.
- Detect/mitigate **known historical attacks on AI infrastructure**. Signatures can be **fed from an externally managed system**.
- Deliver a **complete, automated test suite** with positive (allowed) and negative (blocked/redacted) cases.

## 3. Expected outcomes (deliverables)
1. **AI Control Layer**: a functional component developers can easily integrate (agent-to-agent, app-to-agent, agent-to-MCP, agent-to-model).
   - a) Build our own demo agent or use an existing one.
   - b) **A simple architecture diagram is required.**
2. **Sample configuration**: a documented policy file showing controls/guardrails, **different strictness/adherence levels**, and **budget rules**.
3. **Simple interactive dashboard**: controls, overall security posture, blocked threats, other metrics (resource consumption/cost).
4. **Executable test suite**: ready to run, verifies the controls, **including budget limits and exploit mitigation**.

## 4. Formal requirements
| # | Requirement |
|---|---|
| R1 | **Centralised Policy Engine**: single config source (file/system) managing controls, sensitivity thresholds (**Block vs Redact**, or **adherence %**), **allowed LLM models**, resource/financial budgets. |
| R2.1 | **Deterministic (non-AI) controls**: e.g. pattern matching (PII, secrets), authentication/access checks. |
| R2.2 | **Semantic (AI-based) controls**: where possible, use AI models to secure the interaction with AI systems. |
| R3 | **Budget and resource governance**: limits on resource access, compute time, token spend. |
| R4 | **Historical attack mitigation**: detect/block patterns of past successful exploits: malicious code execution, unsafe deserialization, supply-chain exploits on model repositories. |
| R5 | **Security reporting and auditing**: real-time metrics (blocked interactions, budget usage) for management, and **exportable audit logs** for security teams (threats, policy violations, usage). Dashboard or otherwise. |
| R6 | **Self-testing suite**: automated, verifying both positive (allowed) and negative (blocked) cases. |

Interpretation (team): a "policy engine" is not only a config file. It is the single source of truth **and** the component that evaluates every request against it. Judges will edit it live, so changes must apply in real time (hot reload).

## 5. Technical requirements
- Any stack (Go, Rust, Python, ...). Built from scratch or on open-source tools. **Check licences.**
- Agents, LLMs and apps that use the layer are **not assessed**.

## 6. Testing / validation by judges
- The evaluation relies on our deliverables and on **spontaneous, zero-preparation actions** by judges.
- Judges **run our automated test suite** (it must contain positive and negative cases).
- Judges **interactively test the running layer** with ad-hoc prompts.
- Judges **modify config files/feeds** (change rules, remove controls, adjust thresholds) to see how changes are reflected and whether they apply in real time.
- We must be able to **produce performance telemetry** (latency overhead etc.).
- Judges review the **architecture, dashboards and logs** meant for management and security teams.

## 7. Available resources
- No datasets, proprietary APIs, hardware or paid subscriptions (OpenAI, Anthropic, Copilot...) are provided.
- Expected to use public open-source libraries, **local models (e.g. Ollama)** and self-created test prompts.
- "Ensure that you can design, build and run the entire system on your own setup."
- Team decision: we may use our own paid APIs, but a local fallback must exist (see `07-decisions-and-open-questions.md`).

## 8. Evaluation criteria (as stated in this brief)
| Criterion | Weight |
|---|---|
| Robustness of the solution and quality of guardrails | 30% |
| Architecture and performance efficiency | 20% |
| Security reporting | 20% |
| Completeness of the self-testing suite | 15% |
| Practical implementability and scalability | 15% |

The legal Rules PDF gives different weights. See `02-competition-rules.md`.
