# AI Control Layer

An AI firewall that sits between internal agents, LLMs and resources (MCP servers, databases, APIs) and governs every interaction against one centrally managed Policy.

## Language

### Configuration

**Policy**:
The single, versioned configuration document that is the source of truth for which Controls run, how strictly, and for which Agents.
_Avoid_: config, rules file, control catalog

**Control**:
One pluggable check with an id, the Stages it runs at, a Mode and its own parameters (e.g. `pii_filter`, `token_budget`).
_Avoid_: guardrail (pitch-only word), rule, filter, plugin

**Mode**:
How strictly a Control is enforced, set per Control in the Policy: `off`, `monitor` (record only), `redact` or `block`.
_Avoid_: level, severity, strictness

**Preset**:
A complete ready-made Policy at a given strictness (`permissive`, `standard`, `strict`).
_Avoid_: profile, template

### Evaluation

**Stage**:
The point in an interaction where Controls run: `input` (to the LLM), `output` (from the LLM), `tool_call` (to a resource) or `tool_result` (from a resource).
_Avoid_: hook, phase, direction

**Check**:
One evaluation of one Stage of one interaction against the current Policy.
_Avoid_: scan, inspection, request

**Verdict**:
What a single Control returns for a Check: action, reason, risk score, findings and optionally rewritten content.
_Avoid_: result, control decision

**Decision**:
The combined outcome of all Verdicts in a Check, which the caller must enforce; the most severe action wins (`block` > `review` > `redact` > `allow`).
_Avoid_: verdict, response

**Finding**:
One concrete thing a Control detected (e.g. an email address at a position, a matched signature).
_Avoid_: violation, hit, match

### Actors

**Agent**:
A calling identity (an AI agent or app) known to the Policy by its key, always attributable to an Owner.
_Avoid_: client, caller, bot

**Owner**:
The person or team accountable for an Agent.
_Avoid_: user, developer

**User**:
The human on whose behalf an Agent is acting, when known.
_Avoid_: asker, requester, owner

**Resource**:
Anything an Agent acts on through a tool call: an MCP server, database, or API.
_Avoid_: tool, service, backend

### Evidence

**Audit Event**:
The immutable record of one Check: who, what, which Controls ran, the Decision, and the Policy version.
_Avoid_: log line, log entry, record

### Routing

**Upstream**:
An OpenAI-compatible LLM endpoint the firewall forwards to in proxy mode, mapped from model names in the Policy.
_Avoid_: provider, backend, LLM server
