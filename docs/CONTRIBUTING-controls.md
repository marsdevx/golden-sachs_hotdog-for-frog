# Add a Control in 15 minutes

A **Control** is one pluggable check with an id, the Stages it runs at, a Mode and its own parameters (see `CONTEXT.md`). You add one without touching the core: **one file, one import line, one test file, and a section in the three Presets.**

The reference Control is `firewall/firewall_app/controls/keyword_blocklist.py`, and its test `tests/test_keyword_blocklist.py` is the template. Copy both.

## 1. The file

`firewall/firewall_app/controls/my_control.py`:

```python
from __future__ import annotations

from pydantic import BaseModel, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Content, Finding, Stage, Verdict


@control("my_control")                       # the id used in policy.yaml
class MyControl(Control):
    stages = {Stage.input, Stage.output}      # the Stages this Control supports
    description = "One sentence a non-engineer understands."

    class Params(BaseModel):                  # validated when the Policy loads
        threshold: float = Field(0.5, ge=0, le=1)
        words: list[str] = Field(default_factory=list)

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        text = check.message.content if check.stage == Stage.output else ""
        if "bad" not in text:
            return Verdict()                  # allow, no findings
        return Verdict(
            action=Action.block,
            reason="contains 'bad'",          # shown to the Agent and in the audit log
            risk_score=0.8,
            findings=[Finding(control=self.id, type="bad_word", detail="output contains a bad word",
                              span=(text.index("bad"), text.index("bad") + 3))],
            rewritten=Content(message=check.message.model_copy(
                update={"content": text.replace("bad", "[REDACTED]")})),
        )
```

## 2. Register it

Add one line to `firewall/firewall_app/controls/__init__.py`:

```python
from firewall_app.controls import keyword_blocklist, my_control  # noqa: F401
```

## 3. The Policy section

Add a section to **all three** Presets in `policies/` (`permissive`, `standard`, `strict`). Position matters: Controls run top to bottom, and redactions by earlier Controls are what later Controls see. Put cheap deterministic Controls before slow semantic ones.

```yaml
controls:
  my_control:
    mode: block               # off | monitor | redact | block
    stages: [output]          # optional; must be a subset of the supported stages
    on_error: block           # optional; else defaults.on_error
    description: "One sentence a non-engineer understands."
    params:
      threshold: 0.7
```

Typical strictness: `permissive` → `monitor`, `standard` → `block` or `redact`, `strict` → `block` with tighter params. The firewall refuses to load a Policy with an unknown Control id, unknown or invalid `params`, or unsupported `stages` (and keeps the last good Policy if it is already running).

## 4. What a Check carries, per Stage

| Stage | Read from the Check | Rewrite with |
|---|---|---|
| `input` | `check.messages` (the whole conversation sent to the LLM) | `Content(messages=[...])` |
| `output` | `check.message` (the LLM reply), `check.usage` (model, tokens) | `Content(message=...)` |
| `tool_call` | `check.tool` (`resource`, `action`, `args`) | `Content(tool=...)` |
| `tool_result` | `check.tool` + `check.tool_result` (what the Resource returned) | `Content(tool_result="...")` |

Always available: `check.agent` (`id`, `owner`, `team`), `check.user`, `check.labels` (reserved for the information barrier), `check.metadata`, `check.check_id`.

## 5. Return a Verdict

- `action`: `allow`, `redact`, `review` or `block`. Return what the Control *would* do; the pipeline applies the Mode:
  - `monitor`: always `allow`, but your Verdict and Findings are recorded.
  - `redact`: a non-allow Verdict becomes `redact` **only if you returned `rewritten`**, else `allow`.
  - `block`: your action as is.
  So return `rewritten` content whenever you can; it makes your Control usable in `redact` Mode for free.
- `reason`: short, human-readable. The pipeline prefixes the Control id ("Blocked by my_control: ...").
- `risk_score`: 0..1.
- `findings`: one `Finding` per concrete thing detected (`type`, `detail`, optional `span`).
- Do not set `control`, `effective_action`, `mode` or `latency_ms`: the pipeline stamps them.
- If `evaluate` raises, the pipeline turns it into a Verdict per `on_error` (`"control error: <Type>"`). Don't swallow errors to "fail open"; let the Policy decide.

## 6. Tests

Copy `tests/test_keyword_blocklist.py` to `tests/test_my_control.py`. Required:

- For **every supported Stage**: at least one allowed case and one blocked (or redacted) case, calling `evaluate` directly.
- A `monitor` Mode case through `run_check` (the Decision is `allow`, the raw Verdict is not).
- If you return `rewritten`: a `redact` Mode case asserting the content the caller gets back (`result.after`).
- Tests run offline: no network, no API keys. Mock any model call (see the `injection_classifier` ticket in `docs/backlog.md`).

Run `uv run pytest tests/test_my_control.py tests/test_policy.py -q` (the Preset test checks your new sections load) and `uv run ruff check .`.

## Do's and don'ts

- **No state in module globals.** Controls are instantiated per Check. State (budget counters, history for loop detection) goes through the injected store: `self.ctx.db` is an SQLAlchemy `async_sessionmaker`. Use portable SQL only (ADR 0002).
- **Never branch on `check.transport`.** It exists for the audit log. A Control must behave the same for the check API and the proxy (ADR 0001).
- **Read token usage from `check.usage` only**, whichever transport filled it.
- **Never put the sensitive value itself in `reason` or `detail`** (e.g. say "credit card number at 12..28", not the number). Decisions are returned to the Agent and stored.
- **Use the glossary** (`CONTEXT.md`): Finding, not violation; Verdict, not result; Resource, not tool; Agent and Owner, not client and user.
- Keep `evaluate` fast; the pipeline measures `latency_ms` per Control and it shows up on the dashboard.
- Policy edits from the dashboard (`PATCH /v1/admin/controls/{id}`) re-serialize the YAML and **drop comments**. Keep important explanations in `description`.
