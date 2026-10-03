# The core, in plain words

This is the base everyone builds on. You should **not** need to change it. You add your feature as a **Control** (one small file), or you work on the dashboard, the demo or the docs.

Words like Policy, Control, Check and Decision have exact meanings. They are in [`CONTEXT.md`](CONTEXT.md). Please use them.

## What it does

The firewall sits between an AI Agent and the LLM (and the tools the Agent uses). Every message passes through it. For each message it:

1. Finds out **who is calling** from the agent key (`X-Agent-Key` header).
2. Runs the **Controls** that are switched on, one after another.
3. Returns a **Decision**: `allow`, `redact`, `review` or `block`, with a reason.
4. Saves an **Audit Event** in the database, for every message, even allowed ones.

## The 4 Stages

A Check happens at one of four points:

| Stage | What is checked |
|---|---|
| `input` | messages going **to** the LLM |
| `output` | the answer coming **from** the LLM |
| `tool_call` | the Agent wants to use a Resource (CRM, database, API) |
| `tool_result` | what the Resource sent back |

## Two ways to connect an Agent

- **Check API:** the Agent asks the firewall itself: `POST /v1/check/{stage}`. This works for all 4 Stages. The demo chat uses this.
- **Proxy:** the Agent just changes its OpenAI `base_url` to the firewall. The firewall checks the input, calls the LLM, and checks the output. This only covers `input` and `output`.

Both run the same Controls. A Control never knows which way the message came in.

## The Policy file

`policies/standard.yaml` controls everything:

- which Controls run, and **in which order** (top to bottom)
- each Control's **Mode**:
  - `off`: does not run
  - `monitor`: only records, never blocks
  - `redact`: hides the bad part, the message goes through
  - `block`: stops the message
- each Control's settings (`params`)
- the known Agents and their Owners, the allowed models, the LLM addresses

**Save the file and the change is live on the next message. No restart.** If you save a broken file, the firewall keeps the last good version and shows the error.

There are 3 ready-made Presets: `permissive.yaml`, `standard.yaml`, `strict.yaml`.

## What is in the repo

| Folder | What |
|---|---|
| `firewall/` | the firewall (port 8001) |
| `chat/` | a demo chat Agent that uses the firewall (port 8000) |
| `dashboard/` | Streamlit dashboard: switch Controls, see events and metrics (port 8501) |
| `policies/` | the Policy files |
| `tests/` | all tests |
| `docs/` | guides, backlog, decisions |

Inside `firewall/firewall_app/`, the parts you will touch:

- `controls/`: **this is where your Control goes**
- `controls/keyword_blocklist.py`: the example Control. Copy it.
- `domain.py`: the data shapes (Check, Verdict, Finding...)

You should not need to change the rest: the pipeline, the Policy loader, storage and the APIs.

## Run it

Everything with Docker:

```bash
docker compose up --build
```

Then open the dashboard at http://localhost:8501 and send a test message:

```bash
curl -s localhost:8000/v1/chat -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Any news on Project Falcon?"}]}'
```

It is blocked by the example Control. Set it to `monitor` in the dashboard and send it again: now it passes.

If a port is already in use, set `CHAT_PORT`, `FIREWALL_PORT` or `DASHBOARD_PORT` in `.env`.

Tests (no Docker, no internet, no API keys needed):

```bash
uv run pytest
uv run ruff check .
```

## Add your feature

1. Pick your ticket in [`docs/backlog.md`](docs/backlog.md).
2. Follow [`docs/CONTRIBUTING-controls.md`](docs/CONTRIBUTING-controls.md). In short:
   - one new file in `firewall/firewall_app/controls/`
   - one import line in `controls/__init__.py`
   - one test file (copy `tests/test_keyword_blocklist.py`)
   - one section in each of the 3 Presets
3. Run the tests, then open a pull request.

## Rules

- **Don't keep state in global variables.** Use the database through `self.ctx.db`.
- **Don't check how the message arrived** (`check.transport`). It is only for the audit log.
- **Don't put secrets or personal data in the `reason`** of your Control. Say what you found, not the value itself.
- **Tests must work offline.** Mock any LLM call.
- **Return the cleaned content** (`rewritten`) when you can. Then your Control also works in `redact` Mode.

## Known limits

- Changing a Control in the dashboard removes the comments from the Policy file (backlog #17).
- In Docker, the proxy can't reach Ollama with the current Presets. Use `model: mock` for now (backlog #18).
- The proxy does not support streaming yet (backlog #11).

## More

- [`README.md`](README.md): full details and the API contract
- [`CONTEXT.md`](CONTEXT.md): the glossary
- [`docs/adr/`](docs/adr/): why it is built this way
- [`docs/implementation-plan-core.md`](docs/implementation-plan-core.md): how the core was built, with every decision
