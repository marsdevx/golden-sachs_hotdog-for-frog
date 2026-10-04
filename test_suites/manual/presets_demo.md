# Demo: presets and the Sensitive Data slider (about 3 minutes)

Shows the judges that strictness is configuration: one line in `policy.yaml`, saved, and the
next message behaves differently. No restart, no code. How presets work:
[`presets/README.md`](../../presets/README.md).

## Setup

```bash
# .env
AGENT_KEY=trading-agent-key
LLM_MODEL=mock
```
```bash
docker compose up -d chat
```

- Chat <http://localhost:8000/>, console <http://localhost:8001/console> side by side.
- Open `policy.yaml` in VS Code (it saves in place, the containers see every save).
- Start from `preset: custom` and `level: secrets` (the committed state).

The file used throughout: `/demo/trading/client_ticket.txt`, a client order on the trader's desk
with a name, an email, a phone, a card, an IBAN and a broker API key (all synthetic).

**Do not rehearse the same command right before the demo.** More than 3 identical requests in
a minute stop the Agent (`loop_detector`), and resetting the breaker does not clear that minute:
wait 60 s, then `curl -X DELETE localhost:8001/v1/settings/breakers/trading-assistant`.

## Act 1: presets (one line, three levels)

Type the same command after each edit:

```
/read_file /demo/trading/client_ticket.txt
```

| Edit in `policy.yaml` | The chat shows | The console shows |
|---|---|---|
| `preset: permissive` | the whole ticket in clear: email, card, IBAN, `sk-ant-...` | `allow`, "recorded without enforcement: sensitive_data (monitor)" |
| `preset: standard` | `[EMAIL]`, `[PHONE]`, `[CARD]`, `[IBAN]`, `[LLM_API_KEY]`; name and order visible | `redact` by `sensitive_data` |
| `preset: strict` | blocked: nothing of the ticket reaches the model | `block` by `sensitive_data` (a secret stops the whole reply) |

Point at the console's Policy chip: `policy <version> · preset strict` changes with every save.
Open `presets/strict.yaml` to show that a level is a short file of differences.

## Act 2: the slider (the mentor's demo)

Set `preset: custom`, then move one value and repeat the same command (wait about 20 s between
steps or the 4th identical read trips `loop_detector`):

```yaml
  sensitive_data:
    params:
      level: personal      # then financial, then secrets
```

| `level` | The chat shows |
|---|---|
| `personal` | `[EMAIL]`, `[PHONE]`; card, IBAN and API key in clear |
| `financial` | + `[CARD]`, `[IBAN]`; API key in clear |
| `secrets` | + `[LLM_API_KEY]` |

"A new regulation says X is sensitive" is one more category under `categories:`, e.g.
`- {name: pesel, patterns: ['\b\d{11}\b'], validator: pesel_checksum}`, saved the same way.

## Act 3 (optional): the barrier does not depend on the level

At any preset, `/read_file /demo/mna/falcon_term_sheet.txt` is refused for the trader: folder
rules are the user's own decision, the preset only decides whether a violation is recorded
(`permissive`) or blocked. Full M&A scenario: [`mna_trading.md`](mna_trading.md).

## Reset

Set `preset: custom` and `level: secrets` again, or `git checkout policy.yaml` followed by
`docker compose up -d --force-recreate firewall firewall-console` (git replaces the file, and
the single-file mount does not see a replaced file).
