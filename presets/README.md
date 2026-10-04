# Presets: how strict the firewall is

One line in `policy.yaml` picks the level:

```yaml
preset: strict        # permissive | standard | strict | custom
```

- **`custom`**: the Controls run exactly as written in `policy.yaml`.
- **`permissive`, `standard`, `strict`**: the file of the same name in this folder is laid over
  the Controls of `policy.yaml`. It holds **only what changes** (Modes and limits); everything
  else (Agents, models, folders, data categories) comes from `policy.yaml`.

Save the file: the next request uses the new level, no restart. The console shows the active
preset next to the Policy version.

## What changes between levels

| | permissive | standard | strict |
|---|---|---|---|
| Every Control | records only (`monitor`), blocks nothing | blocks / masks | blocks / masks |
| Personal and payment data in replies and files | recorded | masked: `[EMAIL]`, `[CARD]`, `[IBAN]` | masked |
| ... in what the user types | not checked | not checked | checked too |
| A secret (API key, private key) in a reply or file | recorded | masked | **whole reply blocked** |
| Prompt injection inside a document | recorded | that sentence removed | **whole document refused** |
| Injection model unavailable | requests pass | requests pass | **requests blocked** |
| Links and images to outside domains | recorded | removed (bank domains kept) | all removed |
| Identical requests before the Agent is stopped | 10 (never stopped) | 5, stopped 5 min | 3, stopped 15 min |
| Requests per conversation / run | 100 | 25 | 10 |
| Agent tokens per day | 1,000,000 | 200,000 | 50,000 |
| Forbidden deal code names | `project falcon` (recorded) | `project falcon` | + `project osprey`, `insider list`, `material non-public` |

Folder access (`resource_access.folders`) is the same at every level: who may read what is the
user's decision, not a strictness setting. A preset only decides whether a violation is
recorded (`permissive`) or blocked.

## The Sensitive Data slider

Independent of the preset, in `policy.yaml`:

```yaml
  sensitive_data:
    params:
      level: secrets       # personal < financial < secrets
```

| level | masked |
|---|---|
| `personal` | emails, phone numbers |
| `financial` | + card numbers, IBANs |
| `secrets` | + API keys, tokens, private keys |

Each category in `policy.yaml` names its `group`; a category without one (e.g. `mna_client`,
the client of a live deal) is masked at every level. `permissive` sets the slider to
`personal`, `standard` and `strict` to `secrets`; with `custom` you move it yourself.

Demo script: [`test_suites/manual/presets_demo.md`](../test_suites/manual/presets_demo.md).
