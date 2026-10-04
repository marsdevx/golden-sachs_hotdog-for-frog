# Manual test cases: `/list_files`, `/read_file` and `/delete_file`

Manual checks of the tool demo through the chat. Each case has a command to type, the
expected reply and what to look for in the console.

## Setup

```bash
LLM_MODEL=mock docker compose up -d --build          # standard Preset (default)
```

- Chat: <http://localhost:8000/>. Console: <http://localhost:8001/console>.
- The firewall runs `policy.yaml` (repository root). For a looser or stricter run, change Modes in it.
- Mock only: the chat must receive the command exactly as written (one space, no extra text).
  Any other text is not a tool call and just comes back as `Mock response: ...`.
- For each case, copy the `run_id` from the reply into **Console → Agent runs → Load steps**.

Demo files (`firewall/firewall_app/demo_data`, shown to the AI as `/demo`):

```text
/demo/README.txt
/demo/contacts.txt          alice@example.com, +48 600 123 456
/demo/private/internal.txt  must never be read on standard / strict
/demo/sandbox/scratch.txt   the only file that can be deleted
```

After a successful delete, restore the file:
`git checkout firewall/firewall_app/demo_data/sandbox` (local run) or `docker compose up -d --build` (Docker).

How to read a result:

- **Allowed**: the reply holds the file list or the file text. Audit shows
  `input, output, tool_call, tool_result, input, output`, and `tool_result` has `execution: succeeded`.
- **Blocked before execution**: `output_decision.action = block`, step `executed: false`,
  `result_check_id: null`. No `tool_result` event.
- **Blocked after execution**: `executed: true` but nothing released, `tool_result` is `null`.
  `tool_result` event has `execution: failed` (error) or `action: block` (content).

## A. `/list_files` on the standard Preset

| ID | Command | Expected |
|---|---|---|
| LF-01 | `/list_files /demo` | Allowed. Reply lists `README.txt`, `contacts.txt`, `private`, `sandbox`, one per line, sorted. |
| LF-02 | `/list_files` (no path) | Same as LF-01, because the path defaults to `/demo`. |
| LF-03 | `/list_files /demo/` | Same as LF-01, because the trailing slash is normalised away. |
| LF-04 | `/list_files /demo/./` | Same as LF-01. |
| LF-05 | `/list_files /demo/private` | Blocked before execution. Reason names `resource_access` and the `/demo/private` rule ("Demo denied folder"). `internal.txt` is not shown. |
| LF-06 | `/list_files /demo/contacts.txt` | Blocked after execution: not a directory. `execution: failed`, reason "Tool execution failed or exceeded its limits". |
| LF-07 | `/list_files /demo/nothing` | Blocked after execution: missing folder. The reason does not quote the path. |
| LF-08 | `/list_files /` | Blocked before execution (default `none`, outside every folder). |
| LF-09 | `/list_files /etc` | Blocked before execution. |
| LF-10 | `/list_files /home/me/Projects` | Blocked. `resource_access` allows it (write folder), but the gateway rejects it: `invalid_tool`, "outside the demo gateway contract". |
| LF-11 | `/list_files /demo/../etc` | Blocked, never executed. |
| LF-12 | `/list_files demo` (relative) | Blocked, never executed. |
| LF-13 | `/list_files /DEMO` | Blocked: paths are case-sensitive, so this is outside `/demo`. |

## B. `/read_file` on the standard Preset

| ID | Command | Expected |
|---|---|---|
| RF-01 | `/read_file /demo/README.txt` | Allowed. The full text is shown unchanged. `tool_result` action is `allow`. |
| RF-02 | `/read_file /demo/contacts.txt` | Allowed with redaction. Reply shows `[EMAIL]` and `[PHONE]`. `Project status: ready for review.` is kept. `tool_result` action is `redact`. |
| RF-03 | RF-02, then open the audit event | `alice@example.com` and `600 123 456` appear nowhere in the reply JSON, the event, or the console export. |
| RF-04 | `/read_file /demo/private/internal.txt` | Blocked before execution. `executed: false`, reason names the `/demo/private` rule. |
| RF-05 | `/read_file /demo/private/../private/internal.txt` | Blocked, because the path normalises to the denied folder. |
| RF-06 | `/read_file /demo//private/internal.txt` | Blocked, because the double slash collapses. |
| RF-07 | `/read_file /demo/./private/internal.txt` | Blocked. |
| RF-08 | `/read_file /demo/../etc/passwd` | Blocked, never executed. |
| RF-09 | `/read_file /etc/passwd` | Blocked before execution. Same result with `resource_access: off` (see E-03). |
| RF-10 | `/read_file /demo\private\internal.txt` | Blocked, never executed (backslashes are rejected). |
| RF-11 | `/read_file C:\Windows\win.ini` | Blocked, never executed. |
| RF-12 | `/read_file /demo` | Blocked after execution: not a regular file, `execution: failed`. |
| RF-13 | `/read_file /demo/missing.txt` | Blocked after execution: `execution: failed`. `missing.txt` is not in the reason. |
| RF-14 | `/read_file /demo/%2e%2e/etc/passwd` | Blocked. `%2e` is not decoded and the file does not exist. |
| RF-15 | `/read_file /home/me/.ssh/id_rsa` | Blocked before execution by the `.ssh` rule ("Keys: never"). |
| RF-16 | `/read_file /home/me/Documents/notes.txt` | Blocked by the gateway (`invalid_tool`), even though `resource_access` allows reading it. |
| RF-17 | `/read_file /demo/PRIVATE/internal.txt` | **Expected: blocked.** See *Known issue* below. |
| RF-18 | `/read_file /demo/Private/internal.txt` | **Expected: blocked.** See *Known issue* below. |

### Known issue: case variants of `/demo/private` (RF-17, RF-18)

`resource_access` compares POSIX paths case-sensitively, so `/demo/PRIVATE/...` does not
match the `/demo/private` rule. It falls under the `/demo` read rule and is allowed:

```text
/demo/private/internal.txt  -> ('none', rule 1)
/demo/PRIVATE/internal.txt  -> ('read', rule 0)
```

What happens next depends on the file system:

- **Docker (Linux, case-sensitive)**: the file is not found, `execution: failed`. Nothing leaks,
  but the denial comes from the missing file, not from the rule.
- **Local run on macOS / Windows (case-insensitive)**: the executor opens `private/internal.txt`
  and **the confidential text is returned**. Verified on macOS:
  `execute(read_file /demo/PRIVATE/internal.txt)` returned
  `"Demo-only confidential record. ..."`.

Run RF-17 and RF-18 on both setups and record the result. On a local macOS run they are
expected to **fail** until this is fixed.

## B2. `/delete_file` on the standard Preset

| ID | Command | Expected |
|---|---|---|
| DF-01 | `/delete_file /demo/sandbox/scratch.txt` | Allowed. Reply `Deleted /demo/sandbox/scratch.txt`. `/list_files /demo/sandbox` then shows `(empty directory)`. |
| DF-02 | DF-01 again (file already gone) | Blocked after execution: `execution: failed`. |
| DF-03 | `/delete_file /demo/contacts.txt` | Blocked before execution: `/demo` is read-only. The file still exists. |
| DF-04 | `/delete_file /demo/private/internal.txt` | Blocked before execution (`/demo/private` is `none`). |
| DF-05 | `/delete_file /demo/sandbox` | Blocked, never executed (a folder, not a file). |
| DF-06 | `/delete_file /demo/sandbox/../contacts.txt` | Blocked. `contacts.txt` still exists. |
| DF-07 | `/delete_file /demo/SANDBOX/scratch.txt` | Blocked by the gateway (case-sensitive), even on macOS. |
| DF-08 | `/delete_file` (no path) | Blocked: the path defaults to `/demo`, which is outside the sandbox. |
| DF-09 | `/delete_file /etc/passwd` | Blocked, never executed. |

## C. Preset comparison

Run the same four commands on each Preset.

| ID | Command | permissive | standard | strict |
|---|---|---|---|---|
| PR-01 | `/list_files /demo` | allowed | allowed | allowed |
| PR-02 | `/read_file /demo/README.txt` | allowed | allowed | allowed |
| PR-03 | `/read_file /demo/contacts.txt` | allowed, **raw** email and phone. `sensitive_data` is `monitor`: Findings in the audit, `action: allow` | redacted (`[EMAIL]`, `[PHONE]`) | blocked after execution: `executed: true`, `tool_result: null` |
| PR-04 | `/read_file /demo/private/internal.txt` | **read succeeds**. `resource_access` is `monitor`, so the audit has a `block` raw Verdict with effective `allow` | blocked before execution | blocked before execution |
| PR-05 | `/read_file /etc/passwd` | blocked (gateway contract) | blocked | blocked |
| PR-06 | `/delete_file /demo/sandbox/scratch.txt` | allowed | allowed | blocked before execution (strict has no write folder under `/demo`) |
| PR-07 | `/delete_file /demo/contacts.txt` | blocked (gateway contract, even though `resource_access` only monitors) | blocked | blocked |

Check: the number of blocks never goes down from permissive to standard to strict.

## D. Run limits and audit

| ID | Steps | Expected |
|---|---|---|
| AU-01 | After LF-01, load the run in the console | 6 events in order: `input, output, tool_call, tool_result, input, output`. `tool_result.metadata.operation_id` matches the reply's step. |
| AU-02 | Load steps for a made-up `run_id` | Empty list. |
| AU-03 | After RF-04 | `tool_call` event has `action: block`. No `tool_result` event for that run. |
| AU-04 | After LF-06 / RF-13 | `tool_result` event has `execution: failed`. Its content holds no file data or path detail. |
| AU-05 | `GET http://localhost:8001/v1/settings/events?session_id=<run_id>` | Same events as the console view. |
| AU-06 | Send `/list_files /demo` 10 times quickly | `loop_detector` / `request_limits` start blocking according to the Preset. Each blocked call is audited. |

## E. Policy edits (hot reload, no restart)

Edit `policy.yaml` on the host and save. The next message uses the new Policy.

| ID | Edit | Command | Expected |
|---|---|---|---|
| E-01 | `resource_access.mode: monitor` | `/read_file /demo/private/internal.txt` | Read succeeds. Audit raw `block`, effective `allow`. |
| E-02 | Change the `/demo/private` folder to `access: read` | same | Read succeeds. |
| E-03 | `resource_access.mode: off` | `/read_file /etc/passwd`, `/read_file /demo/../etc/passwd`, `/delete_file /demo/contacts.txt` | Still blocked (gateway contract, `invalid_tool`). |
| E-03b | Change the `/demo` folder to `access: write` | `/delete_file /demo/contacts.txt` | Still blocked: the gateway only deletes inside `/demo/sandbox`. |
| E-04 | Change the `/demo` folder to `access: none` | `/list_files /demo` | Blocked before execution. |
| E-05 | Remove `list_files: read` from `action_classes` | `/list_files /demo` | Blocked: unlisted actions count as `write`, and `/demo` is read-only. |
| E-06 | `sensitive_data.mode: off` | `/read_file /demo/contacts.txt` | Raw email and phone returned. |
| E-07 | Break the YAML (e.g. a stray `:`) | `/list_files /demo` | The last good Policy is still used. The console shows `last_error`. |

Revert every edit after the case (`git checkout policy.yaml`).

## F. Not reachable from the chat (API only)

Send these with `curl` to the firewall's `/v1/tools/execute`, with header `X-Agent-Key: demo-agent-key`.

| ID | Request | Expected |
|---|---|---|
| API-01 | `action: write_file`, path `/demo/sandbox/scratch.txt` | `block`, `executed: false` (no write tool) |
| API-02 | `action: shell`, path `/demo` | `block`, `executed: false` |
| API-03 | No `X-Agent-Key` | `block` (unknown agent), not executed |
| API-04 | Extra argument `{"path": "/demo", "recursive": true}` | Rejected (`extra="forbid"`), not executed |
| API-05 | Path longer than 1024 characters | Rejected, not executed |
| API-06 | `GET /v1/tools` | Exactly three tools: `list_files`, `read_file`, `delete_file` |

Note: in Compose the `firewall` data-plane instance is internal. Run section F against a local
single-process firewall (`make` dev command) or from inside the Compose network.
