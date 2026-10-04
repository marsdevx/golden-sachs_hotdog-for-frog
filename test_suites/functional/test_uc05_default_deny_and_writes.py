"""UC-05: the Agent gets no access unless it is explicitly allowed, and writing is a step
above reading (R2.1, R1).

`resource_access` governs file Resources. Every path in a tool call is checked against the
folders of the Policy: the deepest folder decides, a path outside every folder gets `default`
(`none`, so default deny), and a write needs more than a read. The Agent can be sure of nothing
but the rules: it may try `..`, a Windows path, a second path in another argument, or no path
at all.

Folders below come from `policy.yaml`:
  /home/me/Projects              write
  /home/me/Documents             read          (and Documents/Private: none)
  /home/me/.ssh                  none
  /demo                          read          (and /demo/private: none, /demo/sandbox: write)
Tool calls are checked through the check API (`/v1/check/tool_call`): the proxy only handles the
model's text, and the demo chat has no tool executor yet.
"""

from __future__ import annotations

import json

import pytest

from test_suites.harness import AGENT_KEY, TRADER_KEY

pytestmark = [pytest.mark.uc("UC-05"), pytest.mark.req("R2.1", "R1")]


def call(gateway, action: str, path=None, *, resource: str = "files", key: str = AGENT_KEY,
         **args) -> dict:
    """Run a tool_call Check and return the Decision."""
    if path is not None:
        args["path"] = path
    body = {"tool": {"resource": resource, "action": action, "args": args}}
    return gateway.check("tool_call", body, key=key)["decision"]


def finding_types(decision: dict) -> set[str]:
    return {f["type"] for f in decision["findings"]}


def set_folders(gateway, folders: list[dict]) -> None:
    gateway.policy.set_params("resource_access", folders=folders)


def folders_of(gateway) -> list[dict]:
    return gateway.policy.load()["controls"]["resource_access"]["params"]["folders"]


# ---- 1. reading is allowed where it was granted ---------------------------------------------


@pytest.mark.parametrize(
    ("action", "path"),
    [
        ("read_file", "/home/me/Documents/report.txt"),
        ("list_dir", "/home/me/Documents"),
        ("list_files", "/demo"),
        ("read_file", "/home/me/Projects/app/main.py"),
        ("read_file", "/demo/readme.txt"),
    ],
)
def test_reading_inside_a_granted_folder_is_allowed(gateway, action, path):
    decision = call(gateway, action, path)

    assert decision["action"] == "allow"
    assert decision["findings"] == []


def test_the_demo_sandbox_is_the_one_demo_folder_that_can_be_written(gateway):
    assert call(gateway, "write_file", "/demo/sandbox/note.txt")["action"] == "allow"
    assert call(gateway, "delete_file", "/demo/sandbox/note.txt")["action"] == "allow"
    assert call(gateway, "write_file", "/demo/note.txt")["action"] == "block", "read-only"
    assert call(gateway, "delete_file", "/demo/private/x")["action"] == "block"


def test_an_action_missing_from_the_list_of_classes_counts_as_write(gateway):
    """`search` is not classified in policy.yaml, so it needs write like the unknown `chmod`."""
    assert call(gateway, "search", "/home/me/Documents/notes")["action"] == "block"
    assert call(gateway, "search", "/home/me/Projects/notes")["action"] == "allow"


# ---- 2. writing needs more than reading -----------------------------------------------------


@pytest.mark.parametrize("action", ["write_file", "delete_file", "move", "make_dir"])
def test_writing_in_a_read_only_folder_is_blocked(gateway, action):
    decision = call(gateway, action, "/home/me/Documents/report.txt")

    assert decision["action"] == "block"
    assert "allows only read" in decision["reason"]
    assert f"files.{action} needs write" in decision["reason"]
    assert finding_types(decision) == {"folder_denied"}


def test_writing_is_allowed_where_write_was_granted(gateway):
    assert call(gateway, "write_file", "/home/me/Projects/app/main.py")["action"] == "allow"


def test_an_action_nobody_classified_counts_as_a_write(gateway):
    """The stricter reading wins: an unknown action never gets read-only treatment."""
    assert call(gateway, "chmod", "/home/me/Documents/report.txt")["action"] == "block"
    assert call(gateway, "chmod", "/home/me/Projects/app/main.py")["action"] == "allow"


# ---- 3. default deny ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "/var/log/syslog", "/home/me/Downloads/invoice.pdf", "/home/other/file", "/"],
)
def test_a_path_outside_every_folder_is_denied_even_for_reading(gateway, path):
    decision = call(gateway, "read_file", path)

    assert decision["action"] == "block"
    assert "outside every allowed folder" in decision["reason"]
    assert finding_types(decision) == {"outside_folders"}


def test_a_folder_name_that_only_starts_like_a_granted_one_is_not_granted(gateway):
    """/home/me/Projects-old is not inside /home/me/Projects."""
    assert call(gateway, "write_file", "/home/me/Projects-old/x")["action"] == "block"
    assert call(gateway, "write_file", "/home/me/Projectsx/x")["action"] == "block"


@pytest.mark.parametrize("action", ["read_file", "write_file"])
@pytest.mark.parametrize("path", ["/home/me/.ssh/id_rsa", "/home/me/Documents/Private/salary.xlsx"])
def test_a_denied_folder_inside_a_granted_one_stays_closed(gateway, action, path):
    decision = call(gateway, action, path)

    assert decision["action"] == "block"
    assert "allows no access" in decision["reason"]


# ---- 4. the Agent tries to get around it ----------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/home/me/Projects/../.ssh/id_rsa",
        "/home/me/Projects/./app/../../.ssh/id_rsa",
        "//home//me//.ssh//id_rsa",
        "/home/me/Documents/Private/../Private/salary.xlsx",
        "\\home\\me\\.ssh\\id_rsa",
        "/home/me/.ssh",
    ],
    ids=["dotdot", "dot-and-dotdot", "double-slashes", "back-and-forth", "windows-slashes",
         "the-folder-itself"],
)
def test_disguised_paths_are_judged_by_where_they_really_point(gateway, path):
    assert call(gateway, "read_file", path)["action"] == "block"


@pytest.mark.parametrize(
    "path",
    [
        "~/.ssh/id_rsa",
        "file:///home/me/.ssh/id_rsa",
        "C:\\Users\\me\\secrets.txt",
        "",
        "   ",
        "bad\x00path",
        12345,
        None,
    ],
    ids=["home-shortcut", "url", "windows-drive", "empty", "blank", "nul-byte", "number", "null"],
)
def test_a_path_that_cannot_be_judged_is_refused(gateway, path):
    decision = call(gateway, "read_file", path="/x")  # a valid call first: control
    assert decision["action"] == "block"  # /x is outside every folder

    decision = gateway.check(
        "tool_call",
        {"tool": {"resource": "files", "action": "read_file", "args": {"path": path}}},
    )["decision"]

    assert decision["action"] == "block"


def test_a_call_that_names_no_path_is_refused(gateway):
    """Leaving the path out must not skip the check."""
    decision = call(gateway, "read_file")

    assert decision["action"] == "block"
    assert "names no path" in decision["reason"]
    assert finding_types(decision) == {"no_path"}


def test_every_path_in_the_call_must_be_allowed(gateway):
    allowed = "/home/me/Projects/a.txt"
    hidden = "/home/me/.ssh/key"

    assert call(gateway, "move", src=allowed, dst="/home/me/Projects/b.txt")["action"] == "allow"
    assert call(gateway, "move", src=allowed, dst=hidden)["action"] == "block"
    nested = call(gateway, "write_file", files=[{"path": allowed}, {"path": hidden}])
    assert nested["action"] == "block", "a forbidden path inside a list or nested object counts"


def test_the_decision_never_repeats_the_file_name(gateway):
    """File names can carry personal data, and decisions go back to the Agent and into logs."""
    name = "client_ivan_petrov_salary_2026.xlsx"

    decision = call(gateway, "read_file", f"/home/me/.ssh/{name}")

    assert decision["action"] == "block"
    assert name not in json.dumps(decision)


# ---- 5. the same rules for every Agent ------------------------------------------------------


@pytest.mark.parametrize("key", [AGENT_KEY, TRADER_KEY], ids=["research-agent", "trading-agent"])
def test_the_rules_apply_to_every_agent(gateway, key):
    assert call(gateway, "read_file", "/home/me/.ssh/id_rsa", key=key)["action"] == "block"
    assert call(gateway, "write_file", "/home/me/Documents/a", key=key)["action"] == "block"
    assert call(gateway, "read_file", "/home/me/Documents/a", key=key)["action"] == "allow"


# ---- 6. what is a Resource: only the listed ones are governed -------------------------------


def test_other_resources_are_not_this_controls_concern_in_the_policy(gateway):
    """Documents today's behaviour: only `resources: [files]` are checked."""
    assert call(gateway, "read_client", resource="crm", client_id=7)["action"] == "allow"


@pytest.mark.xfail(
    reason="known gap: the policy governs only the `files` Resource, so any other Resource "
    "(crm, trading, a new MCP server) is allowed without a rule. 'No access unless explicitly "
    "allowed' holds for files only",
    strict=False,
)
def test_a_resource_nobody_listed_is_denied_by_default(gateway):
    assert call(gateway, "book_trade", resource="trading", symbol="BTC")["action"] == "block"


def test_the_operator_can_make_every_resource_default_deny(gateway):
    gateway.policy.set_params("resource_access", resources=["*"])

    crm = call(gateway, "read_client", resource="crm", client_id=7)
    files = call(gateway, "read_file", "/home/me/Documents/report.txt")

    assert crm["action"] == "block", "no folder to match, so nothing to allow"
    assert files["action"] == "allow", "listed folders keep working"


# ---- 7. the operator changes the rules in the Policy, no restart ----------------------------


def test_granting_a_folder_takes_effect_on_the_next_call(gateway):
    path = "/home/me/Downloads/invoice.pdf"
    assert call(gateway, "read_file", path)["action"] == "block"

    set_folders(gateway, folders_of(gateway) + [{"path": "/home/me/Downloads", "access": "read"}])

    assert call(gateway, "read_file", path)["action"] == "allow"
    assert call(gateway, "write_file", path)["action"] == "block", "granted for reading only"


def test_removing_a_grant_closes_the_folder_on_the_next_call(gateway):
    assert call(gateway, "read_file", "/home/me/Documents/report.txt")["action"] == "allow"

    set_folders(gateway, [f for f in folders_of(gateway) if f["path"] != "/home/me/Documents"])

    assert call(gateway, "read_file", "/home/me/Documents/report.txt")["action"] == "block"


def test_raising_a_folder_from_read_to_write_opens_writing(gateway):
    path = "/home/me/Documents/report.txt"
    assert call(gateway, "write_file", path)["action"] == "block"

    set_folders(
        gateway,
        [{**f, "access": "write"} if f["path"] == "/home/me/Documents" else f
         for f in folders_of(gateway)],
    )

    assert call(gateway, "write_file", path)["action"] == "allow"
    assert call(gateway, "write_file", "/home/me/Documents/Private/x")["action"] == "block"


def test_opening_the_default_to_read_lets_every_unlisted_path_be_read(gateway):
    gateway.policy.set_params("resource_access", default="read")

    assert call(gateway, "read_file", "/etc/hostname")["action"] == "allow"
    assert call(gateway, "write_file", "/etc/hostname")["action"] == "block"
    assert call(gateway, "read_file", "/home/me/.ssh/id_rsa")["action"] == "block"


def test_a_misspelled_rule_is_refused_and_the_last_good_rules_stay(gateway):
    folders = folders_of(gateway)
    folders[0] = {**folders[0], "acess": "write"}  # typo in the key name
    set_folders(gateway, folders)

    assert call(gateway, "write_file", "/home/me/Documents/report.txt")["action"] == "block"
    assert call(gateway, "read_file", "/home/me/Documents/report.txt")["action"] == "allow"
    assert gateway.policy_view()["last_error"] is not None


def test_monitor_mode_records_the_denial_but_lets_the_call_through(gateway):
    gateway.policy.set_mode("resource_access", "monitor")

    decision = call(gateway, "write_file", "/home/me/Documents/report.txt")

    assert decision["action"] == "allow"
    seen = next(v for v in decision["verdicts"] if v["control"] == "resource_access")
    assert seen["action"] == "block" and seen["effective_action"] == "allow"
    assert seen["findings"], "the attempt is on record"


def test_off_mode_does_not_run_the_control(gateway):
    gateway.policy.set_mode("resource_access", "off")

    assert call(gateway, "read_file", "/home/me/.ssh/id_rsa")["action"] == "allow"


@pytest.mark.parametrize(
    ("action", "path", "expected"),
    [
        ("write_file", "/home/me/Documents/a", "block"),
        ("write_file", "/home/me/Projects/app/a", "allow"),
        ("read_file", "/home/me/Projects/app/a", "allow"),
        ("read_file", "/home/me/Documents/a", "allow"),
        ("write_file", "/demo/sandbox/a", "allow"),
        ("write_file", "/demo/a", "block"),
        ("read_file", "/etc/hostname", "block"),
    ],
)
def test_the_policy_grants_exactly_what_it_lists(gateway, action, path, expected):
    assert call(gateway, action, path)["action"] == expected


# ---- 8. the audit trail ---------------------------------------------------------------------


def test_a_denied_attempt_is_in_the_audit_log_with_the_owner(gateway):
    call(gateway, "write_file", "/home/me/.ssh/authorized_keys")

    (event,) = gateway.events(stage="tool_call", action="block")

    assert event["agent_id"] == "research-assistant"
    assert event["owner"] == "alice@bank.example"
    assert "folder_denied" in {f["type"] for f in event["findings"]}
    # The explanation fields never name the file. (The call itself is kept as content, below.)
    explanation = json.dumps([event["reason"], event["findings"], event["verdicts"]])
    assert "authorized_keys" not in explanation


def test_the_audit_log_keeps_the_call_only_as_far_as_store_content_allows(gateway):
    """`redacted` keeps what the firewall let through or saw; `none` keeps no content at all."""
    gateway.policy.set_store_content("none")
    call(gateway, "write_file", "/home/me/.ssh/authorized_keys")

    (event,) = gateway.events(stage="tool_call", action="block")

    assert event["action"] == "block", "the decision is still recorded"
    assert "authorized_keys" not in json.dumps(event)
