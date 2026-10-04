"""resource_access: the user's own folder rules for file Resources, default deny."""

import pytest
from conftest import BASE_POLICY, POLICY_FILE, bump_mtime
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.controls.resource_access import (
    Params,
    ResourceAccess,
    effective_access,
    normalize_path,
)
from firewall_app.domain import Action, Agent, Check, Mode, Stage, ToolCall
from firewall_app.pipeline import run_check
from firewall_app.policy import PolicyError, PolicyStore, parse_policy

AGENT = Agent(id="desktop-assistant", owner="me@bank.example")

PARAMS = Params.model_validate(
    {
        "folders": [
            {"path": "/home/me/Documents", "access": "read"},
            {"path": "/home/me/Projects", "access": "write"},
            {"path": "/home/me/Documents/Private", "access": "none"},
        ]
    }
)


def tool_check(action: str, resource: str = "files", **args) -> Check:
    return Check(
        stage=Stage.tool_call,
        agent=AGENT,
        tool=ToolCall(resource=resource, action=action, args=args),
    )


async def evaluate(check: Check, params: Params = PARAMS):
    return await ResourceAccess().evaluate(check, params)


def test_registered():
    assert REGISTRY.get("resource_access") is ResourceAccess
    assert ResourceAccess.stages == {Stage.tool_call}


# --- Params ---


def test_policy_file_parses():
    policy = PolicyStore(POLICY_FILE, REGISTRY).get()
    params = policy.controls["resource_access"].parsed_params
    assert params.default == "none"
    assert effective_access(params, "/demo/contacts.txt")[0] == "read"
    assert effective_access(params, "/home/me/.ssh/id_rsa")[0] == "none"


@pytest.mark.parametrize(
    "folder",
    [
        {"path": "/data", "acess": "read"},  # typo
        {"path": "/data", "access": "full"},
        {"path": "data", "access": "read"},  # relative
        {"path": "/data", "access": "read", "teams": ["x"]},  # no teams on a personal PC
    ],
)
def test_bad_rule_is_rejected(folder):
    with pytest.raises(ValueError):
        Params.model_validate({"folders": [folder]})


def test_folder_paths_are_normalized():
    folders = [
        {"path": "//home/./me/x/../Documents/", "access": "read"},
        {"path": "C:\\Users\\Me\\Documents\\", "access": "read"},
    ]
    params = Params.model_validate({"folders": folders})
    assert [f.path for f in params.folders] == ["/home/me/Documents", "c:/users/me/documents"]


def test_bad_rule_keeps_the_last_good_policy(tmp_policy):
    good = BASE_POLICY.replace(
        "controls:\n",
        "controls:\n  resource_access:\n    mode: block\n    params:\n"
        "      folders: [{path: /data, access: read}]\n",
    )
    path = tmp_policy(good)
    store = PolicyStore(path, REGISTRY)
    version = store.get().version
    tmp_policy(good.replace("access: read", "access: full"))
    assert store.get().version == version
    assert "access" in store.last_error
    with pytest.raises(PolicyError):
        parse_policy(good.replace("access: read", "acess: read"), REGISTRY)


# --- Normalization ---


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/home/me/Documents/a.txt", "/home/me/Documents/a.txt"),
        ("/home/me/Projects/../.ssh/id_rsa", "/home/me/.ssh/id_rsa"),
        ("//home//me/./a", "/home/me/a"),
        ("Documents/a", "/home/me/Documents/a"),
        ("/../../etc/passwd", "/etc/passwd"),
        ("C:\\Users\\Me\\Documents\\CV.docx", "c:/users/me/documents/cv.docx"),
        ("c:/Users/me/../../Windows", "c:/windows"),
        ("C:", "c:/"),
    ],
)
def test_normalize_path(raw, expected):
    assert normalize_path(raw, "/home/me") == expected


@pytest.mark.parametrize(
    "raw", ["", "  ", "~/secrets", "/data/\x00x", "file:///etc/passwd", "C:Users\\me"]
)
def test_normalize_path_refuses(raw):
    with pytest.raises(ValueError):
        normalize_path(raw)


# --- Enforcement ---


async def test_read_in_allowed_folder():
    verdict = await evaluate(tool_check("read_file", path="/home/me/Documents/report.pdf"))
    assert verdict.action == Action.allow
    assert verdict.findings == []


async def test_write_in_read_only_folder_is_blocked():
    verdict = await evaluate(tool_check("write_file", path="/home/me/Documents/report.pdf"))
    assert verdict.action == Action.block
    assert verdict.risk_score == 0.6
    assert [f.type for f in verdict.findings] == ["folder_denied"]
    assert verdict.reason == (
        "folders[0] allows only read in /home/me/Documents; files.write_file needs write"
    )


async def test_write_in_writable_folder():
    verdict = await evaluate(tool_check("write_file", path="/home/me/Projects/app/main.py"))
    assert verdict.action == Action.allow


async def test_default_deny_outside_every_folder():
    verdict = await evaluate(tool_check("read_file", path="/etc/passwd"))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "outside_folders"
    assert verdict.risk_score == 0.3


async def test_default_can_be_opened_up():
    params = PARAMS.model_copy(update={"default": "read"})
    assert (await evaluate(tool_check("read_file", path="/tmp/x"), params)).action == Action.allow
    assert (await evaluate(tool_check("write_file", path="/tmp/x"), params)).action == Action.block


async def test_deeper_none_carves_a_hole_into_a_grant():
    verdict = await evaluate(tool_check("read_file", path="/home/me/Documents/Private/diary.txt"))
    assert verdict.action == Action.block
    assert verdict.reason == (
        "folders[2] allows no access in /home/me/Documents/Private; files.read_file needs read"
    )


@pytest.mark.parametrize("order", [1, -1])
def test_deepest_folder_wins_in_any_order(order):
    folders = [
        {"path": "/home/me", "access": "none"},
        {"path": "/home/me/Projects", "access": "write"},
        {"path": "/home/me/Projects/vendor", "access": "read"},
    ][::order]
    params = Params.model_validate({"folders": folders})
    assert effective_access(params, "/home/me/Projects/a.py")[0] == "write"
    assert effective_access(params, "/home/me/Projects/vendor/lib.py")[0] == "read"
    assert effective_access(params, "/home/me/notes.txt")[0] == "none"


@pytest.mark.parametrize("order", [1, -1])
def test_same_folder_strictest_wins_in_any_order(order):
    folders = [{"path": "/data/x", "access": "write"}, {"path": "/data/x", "access": "read"}]
    params = Params.model_validate({"folders": folders[::order]})
    assert effective_access(params, "/data/x")[0] == "read"


async def test_prefix_match_is_on_a_folder_boundary():
    verdict = await evaluate(tool_check("read_file", path="/home/me/Documents-old/x"))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "outside_folders"


async def test_traversal_is_checked_after_normalization():
    path = "/home/me/Documents/../Documents/Private/x"
    verdict = await evaluate(tool_check("read_file", path=path))
    assert verdict.action == Action.block
    assert "/home/me/Documents/Private" in verdict.reason


async def test_windows_paths_are_case_insensitive():
    params = Params.model_validate(
        {
            "folders": [
                {"path": "C:\\Users\\me\\Documents", "access": "read"},
                {"path": "C:\\Users\\me\\Documents\\Private", "access": "none"},
            ]
        }
    )
    allowed = tool_check("read_file", path="c:/users/ME/documents/cv.docx")
    assert (await evaluate(allowed, params)).action == Action.allow
    hidden = tool_check("read_file", path="C:\\Users\\me\\Documents\\PRIVATE\\x")
    assert (await evaluate(hidden, params)).action == Action.block
    other_drive = tool_check("read_file", path="D:\\Users\\me\\Documents\\cv.docx")
    assert (await evaluate(other_drive, params)).action == Action.block


async def test_relative_paths_resolve_against_base_dir():
    params = PARAMS.model_copy(update={"base_dir": "/home/me/Documents"})
    assert (await evaluate(tool_check("read_file", path="a.txt"), params)).action == Action.allow
    blocked = await evaluate(tool_check("read_file", path="Private/x"), params)
    assert blocked.action == Action.block


async def test_every_path_must_be_allowed():
    verdict = await evaluate(
        tool_check("move", src="/home/me/Projects/a.md", dst="/home/me/Documents/a.md")
    )
    assert verdict.action == Action.block
    assert [f.detail.split(":")[0] for f in verdict.findings] == ["dst"]


async def test_nested_and_list_path_args_are_found():
    files = ["/home/me/Documents/a", "/home/me/Documents/Private/b"]
    verdict = await evaluate(tool_check("read_file", options={"files": files}))
    assert verdict.action == Action.block
    assert len(verdict.findings) == 1


async def test_call_without_path_is_blocked():
    verdict = await evaluate(tool_check("list_dir", query="*.pdf"))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "no_path"


async def test_invalid_path_is_blocked():
    verdict = await evaluate(tool_check("read_file", path="~/.ssh/id_rsa"))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "invalid_path"
    verdict = await evaluate(tool_check("read_file", path=42))
    assert verdict.findings[0].type == "invalid_path"


async def test_unclassified_action_counts_as_write():
    verdict = await evaluate(tool_check("chmod", path="/home/me/Documents/a"))
    assert verdict.action == Action.block
    assert "needs write" in verdict.reason


async def test_other_resources_are_not_governed():
    check = tool_check("search", resource="web", path="/anything")
    assert (await evaluate(check)).action == Action.allow
    every = PARAMS.model_copy(update={"resources": ["*"]})
    assert (await evaluate(check, every)).action == Action.block


async def test_requested_path_never_leaks_into_reason_or_findings():
    secret = "/home/me/Documents/Private/jan-kowalski-salary.xlsx"
    verdict = await evaluate(tool_check("read_file", path=secret))
    assert verdict.action == Action.block
    text = verdict.reason + " ".join(f.detail for f in verdict.findings)
    assert "jan-kowalski" not in text


async def test_missing_tool_raises():
    with pytest.raises(ValueError):
        await evaluate(Check(stage=Stage.tool_call, agent=AGENT))


# --- Modes through the pipeline ---


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  resource_access:\n    mode: {mode}\n    params:\n"
        "      folders: [{path: /home/me/Documents, access: read}]\n",
        REGISTRY,
    )


async def test_monitor_mode_records_but_allows():
    check = tool_check("write_file", path="/home/me/Documents/a")
    result = await run_check(check, policy_with_mode("monitor"))
    assert result.decision.action == Action.allow
    assert result.decision.verdicts[0].action == Action.block
    assert result.decision.verdicts[0].mode == Mode.monitor


async def test_block_mode_blocks_with_explanation():
    check = tool_check("write_file", path="/home/me/Documents/a")
    result = await run_check(check, policy_with_mode("block"))
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by resource_access: folders[0]")


# --- End to end through the check API, with hot reload ---


def folder_policy(folders: str) -> str:
    return BASE_POLICY.replace(
        "controls:\n",
        f"controls:\n  resource_access:\n    mode: block\n    params:\n      folders: {folders}\n",
    )


def test_check_api_and_hot_reload(make_firewall_app, tmp_policy, agent_headers):
    docs = "{path: /home/me/Documents, access: read}"
    client = TestClient(make_firewall_app(folder_policy(f"[{docs}]")))

    def decide(action: str, path: str) -> str:
        body = {"tool": {"resource": "files", "action": action, "args": {"path": path}}}
        response = client.post("/v1/check/tool_call", json=body, headers=agent_headers)
        assert response.status_code == 200
        return response.json()["decision"]["action"]

    assert decide("read_file", "/home/me/Documents/a.txt") == "allow"
    assert decide("write_file", "/home/me/Documents/a.txt") == "block"
    assert decide("read_file", "/home/me/Pictures/cat.png") == "block"

    path = tmp_policy(
        folder_policy(
            f"[{docs}, {{path: /home/me/Pictures, access: read}}]"
        )
    )
    bump_mtime(path)
    assert decide("read_file", "/home/me/Pictures/cat.png") == "allow"


