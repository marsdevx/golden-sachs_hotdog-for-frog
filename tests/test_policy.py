import pytest
from conftest import BASE_POLICY, POLICY_FILE
from firewall_app.controls import REGISTRY
from firewall_app.domain import Mode, Stage
from firewall_app.policy import PolicyError, PolicyStore, parse_policy


def test_policy_file_loads():
    store = PolicyStore(POLICY_FILE, REGISTRY)
    policy = store.get()
    assert store.last_error is None
    assert len(policy.version) == 12
    assert "keyword_blocklist" in policy.controls
    assert all(settings.description for settings in policy.controls.values())


def test_policy_file_runs_the_injection_controls():
    policy = PolicyStore(POLICY_FILE, REGISTRY).get()
    for control_id in ("injection_heuristics", "injection_classifier"):
        settings = policy.controls[control_id]
        assert settings.mode == Mode.block
        assert settings.parsed_params.on_indirect == "redact"
        assert REGISTRY.get(control_id).feature == "input_validation"
    classifier = policy.controls["injection_classifier"]
    assert classifier.on_error == "allow"
    assert classifier.parsed_params.threshold == 0.9


def test_effective_stages_default_to_supported(tmp_policy):
    policy = PolicyStore(tmp_policy(), REGISTRY).get()
    assert policy.controls["keyword_blocklist"].effective_stages == {Stage.input, Stage.output}


def test_hot_reload_on_mtime_change(tmp_policy):
    path = tmp_policy()
    store = PolicyStore(path, REGISTRY)
    first_version = store.version
    tmp_policy(BASE_POLICY.replace("mode: block\n    params", "mode: monitor\n    params"))
    policy = store.get()
    assert policy.controls["keyword_blocklist"].mode == Mode.monitor
    assert store.version != first_version


@pytest.mark.parametrize(
    "broken, expected",
    [
        ("controls: [unclosed", "invalid YAML"),
        (BASE_POLICY.replace('keywords: ["project falcon"]', "keywords: 42"), "params.keywords"),
        (BASE_POLICY.replace("params:", "params:\n      typo_key: 1"), "unknown keys"),
        (BASE_POLICY.replace("mode: block", "mode: loud"), "mode"),
        (BASE_POLICY.replace("mode: block", "mode: block\n    stages: [tool_call]"), "stages"),
        (BASE_POLICY + "\nsurprise: true\n", "surprise"),
    ],
)
def test_invalid_edit_keeps_last_good_policy(tmp_policy, broken, expected):
    path = tmp_policy()
    store = PolicyStore(path, REGISTRY)
    good_version = store.version
    tmp_policy(broken)
    policy = store.get()
    assert policy.version == good_version
    assert policy.controls["keyword_blocklist"].mode == Mode.block
    assert expected in store.last_error
    # Fixing the file clears the error.
    tmp_policy(BASE_POLICY.replace("test policy", "fixed"))
    assert store.get().version_note == "fixed"
    assert store.last_error is None


def test_invalid_initial_policy_fails_fast(tmp_policy):
    with pytest.raises(PolicyError):
        PolicyStore(tmp_policy("controls:\n  keyword_blocklist:\n    mode: loud\n"), REGISTRY)


def test_unquoted_yaml_off_means_mode_off():
    policy = parse_policy("controls:\n  keyword_blocklist:\n    mode: off\n", REGISTRY)
    assert policy.controls["keyword_blocklist"].mode == Mode.off


NO_PESEL = BASE_POLICY + """  sensitive_data:
    mode: redact
    params:
      categories:
        - name: email
          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']
"""
PESEL = """        - name: pesel
          description: "Polish national ID number (PESEL), required by the 2026 regulation"
          patterns: ['\\b\\d{11}\\b']
          validator: pesel_checksum
          replacement: "[PESEL]"
"""


async def test_new_category_by_config_only(tmp_policy):
    """The pitch story: a new regulation is a Policy edit, picked up on the next Check."""
    from firewall_app.domain import Action, Agent, Check, Message
    from firewall_app.pipeline import run_check

    def reply(text):
        return Check(stage=Stage.output, agent=Agent(id="a", owner="o"),
                     message=Message(role="assistant", content=text))

    store = PolicyStore(tmp_policy(NO_PESEL), REGISTRY)
    first_version = store.version
    result = await run_check(reply("PESEL 44051401359"), store.get())
    assert result.decision.action == Action.allow

    tmp_policy(NO_PESEL + PESEL)
    policy = store.get()
    assert policy.version != first_version
    result = await run_check(reply("PESEL 44051401359"), policy)
    assert result.decision.action == Action.redact
    assert result.after.message.content == "PESEL [PESEL]"
    assert [finding.type for finding in result.decision.findings] == ["pesel"]
    bad_checksum = await run_check(reply("PESEL 44051401358"), policy)
    assert bad_checksum.decision.action == Action.allow


def test_reference_policy_sections_of_existing_controls_are_valid():
    """policy.example.yaml is the contract. It does not load as a whole (planned settings),
    but the section of every Control that exists must be valid for that Control."""
    import yaml
    from conftest import REPO_ROOT

    reference = yaml.safe_load((REPO_ROOT / "policy.example.yaml").read_text())
    controls = reference["controls"]
    existing = {cid: section for cid, section in controls.items() if cid in REGISTRY}
    assert {"loop_detector", "request_limits", "token_budget"} <= set(existing)
    text = yaml.safe_dump({"features": reference["features"], "controls": existing},
                          sort_keys=False)
    policy = parse_policy(text, REGISTRY)
    assert list(policy.controls)[:3] == ["loop_detector", "request_limits", "token_budget"]
