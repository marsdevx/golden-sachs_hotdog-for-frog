import pytest
from conftest import BASE_POLICY, PRESETS
from firewall_app.controls import REGISTRY
from firewall_app.domain import Mode, Stage
from firewall_app.policy import PolicyError, PolicyStore, dump_policy, parse_policy


@pytest.mark.parametrize("preset", ["permissive", "standard", "strict"])
def test_presets_load(preset):
    store = PolicyStore(PRESETS / f"{preset}.yaml", REGISTRY)
    policy = store.get()
    assert store.last_error is None
    assert len(policy.version) == 12
    assert "keyword_blocklist" in policy.controls
    assert all(settings.description for settings in policy.controls.values())


def test_presets_differ_in_strictness():
    modes = {
        preset: PolicyStore(PRESETS / f"{preset}.yaml", REGISTRY).get()
        for preset in ("permissive", "standard", "strict")
    }
    assert modes["permissive"].controls["keyword_blocklist"].mode == Mode.monitor
    assert modes["standard"].controls["keyword_blocklist"].mode == Mode.block
    assert modes["strict"].controls["keyword_blocklist"].mode == Mode.block
    assert modes["strict"].defaults.unknown_agent == "block"
    strict_keywords = modes["strict"].controls["keyword_blocklist"].parsed_params.keywords
    assert len(strict_keywords) > 1


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
        (BASE_POLICY.replace("keyword_blocklist:", "no_such_control:"), "unknown Control id"),
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
        PolicyStore(tmp_policy("controls:\n  nope:\n    mode: block\n"), REGISTRY)


def test_write_is_validated_and_atomic(tmp_policy):
    path = tmp_policy()
    store = PolicyStore(path, REGISTRY)
    with pytest.raises(PolicyError):
        store.write("controls:\n  nope: {}\n")
    assert path.read_text() == BASE_POLICY
    assert list(path.parent.glob("*.tmp")) == []

    new_text = BASE_POLICY.replace("test policy", "written")
    policy = store.write(new_text)
    assert path.read_text() == new_text
    assert policy.version_note == "written"
    assert store.version == policy.version


def test_dump_round_trip(tmp_policy):
    policy = parse_policy(BASE_POLICY, REGISTRY)
    again = parse_policy(dump_policy(policy), REGISTRY)
    assert again.model_dump() == policy.model_dump()


def test_unquoted_yaml_off_means_mode_off():
    policy = parse_policy("controls:\n  keyword_blocklist:\n    mode: off\n", REGISTRY)
    assert policy.controls["keyword_blocklist"].mode == Mode.off
    assert "'off'" in dump_policy(policy) or '"off"' in dump_policy(policy)
