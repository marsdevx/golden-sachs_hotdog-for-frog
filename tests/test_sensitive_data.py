"""Tests for the `sensitive_data` Control: Params validation, evaluation per Stage, Mode table."""

from typing import get_args

import pytest
from conftest import BASE_POLICY
from firewall_app.controls import REGISTRY
from firewall_app.controls.sensitive_data import SensitiveData, ValidatorName
from firewall_app.controls.sensitive_validators import VALIDATORS
from firewall_app.domain import Action, Agent, Check, Message, Mode, Stage
from firewall_app.pipeline import run_check
from firewall_app.policy import PolicyError, PolicyStore, parse_policy

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
SECRET = "q8ZfK2mXv9LpR4tWb7NcY1hJ3sDgA6eUoP0iTzQx"
EMAIL = "jan.kowalski@bank.example"
CARD = "4111 1111 1111 1111"
IBAN = "DE89 3704 0044 0532 0130 00"

CATEGORIES = [
    {"name": "email", "patterns": [r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"]},
    {"name": "card", "patterns": [r"\b(?:\d[ -]?){12,18}\d\b"], "validator": "luhn"},
    {"name": "iban", "patterns": [r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"], "validator": "iban"},
    {"name": "digits", "patterns": [r"\d{4} \d{4}"]},  # overlaps card numbers
    {"name": "secret", "patterns": [r"[A-Za-z0-9+/_-]{32,}"], "validator": "entropy",
     "context": ["key", "token"], "on_match": "block"},
    {"name": "codename", "keywords": ["Project Falcon"]},
    {"name": "disabled", "patterns": ["hello"], "enabled": False},
]
PARAMS = SensitiveData.Params.model_validate({"categories": CATEGORIES})


def input_check(*texts: str) -> Check:
    return Check(
        stage=Stage.input,
        agent=AGENT,
        messages=[Message(role="user", content=text) for text in texts],
    )


def output_check(text: str) -> Check:
    return Check(stage=Stage.output, agent=AGENT, message=Message(role="assistant", content=text))


def tool_result_check(text: str | None) -> Check:
    return Check(stage=Stage.tool_result, agent=AGENT, tool_result=text)


async def evaluate(check: Check, params=PARAMS):
    return await SensitiveData().evaluate(check, params)


def assert_no_leak(verdict, *values: str) -> None:
    for value in values:
        assert value not in verdict.reason
        assert all(value not in finding.detail for finding in verdict.findings)


def test_registered():
    assert REGISTRY.get("sensitive_data") is SensitiveData
    assert SensitiveData.stages == {Stage.input, Stage.output, Stage.tool_result}


def test_validator_names_in_sync():
    assert set(get_args(ValidatorName)) == set(VALIDATORS)


# --- Params: refused at Policy load -------------------------------------------------------


def policy_text(category_yaml: str, mode: str = "redact") -> str:
    return (
        f"controls:\n  sensitive_data:\n    mode: {mode}\n    params:\n      categories:\n"
        + category_yaml
    )


@pytest.mark.parametrize(
    "category_yaml, expected",
    [
        ("        - name: bad\n          patterns: ['(unclosed']\n", "invalid regex"),
        ("        - name: empty\n", "needs patterns or keywords"),
        ("        - name: typo\n          patern: ['x']\n          patterns: ['x']\n", "patern"),
        ("        - name: a\n          patterns: ['x']\n"
         "        - name: a\n          patterns: ['y']\n", "duplicate category names"),
        ("        - name: v\n          patterns: ['x']\n          validator: crc32\n", "validator"),
        ("        - name: w\n          patterns: ['x']\n          on_match: warn\n", "on_match"),
        ("        - name: Bad-Name\n          patterns: ['x']\n", "name"),
    ],
)
def test_invalid_categories_are_refused(category_yaml, expected):
    with pytest.raises(PolicyError) as info:
        parse_policy(policy_text(category_yaml), REGISTRY)
    message = str(info.value)
    assert "controls.sensitive_data.params" in message
    assert expected in message


GOOD_SENSITIVE = (
    "  sensitive_data:\n    mode: redact\n    params:\n      categories:\n"
    "        - name: email\n          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']\n"
)


def test_broken_category_keeps_last_good_policy(tmp_policy):
    store = PolicyStore(tmp_policy(BASE_POLICY + GOOD_SENSITIVE), REGISTRY)
    good_version = store.version
    tmp_policy(BASE_POLICY + GOOD_SENSITIVE + "        - name: phone\n          patterns: ['(']\n")
    assert store.get().version == good_version
    assert "phone" in store.last_error
    assert "invalid regex" in store.last_error


# --- Evaluation per Stage -----------------------------------------------------------------


async def test_output_allowed():
    verdict = await evaluate(output_check("The weather is fine today."))
    assert verdict.action == Action.allow
    assert verdict.findings == []


async def test_output_redacted():
    verdict = await evaluate(output_check(f"Write to {EMAIL} today."))
    assert verdict.action == Action.redact
    assert verdict.rewritten.message.content == "Write to [EMAIL] today."
    assert verdict.rewritten.message.role == "assistant"
    (finding,) = verdict.findings
    assert finding.type == "email"
    assert finding.control == "sensitive_data"
    assert finding.span == (9, 9 + len(EMAIL))
    assert finding.detail == f"email at 9..{9 + len(EMAIL)}"
    assert verdict.reason == "sensitive data: email (1)"
    assert verdict.risk_score == 0.7
    assert_no_leak(verdict, EMAIL)


async def test_input_only_the_matching_message_changes():
    check = input_check("hello", f"mail {EMAIL}", "bye")
    verdict = await evaluate(check)
    assert verdict.action == Action.redact
    assert [m.content for m in verdict.rewritten.messages] == ["hello", "mail [EMAIL]", "bye"]
    assert verdict.findings[0].detail.startswith("email in message 1 at ")
    assert_no_leak(verdict, EMAIL)


async def test_input_allowed():
    verdict = await evaluate(input_check("system rules", "What is the weather?"))
    assert verdict.action == Action.allow


async def test_tool_result_redacted():
    verdict = await evaluate(tool_result_check(f"Account: {IBAN}."))
    assert verdict.action == Action.redact
    assert verdict.rewritten.tool_result == "Account: [IBAN]."
    assert_no_leak(verdict, IBAN)


async def test_tool_result_allowed():
    assert (await evaluate(tool_result_check("client 7: ACME Corp"))).action == Action.allow


async def test_missing_content_is_allowed():
    assert (await evaluate(Check(stage=Stage.output, agent=AGENT))).findings == []
    assert (await evaluate(tool_result_check(None))).findings == []


# --- Category behaviour -------------------------------------------------------------------


async def test_validator_confirms_matches():
    verdict = await evaluate(output_check(f"card {CARD}"))
    assert verdict.rewritten.message.content == "card [CARD]"
    assert [f.type for f in verdict.findings] == ["card"]
    assert_no_leak(verdict, CARD)
    bad = "4111 1111 1111 1112"
    verdict = await evaluate(output_check(f"card {bad}"))
    assert "card" not in {f.type for f in verdict.findings}
    assert bad[:9] not in verdict.rewritten.message.content  # only the digits category hit it


async def test_context_is_required():
    assert (await evaluate(output_check(f"here: {SECRET}"))).action == Action.allow
    verdict = await evaluate(output_check(f"api_key = {SECRET}"))
    assert verdict.action == Action.block
    assert verdict.rewritten.message.content == "api_key = [SECRET]"
    assert_no_leak(verdict, SECRET)


async def test_keywords_are_whole_words_case_insensitive():
    verdict = await evaluate(output_check("status of project falcon?"))
    assert verdict.rewritten.message.content == "status of [CODENAME]?"
    assert (await evaluate(output_check("projectfalconer"))).action == Action.allow


async def test_disabled_category_never_matches():
    assert (await evaluate(output_check("hello"))).action == Action.allow


async def test_overlap_is_replaced_once():
    verdict = await evaluate(output_check(f"pay with {CARD} now"))
    assert verdict.rewritten.message.content == "pay with [CARD] now"
    assert len(verdict.findings) == 1


async def test_on_match_redact_and_block():
    redact = await evaluate(output_check(f"{EMAIL} and {CARD}"))
    assert redact.action == Action.redact
    assert redact.reason == "sensitive data: card (1), email (1)"
    block = await evaluate(output_check(f"{EMAIL} token {SECRET}"))
    assert block.action == Action.block
    assert block.risk_score == 1.0
    assert block.rewritten.message.content == "[EMAIL] token [SECRET]"


async def test_custom_replacement():
    params = SensitiveData.Params.model_validate(
        {"categories": [{"name": "pesel", "patterns": [r"\b\d{11}\b"],
                         "validator": "pesel_checksum", "replacement": "<ID>"}]}
    )
    verdict = await evaluate(output_check("id 44051401359"), params)
    assert verdict.rewritten.message.content == "id <ID>"


# --- Mode table through run_check ---------------------------------------------------------


def policy_with(mode: str, on_match: str):
    return parse_policy(
        policy_text(
            "        - name: email\n          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']\n"
            f"          on_match: {on_match}\n",
            mode,
        ),
        REGISTRY,
    )


async def test_monitor_mode_records_but_allows():
    result = await run_check(output_check(f"mail {EMAIL}"), policy_with("monitor", "block"))
    assert result.decision.action == Action.allow
    assert result.decision.findings
    assert result.after.message.content == f"mail {EMAIL}"
    assert result.decision.verdicts[0].mode == Mode.monitor


async def test_redact_mode_caps_block():
    result = await run_check(output_check(f"mail {EMAIL}"), policy_with("redact", "block"))
    assert result.decision.action == Action.redact
    assert result.after.message.content == "mail [EMAIL]"


async def test_block_mode_with_redact_category_redacts():
    result = await run_check(output_check(f"mail {EMAIL}"), policy_with("block", "redact"))
    assert result.decision.action == Action.redact
    assert result.after.message.content == "mail [EMAIL]"


async def test_block_mode_with_block_category_blocks():
    result = await run_check(output_check(f"mail {EMAIL}"), policy_with("block", "block"))
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by sensitive_data")
    assert EMAIL not in result.decision.reason
