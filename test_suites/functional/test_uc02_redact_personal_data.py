"""UC-02: personal and payment data is removed from what the AI returns (R2.1, R1).

The agent asks nothing special and its code never changes. The operator decides what is
removed by editing the Policy (`controls.sensitive_data`), and the firewall applies it on the
next request. The built-in `mock` model echoes the question, so the text a test sends is the
"model answer" the firewall inspects.
"""

from __future__ import annotations

import json

import pytest

from test_suites.harness import load_cases

pytestmark = [pytest.mark.uc("UC-02"), pytest.mark.req("R2.1", "R1")]

EMAIL = "ivan.petrov@bank.com"
CARD = "4111 1111 1111 1111"
IBAN = "GB82WEST12345698765432"
PHONE = "+48 600 123 456"
KNOWN_GAP = pytest.mark.xfail(
    reason="known gap in the Policy, see data/personal_data.yaml", strict=False
)


def params(group: str) -> list:
    return [
        pytest.param(case, id=case["id"],
                     marks=[KNOWN_GAP] if case.get("tier") == "stretch" else [])
        for case in load_cases("personal_data", group)
    ]


# ---- 1. what is removed, and what is left alone ---------------------------------------------


@pytest.mark.parametrize("case", params("redact"))
def test_personal_data_is_removed_from_the_answer(gateway, case):
    reply = gateway.chat(f"Client record: {case['text']} end of record.")

    assert reply.status == 200
    assert case["text"] not in reply.answer, "the value reached the agent"
    assert gateway.policy.label(case["category"]) in reply.answer
    # Only the sensitive part is replaced; the rest of the answer survives.
    assert "Client record:" in reply.answer and "end of record." in reply.answer
    assert reply.firewall["action"] == "redact"
    assert reply.finish_reason == "stop"  # redacted answers are delivered, not blocked


@pytest.mark.parametrize("case", params("keep"))
def test_text_that_only_looks_like_personal_data_is_untouched(gateway, case):
    reply = gateway.chat(f"Note: {case['text']} thanks.")

    assert f"Note: {case['text']} thanks." in reply.answer
    assert reply.firewall["action"] == "allow"
    assert reply.firewall["output"]["decision"]["findings"] == []


def test_every_kind_in_one_answer_is_removed(gateway):
    reply = gateway.chat(f"Client {EMAIL}, phone {PHONE}, card {CARD}, account {IBAN}.")

    for value in (EMAIL, PHONE, CARD, IBAN):
        assert value not in reply.answer
    for category in ("email", "phone", "card", "iban"):
        assert gateway.policy.label(category) in reply.answer
    found = {f["type"] for f in reply.firewall["output"]["decision"]["findings"]}
    assert found == {"email", "phone", "card", "iban"}


def test_the_explanation_never_repeats_the_value(gateway):
    """Decisions go back to the agent and into logs: they say what was found, not the value."""
    reply = gateway.chat(f"Client {EMAIL}, card {CARD}, account {IBAN}.")

    assert reply.firewall["output"]["decision"]["findings"], "nothing was found"
    for value in (EMAIL, CARD, IBAN):
        assert value not in json.dumps(reply.firewall)


# ---- 2. the operator changes behaviour through the Policy, no restart ------------------------


def test_switching_a_category_off_and_on_changes_the_next_answer(gateway):
    text = f"Client {EMAIL}, card {CARD}."
    assert CARD not in gateway.chat(text).answer

    gateway.policy.set_category("card", enabled=False)
    reply = gateway.chat(text)
    assert CARD in reply.answer, "the card should now pass"
    assert EMAIL not in reply.answer, "other categories keep working"

    gateway.policy.set_category("card", enabled=True)
    assert CARD not in gateway.chat(text).answer


def test_monitor_mode_records_but_does_not_change_the_answer(gateway):
    gateway.policy.set_mode("sensitive_data", "monitor")
    reply = gateway.chat(f"Client {EMAIL}.")

    assert EMAIL in reply.answer
    assert reply.firewall["action"] == "allow"
    verdict = next(v for v in reply.output_verdicts if v["control"] == "sensitive_data")
    assert verdict["action"] == "redact" and verdict["effective_action"] == "allow"
    assert verdict["findings"], "monitor still records what it saw"


def test_off_mode_does_not_run_the_control(gateway):
    gateway.policy.set_mode("sensitive_data", "off")
    reply = gateway.chat(f"Client {EMAIL}.")

    assert EMAIL in reply.answer
    assert "sensitive_data" not in {v["control"] for v in reply.output_verdicts}


def test_a_category_can_be_set_to_block_instead_of_redact(gateway):
    gateway.policy.set_mode("sensitive_data", "block")
    gateway.policy.set_category("card", on_match="block")

    blocked = gateway.chat(f"Card {CARD}.")
    assert blocked.finish_reason == "content_filter"
    assert CARD not in blocked.answer
    assert blocked.firewall["action"] == "block"
    assert "card" in blocked.firewall["reason"]

    # Other categories still redact: Block vs Redact is decided per category.
    redacted = gateway.chat(f"Mail {EMAIL}.")
    assert redacted.finish_reason == "stop" and EMAIL not in redacted.answer


@pytest.mark.parametrize(
    ("mode", "email_visible", "action"),
    [("monitor", True, "allow"), ("redact", False, "redact"), ("block", False, "redact")],
)
def test_mode_sets_how_strict_the_control_is(gateway, mode, email_visible, action):
    gateway.policy.set_mode("sensitive_data", mode)
    reply = gateway.chat(f"Client {EMAIL}.")

    assert (EMAIL in reply.answer) is email_visible
    assert reply.firewall["action"] == action


# ---- 3. other Stages and the audit trail ----------------------------------------------------


def test_data_coming_back_from_a_resource_is_removed_too(gateway):
    """The Agent asked a Resource (e.g. a CRM) and the firewall checks what it returned."""
    result = gateway.check(
        "tool_result",
        {
            "tool": {"resource": "crm", "action": "read_client", "args": {}},
            "tool_result": f"Client {EMAIL}, card {CARD}",
        },
    )

    assert result["decision"]["action"] == "redact"
    assert EMAIL not in result["tool_result"] and CARD not in result["tool_result"]
    assert gateway.policy.label("card") in result["tool_result"]


@pytest.mark.parametrize("store_content", ["redacted", "none"])
def test_the_audit_log_of_the_answer_has_no_raw_value(gateway, store_content):
    gateway.policy.set_store_content(store_content)
    gateway.chat(f"Client {EMAIL}, card {CARD}.")

    (event,) = gateway.events(stage="output")
    assert event["action"] == "redact"
    assert {f["type"] for f in event["findings"]} == {"email", "card"}
    assert EMAIL not in json.dumps(event) and CARD not in json.dumps(event)


@pytest.mark.xfail(
    reason="the Presets run sensitive_data on output and tool_result only, so the audit event "
    "of the INPUT keeps what the user typed",
    strict=False,
)
def test_the_audit_log_of_the_question_has_no_raw_value(gateway):
    gateway.chat(f"Client {EMAIL}, card {CARD}.")

    (event,) = gateway.events(stage="input")
    assert EMAIL not in json.dumps(event) and CARD not in json.dumps(event)
