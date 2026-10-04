"""Every built-in category shipped in policy.yaml finds its sample and leaves look-alikes alone."""

import pytest
from conftest import POLICY_FILE
from firewall_app.controls import REGISTRY
from firewall_app.controls.sensitive_data import SensitiveData
from firewall_app.domain import Action, Agent, Check, Message, Stage
from firewall_app.policy import PolicyStore

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
PARAMS = PolicyStore(POLICY_FILE, REGISTRY).get().controls[
    "sensitive_data"
].parsed_params

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
SAMPLES = {
    "email": ["Contact jan.kowalski@bank.example", "write to jan [at] bank [dot] com"],
    "phone": ["Call +48 600 123 456 tomorrow"],
    "card": ["Card 4111 1111 1111 1111 on file"],
    "iban": ["Pay to DE89 3704 0044 0532 0130 00"],
    "aws_access_key": ["key AKIAIOSFODNN7EXAMPLE in config"],
    "github_token": ["token ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"],
    "llm_api_key": ["use sk-ant-api03-abcdefghijklmnopqrstuvwxyz"],
    "private_key": [PEM],
    "jwt": ["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"],
    "generic_secret": ["password: q8ZfK2mXv9LpR4tWb7NcY1hJ3sDgA6eUoP0iTzQx"],
    "mna_client": ["Acquirer: Nordbank AG"],
}
NEGATIVES = [
    "request id 123e4567-e89b-12d3-a456-426614174000",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b",
    "order 1234567890",
    "The quarterly results were in line with expectations.",
]


async def evaluate(text: str):
    check = Check(stage=Stage.output, agent=AGENT, message=Message(role="assistant", content=text))
    return await SensitiveData().evaluate(check, PARAMS)


def test_every_category_has_a_sample():
    assert {category.name for category in PARAMS.categories} == set(SAMPLES)


@pytest.mark.parametrize(
    "category, text", [(name, text) for name, texts in SAMPLES.items() for text in texts]
)
async def test_builtin_category_finds_its_sample(category, text):
    verdict = await evaluate(text)
    assert category in {finding.type for finding in verdict.findings}
    assert f"[{category.upper()}]" in verdict.rewritten.message.content


@pytest.mark.parametrize("text", NEGATIVES)
async def test_look_alikes_are_not_sensitive(text):
    verdict = await evaluate(text)
    assert verdict.action == Action.allow
    assert verdict.findings == []
