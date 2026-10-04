import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = REPO_ROOT / "policy.yaml"
AGENT_KEY = "test-agent-key"

BASE_POLICY = f"""
version_note: "test policy"
defaults:
  unknown_agent: block
  on_error: block
agents:
  - key: "{AGENT_KEY}"
    id: "test-agent"
    owner: "owner@bank.example"
    team: "test-team"
upstreams:
  - models: ["mock"]
    base_url: "mock://"
  - models: ["remote-model"]
    base_url: "http://upstream.test/v1"
allowed_models: ["mock", "remote-model"]
audit:
  store_content: redacted
controls:
  keyword_blocklist:
    mode: block
    params:
      keywords: ["project falcon"]
"""


@pytest.fixture(autouse=True)
def offline_injection_model(request, monkeypatch):
    """policy.yaml runs injection_classifier with the real ONNX model. Tests must not depend on
    whether the `ml` extra is installed, so the model is a stub that scores everything safe.
    Tests marked `ml` get the real model."""
    if request.node.get_closest_marker("ml"):
        return
    from firewall_app.controls.injection_model import MockScorer

    monkeypatch.setattr(
        "firewall_app.controls.injection_classifier.onnx_scorer",
        lambda model, model_dir: MockScorer({}),
    )


def bump_mtime(path: Path) -> None:
    """Make sure the PolicyStore sees a change even on coarse-mtime filesystems."""
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


@pytest.fixture
def tmp_policy(tmp_path):
    """Write a Policy file and return its path: `tmp_policy(yaml_text)`."""
    path = tmp_path / "policy.yaml"

    def write(yaml_text: str = BASE_POLICY) -> Path:
        existed = path.exists()
        path.write_text(yaml_text)
        if existed:
            bump_mtime(path)
        return path

    return write


@pytest.fixture
def make_firewall_app(tmp_path, tmp_policy):
    """Build a firewall app on a tmp Policy and a tmp SQLite file."""
    from firewall_app.main import create_app

    def make(yaml_text: str = BASE_POLICY, upstream_transport=None):
        return create_app(
            policy_path=str(tmp_policy(yaml_text)),
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'firewall.db'}",
            upstream_transport=upstream_transport,
        )

    return make


@pytest.fixture
def firewall_app(make_firewall_app):
    return make_firewall_app()


@pytest.fixture
def agent_headers():
    return {"X-Agent-Key": AGENT_KEY}


@pytest.fixture
def make_chat_app(firewall_app):
    """Build a chat app whose FirewallClient talks to `firewall_app` over ASGI."""
    import httpx
    from app.config import Settings
    from app.firewall_client import FirewallClient
    from app.main import create_app

    def make(upstream=None, agent_key: str = AGENT_KEY):
        if upstream is not None:
            firewall_app.state.upstream_transport = upstream
        client = FirewallClient(
            Settings(agent_key=agent_key, llm_model="remote-model" if upstream else "mock"),
            transport=httpx.ASGITransport(app=firewall_app)
        )
        return create_app(client)

    return make


@pytest.fixture
def chat_app(make_chat_app):
    return make_chat_app()
