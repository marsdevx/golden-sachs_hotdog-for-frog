"""Fixtures for the acceptance suites.

Every test gets its own copy of the real Policy (`policy.yaml`), its own SQLite file and its
own firewall app, all in a temp dir. See harness.py for the helpers.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from firewall_app.main import create_app

from test_suites.harness import POLICY_FILE, FakeClock, Gateway, PolicyFile


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "uc(id): stakeholder use case, e.g. UC-02")
    config.addinivalue_line("markers", "req(ids): challenge requirement, e.g. R2.1")


@pytest.fixture(autouse=True)
def offline_injection_model(request, monkeypatch):
    """The Presets run injection_classifier with the real ONNX model. Tests must not depend on
    whether the `ml` extra is installed, so the model is a stub that scores everything safe.
    Tests marked `ml` get the real model."""
    if request.node.get_closest_marker("ml"):
        return
    from firewall_app.controls.injection_model import MockScorer

    monkeypatch.setattr(
        "firewall_app.controls.injection_classifier.onnx_scorer",
        lambda model, model_dir: MockScorer({}),
    )


@pytest.fixture
def make_gateway(tmp_path, monkeypatch):
    """`make_gateway()` starts a firewall on a temp copy of policy.yaml."""
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    counter = 0

    def make() -> Gateway:
        nonlocal counter
        counter += 1
        folder = tmp_path / f"fw{counter}"
        folder.mkdir()
        path = folder / "policy.yaml"
        path.write_bytes(POLICY_FILE.read_bytes())
        app = create_app(
            policy_path=str(path), database_url=f"sqlite+aiosqlite:///{folder / 'firewall.db'}"
        )
        # The same hook the core's own tests use: time is the Controls' injected clock.
        clock = FakeClock()
        app.state.service.ctx = replace(app.state.service.ctx, clock=clock)
        return Gateway(TestClient(app), PolicyFile(path), clock)

    return make


@pytest.fixture
def gateway(make_gateway) -> Gateway:
    return make_gateway()
