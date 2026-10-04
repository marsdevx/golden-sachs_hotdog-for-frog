"""Every Control module is imported here so it registers itself. Add one line per Control."""

from firewall_app.controls import (  # noqa: F401
    attack_signatures,
    injection_classifier,
    injection_heuristics,
    keyword_blocklist,
    loop_detector,
    output_sanitizer,
    request_limits,
    resource_access,
    sensitive_data,
    token_budget,
)
from firewall_app.controls.base import REGISTRY, Control, ControlContext, Registry, control

__all__ = ["REGISTRY", "Control", "ControlContext", "Registry", "control"]
