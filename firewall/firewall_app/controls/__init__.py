"""Every Control module is imported here so it registers itself. Add one line per Control."""

from firewall_app.controls import keyword_blocklist  # noqa: F401
from firewall_app.controls.base import REGISTRY, Control, ControlContext, Registry, control

__all__ = ["REGISTRY", "Control", "ControlContext", "Registry", "control"]
