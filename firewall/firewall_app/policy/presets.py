"""Presets: ready-made strictness levels laid over policy.yaml.

`preset:` in the Policy names one of `permissive`, `standard`, `strict`, or `custom`.
`custom` runs the Policy exactly as written. Any other name reads `presets/<name>.yaml`, a
small file holding only the differences (Modes, Stages, params), and merges its `controls:`
into the Policy before validation: mappings are merged key by key, everything else (lists,
numbers, strings) is replaced. A preset never adds a Control the Policy does not list, and
never touches Agents, Upstreams or folders: only how strict the listed Controls are.

`presets/` is looked up next to the Policy file first (Docker: /config/presets), then in the
repository root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PRESETS = ("permissive", "standard", "strict")
CUSTOM = "custom"
DEFAULT_PRESETS_DIR = Path(__file__).resolve().parents[3] / "presets"


def presets_dir_for(policy_path: Path) -> Path:
    sibling = policy_path.parent / "presets"
    return sibling if sibling.is_dir() else DEFAULT_PRESETS_DIR


def preset_path(name: Any, presets_dir: Path | None) -> Path | None:
    """The overlay file of preset `name`, or None for `custom`. Raises ValueError."""
    if name == CUSTOM:
        return None
    if name not in PRESETS:
        raise ValueError(f"preset: unknown preset {name!r} (one of {', '.join(PRESETS)}, {CUSTOM})")
    if presets_dir is None:
        raise ValueError(f"preset: {name!r} needs the presets folder; use {CUSTOM!r} here")
    return presets_dir / f"{name}.yaml"


def merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            merged[key] = merge(base[key], value) if key in base else value
        return merged
    return overlay


def apply_preset(data: dict, name: str, overlay_text: str) -> list[str]:
    """Merge the preset's `controls:` into `data` in place. Returns warnings."""
    try:
        overlay = yaml.safe_load(overlay_text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"presets/{name}.yaml: invalid YAML: {exc}") from exc
    if not isinstance(overlay, dict) or set(overlay) - {"controls"}:
        raise ValueError(f"presets/{name}.yaml: may only hold a `controls:` section")
    controls = data.get("controls") or {}
    warnings = []
    for control_id, section in (overlay.get("controls") or {}).items():
        if control_id not in controls:
            warnings.append(f"preset {name}: controls.{control_id} is not in the Policy, skipped")
            continue
        if not isinstance(section, dict):
            raise ValueError(f"presets/{name}.yaml: controls.{control_id} must be a mapping")
        controls[control_id] = merge(controls[control_id] or {}, section)
    return warnings
