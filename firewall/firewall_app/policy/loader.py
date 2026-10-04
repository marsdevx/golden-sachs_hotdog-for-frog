"""PolicyStore: the live Policy, hot reloaded from its file."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

from firewall_app.controls.base import Registry
from firewall_app.policy.presets import presets_dir_for
from firewall_app.policy.schema import Policy, PolicyError, parse_policy

logger = logging.getLogger("firewall.policy")


def policy_version(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def _stamp(path: Path | None) -> tuple[int, int] | None:
    if path is None:
        return None
    stat = path.stat()
    return (stat.st_mtime_ns, stat.st_size)


class PolicyStore:
    """Checks the mtime of the Policy file and of its preset file on every `get()` and reloads
    when either changed.
    An invalid file keeps the last good Policy and is reported in `last_error`.
    Read-only: the firewall never writes the Policy file; people edit it."""

    def __init__(self, path: str | Path, registry: Registry) -> None:
        self.path = Path(path)
        self.registry = registry
        self.last_error: str | None = None
        self.loaded_at: datetime | None = None
        self._policy: Policy | None = None
        self._text = ""
        self.presets_dir = presets_dir_for(self.path)
        self._stamp: tuple | None = None
        self._preset_file: Path | None = None
        self._reload()
        if self._policy is None:
            raise PolicyError([f"cannot load Policy {self.path}: {self.last_error}"])

    @property
    def text(self) -> str:
        """The YAML of the Policy currently in force (the last good one)."""
        return self._text

    @property
    def version(self) -> str:
        return self.get().version

    def get(self) -> Policy:
        try:
            stamp = (_stamp(self.path), _stamp(self._preset_file))
        except OSError as exc:
            self._fail(f"cannot read {self.path}: {exc}")
            stamp = self._stamp
        if stamp != self._stamp:
            self._reload()
        assert self._policy is not None
        return self._policy

    def _reload(self) -> None:
        try:
            stamp = _stamp(self.path)
            data = self.path.read_bytes()
        except OSError as exc:
            self._fail(f"cannot read {self.path}: {exc}")
            return
        # Remember the stamp even on failure, so a broken file is not re-parsed on every get().
        self._stamp = (stamp, self._safe_stamp(self._preset_file))
        try:
            text = data.decode("utf-8")
            policy = parse_policy(text, self.registry, self.presets_dir)
        except (PolicyError, UnicodeDecodeError) as exc:
            self._fail(str(exc))
            return
        # Watch the preset file too: editing presets/strict.yaml applies like editing the Policy.
        self._preset_file = policy.preset_file
        self._stamp = (stamp, self._safe_stamp(self._preset_file))
        policy._version = policy_version(data + policy._preset_text.encode())
        self._policy = policy
        self._text = text
        self.loaded_at = datetime.now(UTC)
        self.last_error = None
        logger.info("Policy %s loaded from %s", policy.version, self.path)
        for warning in policy.warnings:
            logger.warning("Policy %s: %s", self.path, warning)

    @staticmethod
    def _safe_stamp(path: Path | None) -> tuple[int, int] | None:
        try:
            return _stamp(path)
        except OSError:
            return None

    def _fail(self, error: str) -> None:
        if error != self.last_error:
            logger.error("Policy %s rejected, keeping the last good Policy: %s", self.path, error)
        self.last_error = error
