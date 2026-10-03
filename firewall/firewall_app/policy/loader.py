"""PolicyStore: the live Policy, hot reloaded from its file."""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from firewall_app.controls.base import Registry
from firewall_app.policy.schema import Policy, PolicyError, parse_policy

logger = logging.getLogger("firewall.policy")


def policy_version(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


class PolicyStore:
    """Checks the file's mtime on every `get()` and reloads when it changed.
    An invalid file keeps the last good Policy and is reported in `last_error`."""

    def __init__(self, path: str | Path, registry: Registry) -> None:
        self.path = Path(path)
        self.registry = registry
        self.last_error: str | None = None
        self.loaded_at: datetime | None = None
        self._policy: Policy | None = None
        self._text = ""
        self._stamp: tuple[int, int] | None = None
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
            stat = self.path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
        except OSError as exc:
            self._fail(f"cannot read {self.path}: {exc}")
            stamp = self._stamp
        if stamp != self._stamp:
            self._reload()
        assert self._policy is not None
        return self._policy

    def validate(self, text: str) -> Policy:
        return parse_policy(text, self.registry)

    def write(self, text: str) -> Policy:
        """Validate first, then replace the file atomically. Raises PolicyError if invalid."""
        self.validate(text)
        directory = self.path.parent
        fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{self.path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            self._copy_ownership(tmp_name)
            os.replace(tmp_name, self.path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        self._reload()
        return self.get()

    def _copy_ownership(self, tmp_name: str) -> None:
        # Keep the file editable by whoever owned it (e.g. the host user behind a bind mount).
        try:
            stat = self.path.stat()
        except OSError:
            os.chmod(tmp_name, 0o644)
            return
        os.chmod(tmp_name, stat.st_mode & 0o777)
        try:
            os.chown(tmp_name, stat.st_uid, stat.st_gid)
        except OSError:
            pass

    def _reload(self) -> None:
        try:
            stat = self.path.stat()
            data = self.path.read_bytes()
        except OSError as exc:
            self._fail(f"cannot read {self.path}: {exc}")
            return
        # Remember the stamp even on failure, so a broken file is not re-parsed on every get().
        self._stamp = (stat.st_mtime_ns, stat.st_size)
        try:
            text = data.decode("utf-8")
            policy = parse_policy(text, self.registry)
        except (PolicyError, UnicodeDecodeError) as exc:
            self._fail(str(exc))
            return
        policy._version = policy_version(data)
        self._policy = policy
        self._text = text
        self.loaded_at = datetime.now(UTC)
        self.last_error = None
        logger.info("Policy %s loaded from %s", policy.version, self.path)

    def _fail(self, error: str) -> None:
        if error != self.last_error:
            logger.error("Policy %s rejected, keeping the last good Policy: %s", self.path, error)
        self.last_error = error
