"""Folder access: which folders on this PC the AI may read or write through a file Resource.

The firewall runs on the user's own PC and the user sets these rules for themselves. Default
deny: each Access Rule names a folder and an access level (`none`, `read`, `write`); a path
outside every listed folder gets `default`. For every path in a tool call:

1. the deepest folder containing the path decides;
2. two rules for the same folder: the strictest wins.

So YAML order never matters, and `~/Documents/Private: none` carves a hole into a broader
`~/Documents: read`.

Paths are normalized before matching (`..`, `.`, `//`, backslashes), so
`/home/me/Projects/../.ssh` is checked as `/home/me/.ssh`. Windows paths (`C:\\Users\\me`) are
supported and compared case-insensitively. The firewall never sees the file system: symlinks
are not resolved, so the tool behind the Resource must not follow links out of its folders.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Finding, Stage, Verdict

Access = Literal["none", "read", "write"]
ActionClass = Literal["read", "write"]

ACCESS_RANK: dict[str, int] = {"none": 0, "read": 1, "write": 2}
RISK: dict[str, float] = {"read": 0.3, "write": 0.6}
INVALID_PATH_RISK = 0.9

_DRIVE = re.compile(r"^([A-Za-z]):(/.*)?$")


def _is_absolute(path: str) -> bool:
    return path.startswith("/") or _DRIVE.match(path) is not None


def normalize_path(raw: str, base_dir: str = "/") -> str:
    """An absolute, normalized path (`/a/b` or `c:/a/b`). Raises ValueError when we refuse it."""
    if not raw or not raw.strip():
        raise ValueError("empty path")
    if "\x00" in raw:
        raise ValueError("NUL byte in path")
    path = raw.strip().replace("\\", "/")
    if path.startswith("~"):
        raise ValueError("home-relative path")
    if "://" in path:
        raise ValueError("URL instead of a path")
    if re.match(r"^[A-Za-z]:(?!/|$)", path):
        raise ValueError("drive-relative Windows path")
    if not _is_absolute(path):
        path = base_dir.rstrip("/") + "/" + path
    drive = _DRIVE.match(path)
    if drive:
        # Windows file systems ignore case: compare lowercased.
        rest = "/" + posixpath.normpath("/" + (drive.group(2) or "/")).lstrip("/")
        return f"{drive.group(1)}:{rest}".lower()
    # normpath keeps a leading "//"; collapse it so it cannot dodge prefix matching.
    return "/" + posixpath.normpath(path).lstrip("/")


def contains(folder: str, path: str) -> bool:
    """True when `path` is `folder` or inside it (on a `/` boundary)."""
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def depth(path: str) -> int:
    return len([part for part in path.split("/") if part])


class Folder(BaseModel):
    """One Access Rule: what the AI may do inside `path`."""

    model_config = ConfigDict(extra="forbid")

    path: str
    access: Access
    description: str = ""

    @field_validator("path")
    @classmethod
    def _absolute_and_normalized(cls, value: str) -> str:
        if not _is_absolute(value.strip().replace("\\", "/")):
            raise ValueError("folder path must be absolute (/home/me/... or C:\\Users\\me\\...)")
        return normalize_path(value)


DEFAULT_ACTION_CLASSES: dict[str, ActionClass] = {
    "read_file": "read",
    "list_dir": "read",
    "list_files": "read",
    "search": "read",
    "write_file": "write",
    "delete_file": "write",
    "move": "write",
    "make_dir": "write",
}
DEFAULT_PATH_ARGS = [
    "path", "paths", "file", "files", "dir", "directory", "folder",
    "src", "source", "dst", "destination", "target",
]


class Params(BaseModel):
    # Which Resources are file systems. Calls to other Resources are not this Control's concern.
    resources: list[str] = Field(default_factory=lambda: ["files"], min_length=1)
    # Action -> read | write. An action not listed here counts as `write` (the stricter one).
    action_classes: dict[str, ActionClass] = Field(
        default_factory=lambda: dict(DEFAULT_ACTION_CLASSES)
    )
    # Argument names (at any nesting depth) that hold a path or a list of paths.
    path_args: list[str] = Field(default_factory=lambda: list(DEFAULT_PATH_ARGS), min_length=1)
    # Relative paths are resolved against this folder.
    base_dir: str = "/"
    # Access to any path outside every listed folder. `none` = default deny.
    default: Access = "none"
    folders: list[Folder] = Field(default_factory=list)

    @field_validator("base_dir")
    @classmethod
    def _base_dir_absolute(cls, value: str) -> str:
        if not _is_absolute(value.strip().replace("\\", "/")):
            raise ValueError("base_dir must be absolute")
        return normalize_path(value)


def action_class(params: Params, action: str) -> ActionClass:
    return params.action_classes.get(action, "write")


def governs(params: Params, resource: str) -> bool:
    return "*" in params.resources or resource in params.resources


def deciding_rule(params: Params, path: str) -> int | None:
    """Index of the Access Rule that decides `path`, or None (then `default` applies)."""
    candidates = [i for i, folder in enumerate(params.folders) if contains(folder.path, path)]
    if not candidates:
        return None
    # Deepest folder first; for the same folder the strictest (lowest rank) wins.
    return max(
        candidates,
        key=lambda i: (depth(params.folders[i].path), -ACCESS_RANK[params.folders[i].access]),
    )


def effective_access(params: Params, path: str) -> tuple[Access, int | None]:
    index = deciding_rule(params, path)
    if index is None:
        return params.default, None
    return params.folders[index].access, index


def extract_paths(args: Any, names: set[str]) -> Iterator[tuple[str, Any]]:
    """Every (argument name, value) under a path argument name, nested dicts and lists included."""
    if isinstance(args, dict):
        for name, value in args.items():
            if name in names:
                if isinstance(value, list):
                    for item in value:
                        yield name, item
                else:
                    yield name, value
            else:
                yield from extract_paths(value, names)
    elif isinstance(args, list):
        for item in args:
            yield from extract_paths(item, names)


@control("resource_access")
class ResourceAccess(Control):
    stages = {Stage.tool_call}
    feature = "resource_access"
    description = "The AI may only read or write files in the folders you allow here."
    Params = Params

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        tool = check.tool
        if tool is None:
            raise ValueError("tool_call Check without a tool")
        if not governs(params, tool.resource):
            return Verdict()

        call = f"{tool.resource}.{tool.action}"
        required = action_class(params, tool.action)
        values = list(extract_paths(tool.args, set(params.path_args)))
        if not values:
            return Verdict(
                action=Action.block,
                reason=f"{call} names no path, so folder access cannot be checked",
                risk_score=RISK[required],
                findings=[Finding(control=self.id, type="no_path", detail=f"{call} has no path")],
            )

        findings: list[Finding] = []
        reasons: list[str] = []
        risk = 0.0
        for arg, value in values:
            # Never put the requested path itself in a reason or Finding: file names can carry
            # personal data, and Decisions are stored. Name the argument and the rule's folder.
            try:
                if not isinstance(value, str):
                    raise ValueError(f"expected a string, got {type(value).__name__}")
                path = normalize_path(value, params.base_dir)
            except ValueError as exc:
                findings.append(
                    Finding(control=self.id, type="invalid_path", detail=f"{arg}: {exc}")
                )
                reasons.append(f"argument {arg!r} is not a usable path ({exc})")
                risk = max(risk, INVALID_PATH_RISK)
                continue

            granted, index = effective_access(params, path)
            if ACCESS_RANK[granted] >= ACCESS_RANK[required]:
                continue
            risk = max(risk, RISK[required])
            if index is None:
                findings.append(
                    Finding(
                        control=self.id,
                        type="outside_folders",
                        detail=f"{arg}: outside every listed folder (default: {params.default})",
                    )
                )
                reasons.append(
                    f"{arg!r} is outside every allowed folder; {call} needs {required} "
                    f"(default: {params.default})"
                )
            else:
                folder = params.folders[index]
                findings.append(
                    Finding(
                        control=self.id,
                        type="folder_denied",
                        detail=f"{arg}: under {folder.path} (folders[{index}]: {folder.access})",
                    )
                )
                allowed = "no access" if folder.access == "none" else f"only {folder.access}"
                reasons.append(
                    f"folders[{index}] allows {allowed} in {folder.path}; {call} needs {required}"
                )

        if not findings:
            return Verdict()
        return Verdict(
            action=Action.block,
            reason="; ".join(dict.fromkeys(reasons)),
            risk_score=risk,
            findings=findings,
        )
