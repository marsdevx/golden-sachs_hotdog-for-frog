from __future__ import annotations

import itertools
import os
import stat
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from firewall_app.domain import ToolCall

ROOT = Path(__file__).resolve().parent.parent / "demo_data"
ACTIONS = {"list_files", "read_file", "delete_file"}
# Deleting is limited to this folder by the gateway itself, whatever the Policy says.
DELETABLE = ("/", "demo", "sandbox")


class FileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str = Field(min_length=1, max_length=1024)


def definitions() -> list[dict]:
    return [{
        "type": "function",
        "function": {
            "name": name, "description": description,
            "parameters": FileArgs.model_json_schema(),
        },
    } for name, description in (
        ("list_files", "List files in the demo directory. Use absolute paths under /demo."),
        ("read_file", "Read a UTF-8 demo file, e.g. /demo/contacts.txt. Maximum 32 KiB."),
        ("delete_file", "Delete one file under /demo/sandbox, e.g. /demo/sandbox/scratch.txt."),
    )]


def validate(tool: ToolCall) -> ToolCall:
    if tool.resource != "files" or tool.action not in ACTIONS:
        raise ValueError("unknown tool")
    args = FileArgs.model_validate(tool.args)
    parts = PurePosixPath(args.path).parts
    if not parts or parts[:2] != ("/", "demo") or ".." in parts or "\\" in args.path:
        raise ValueError("path must be inside /demo")
    if tool.action == "delete_file" and (len(parts) <= 3 or parts[:3] != DELETABLE):
        raise ValueError("delete is only allowed inside /demo/sandbox")
    return tool.model_copy(update={"args": {"path": str(PurePosixPath(args.path))}})


def execute(tool: ToolCall, root: Path = ROOT) -> str:
    """Walk from an open root descriptor; never follow symlinks or open special files."""
    tool = validate(tool)
    parts = PurePosixPath(tool.args["path"]).parts[2:]
    if tool.action == "delete_file":
        # Open only the parent folders; the last part is the file to remove.
        *parts, target = parts
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            directory = index < len(parts) - 1 or tool.action in {"list_files", "delete_file"}
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        if tool.action == "delete_file":
            # unlink never follows a symlink; the check only refuses links and special files.
            if not stat.S_ISREG(os.stat(target, dir_fd=fd, follow_symlinks=False).st_mode):
                raise ValueError("not a regular file")
            os.unlink(target, dir_fd=fd)
            return f"Deleted {tool.args['path']}"
        info = os.fstat(fd)
        if tool.action == "list_files":
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("not a directory")
            with os.scandir(fd) as entries:
                names = [entry.name for entry in itertools.islice(entries, 101)]
            if len(names) > 100:
                raise ValueError("directory exceeds demo limit")
            return "\n".join(sorted(names)) or "(empty directory)"
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32768:
            raise ValueError("not a bounded regular file")
        data = bytearray()
        while len(data) <= 32768:
            chunk = os.read(fd, min(4096, 32769 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 32768:
            raise ValueError("file exceeds demo limit")
        return data.decode("utf-8")
    finally:
        os.close(fd)
