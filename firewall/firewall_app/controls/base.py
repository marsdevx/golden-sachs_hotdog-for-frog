"""Control base class and registry.

A Control is one small module: subclass `Control`, declare the Stages it supports and its
`Params`, implement `evaluate`, and decorate the class with `@control("<id>")`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel

from firewall_app.domain import Check, Stage, Verdict

# The `features:` switch of the Policy that turns each group of Controls on or off.
CONTROL_FEATURES = (
    "input_validation",
    "data_protection",
    "resource_access",
    "usage_limits",
    "attack_mitigation",
)


def utcnow() -> datetime:
    """Naive UTC, like the timestamps in the database."""
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True, slots=True)
class ControlContext:
    """Dependencies injected into every Control. Controls keep state here, never in globals."""

    db: Any = None  # SQLAlchemy async_sessionmaker, when the app has storage
    clock: Callable[[], datetime] = field(default=utcnow)  # tests inject a fake clock


class Control:
    id: ClassVar[str] = ""
    stages: ClassVar[set[Stage]] = set()
    feature: ClassVar[str] = ""  # one of CONTROL_FEATURES
    description: ClassVar[str] = ""

    class Params(BaseModel):
        pass

    def __init__(self, ctx: ControlContext | None = None) -> None:
        self.ctx = ctx or ControlContext()

    async def evaluate(self, check: Check, params: Any) -> Verdict:
        raise NotImplementedError


C = TypeVar("C", bound=type[Control])


class Registry:
    """Maps Control id to Control class."""

    def __init__(self) -> None:
        self._controls: dict[str, type[Control]] = {}

    def control(self, control_id: str) -> Callable[[C], C]:
        def register(cls: C) -> C:
            existing = self._controls.get(control_id)
            if existing is not None and existing.__qualname__ != cls.__qualname__:
                raise ValueError(f"Control id {control_id!r} is already registered")
            if not cls.stages or not all(isinstance(stage, Stage) for stage in cls.stages):
                raise ValueError(f"Control {control_id!r} must declare its supported stages")
            if cls.feature not in CONTROL_FEATURES:
                raise ValueError(
                    f"Control {control_id!r} must declare its feature, one of {CONTROL_FEATURES}"
                )
            if not (isinstance(cls.Params, type) and issubclass(cls.Params, BaseModel)):
                raise ValueError(f"Control {control_id!r} Params must be a pydantic model")
            cls.id = control_id
            self._controls[control_id] = cls
            return cls

        return register

    def get(self, control_id: str) -> type[Control] | None:
        return self._controls.get(control_id)

    def all(self) -> dict[str, type[Control]]:
        return dict(self._controls)

    def __contains__(self, control_id: object) -> bool:
        return control_id in self._controls


REGISTRY = Registry()
control = REGISTRY.control
