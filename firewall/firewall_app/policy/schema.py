"""Pydantic models of policy.yaml, plus validation against the Control registry."""

from __future__ import annotations

from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from firewall_app.controls.base import Registry
from firewall_app.domain import Mode, Stage
from firewall_app.providers import registry as provider_registry

FailAction = Literal["block", "allow"]


class StrictModel(BaseModel):
    # Typos in the Policy are errors, not silently ignored settings.
    model_config = ConfigDict(extra="forbid")


class Defaults(StrictModel):
    unknown_agent: FailAction = "block"
    on_error: FailAction = "block"


class AgentEntry(StrictModel):
    key: str = Field(min_length=1)
    id: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    team: str | None = None


class UpstreamEntry(StrictModel):
    provider: str = "openai_compatible"
    models: list[str] = Field(min_length=1)
    base_url: str
    base_url_env: str | None = None
    api_key_env: str | None = None


    @model_validator(mode="before")
    @classmethod
    def legacy_mock_provider(cls, value: Any) -> Any:
        # Existing policy files used mock:// before adapters were introduced.
        if isinstance(value, dict) and "provider" not in value:
            if str(value.get("base_url", "")).startswith("mock://"):
                return {**value, "provider": "mock"}
        return value


class AuditSettings(StrictModel):
    store_content: Literal["full", "redacted", "none"] = "redacted"


class ControlSettings(StrictModel):
    mode: Mode = Mode.off
    stages: list[Stage] | None = None
    on_error: FailAction | None = None
    description: str = ""
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mode", mode="before")
    @classmethod
    def _yaml_off_is_false(cls, value: Any) -> Any:
        # YAML 1.1 reads an unquoted `off` as boolean false.
        return Mode.off if value is False else value

    _parsed_params: BaseModel | None = PrivateAttr(default=None)
    _supported_stages: frozenset[Stage] = PrivateAttr(default=frozenset())

    @property
    def parsed_params(self) -> BaseModel:
        assert self._parsed_params is not None, "Policy was not validated against a registry"
        return self._parsed_params

    @property
    def effective_stages(self) -> frozenset[Stage]:
        return frozenset(self.stages) if self.stages is not None else self._supported_stages


class Policy(StrictModel):
    version_note: str = ""
    defaults: Defaults = Field(default_factory=Defaults)
    agents: list[AgentEntry] = Field(default_factory=list)
    upstreams: list[UpstreamEntry] = Field(default_factory=list)
    allowed_models: list[str] = Field(default_factory=list)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    # Order matters: the pipeline runs Controls top to bottom.
    controls: dict[str, ControlSettings] = Field(default_factory=dict)

    _version: str = PrivateAttr(default="")

    @property
    def version(self) -> str:
        return self._version


class PolicyError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def _format_validation_error(exc: ValidationError, prefix: str = "") -> list[str]:
    errors = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        location = f"{prefix}{location}" if location else prefix.rstrip(".")
        errors.append(f"{location}: {error['msg']}" if location else error["msg"])
    return errors


def parse_policy(text: str, registry: Registry) -> Policy:
    """Parse and fully validate a Policy document. Raises PolicyError with every problem found."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError([f"invalid YAML: {exc}"]) from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(["the Policy must be a YAML mapping"])

    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(exc)) from exc

    errors: list[str] = []
    seen_models: set[str] = set()
    for index, upstream in enumerate(policy.upstreams):
        if upstream.provider not in provider_registry.names():
            errors.append(f"upstreams.{index}.provider: unknown provider {upstream.provider!r}")
        for model in upstream.models:
            if model in seen_models:
                errors.append(f"upstreams: duplicate model route {model!r}")
            seen_models.add(model)
    keys = [agent.key for agent in policy.agents]
    if len(keys) != len(set(keys)):
        errors.append("agents: duplicate key")
    for control_id, settings in policy.controls.items():
        cls = registry.get(control_id)
        if cls is None:
            errors.append(f"controls.{control_id}: unknown Control id")
            continue
        unknown = set(settings.params) - set(cls.Params.model_fields)
        if unknown:
            errors.append(f"controls.{control_id}.params: unknown keys {sorted(unknown)}")
        try:
            settings._parsed_params = cls.Params.model_validate(settings.params)
        except ValidationError as exc:
            errors.extend(_format_validation_error(exc, f"controls.{control_id}.params."))
        settings._supported_stages = frozenset(cls.stages)
        if settings.stages is not None:
            unsupported = set(settings.stages) - set(cls.stages)
            if unsupported:
                errors.append(
                    f"controls.{control_id}.stages: {sorted(unsupported)} not supported "
                    f"(supported: {sorted(cls.stages)})"
                )
        if not settings.description:
            settings.description = cls.description
    if errors:
        raise PolicyError(errors)
    return policy


def dump_policy(policy: Policy) -> str:
    """Serialize a Policy back to YAML. Comments in the original file are not preserved."""
    data = policy.model_dump(mode="json", exclude_none=True)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
