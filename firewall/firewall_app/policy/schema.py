"""Pydantic models of policy.yaml, plus validation against the Control registry."""

from __future__ import annotations

from pathlib import Path
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
from firewall_app.policy.presets import CUSTOM, PRESETS, apply_preset, preset_path
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
    # Planned (docs/reference-policy): accepted so the Policy loads, not enforced yet.
    enabled: bool | None = None
    require_user: bool | None = None


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


class Features(StrictModel):
    """Master switches. false = as if the feature did not exist. A Control runs only when its
    feature is on AND its own mode is not off, so switching a feature back on restores every
    Control as it is configured."""

    input_validation: bool = True  # prompt checks (keyword_blocklist, ...)
    data_protection: bool = True  # sensitive_data, output_sanitizer
    resource_access: bool = True  # resource_access (folders on this PC)
    usage_limits: bool = True  # loop_detector, request_limits, token_budget
    attack_mitigation: bool = True  # historical attack signatures (attack_signatures)
    audit: bool = True  # false: no Audit Events are written
    console: bool = True  # false: the web console page is gone (404)


class AuditSettings(StrictModel):
    store_content: Literal["full", "redacted", "none"] = "redacted"
    # Planned: accepted so the Policy loads, not enforced yet.
    retention_days: int | None = None


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
    _feature: str = PrivateAttr(default="")
    _feature_on: bool = PrivateAttr(default=True)

    @property
    def parsed_params(self) -> BaseModel:
        assert self._parsed_params is not None, "Policy was not validated against a registry"
        return self._parsed_params

    @property
    def feature(self) -> str:
        """The `features:` switch this Control belongs to."""
        return self._feature

    @property
    def feature_on(self) -> bool:
        return self._feature_on

    @property
    def active(self) -> bool:
        """Runs at all: its feature is on and its Mode is not off."""
        return self._feature_on and self.mode != Mode.off

    @property
    def effective_stages(self) -> frozenset[Stage]:
        return frozenset(self.stages) if self.stages is not None else self._supported_stages


class Policy(StrictModel):
    version_note: str = ""
    # Strictness level laid over `controls:` from presets/<name>.yaml; custom = as written.
    preset: Literal[PRESETS + (CUSTOM,)] = CUSTOM  # type: ignore[valid-type]
    defaults: Defaults = Field(default_factory=Defaults)
    agents: list[AgentEntry] = Field(default_factory=list)
    upstreams: list[UpstreamEntry] = Field(default_factory=list)
    allowed_models: list[str] = Field(default_factory=list)
    features: Features = Field(default_factory=Features)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    # Planned: accepted so the Policy loads, not used yet.
    observability: dict[str, Any] = Field(default_factory=dict)
    # Order matters: the pipeline runs Controls top to bottom.
    controls: dict[str, ControlSettings] = Field(default_factory=dict)

    _version: str = PrivateAttr(default="")
    # Settings the Policy names but the firewall does not implement yet: loaded, ignored.
    _warnings: list[str] = PrivateAttr(default_factory=list)
    # The preset file merged in, and its text (the loader watches it and hashes it).
    _preset_file: Path | None = PrivateAttr(default=None)
    _preset_text: str = PrivateAttr(default="")

    @property
    def preset_file(self) -> Path | None:
        return self._preset_file

    @property
    def version(self) -> str:
        return self._version

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)


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


def parse_policy(text: str, registry: Registry, presets_dir: Path | None = None) -> Policy:
    """Parse and fully validate a Policy document, with its preset laid over `controls:`.
    Raises PolicyError with every problem found."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError([f"invalid YAML: {exc}"]) from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(["the Policy must be a YAML mapping"])

    preset_warnings: list[str] = []
    preset_file: Path | None = None
    preset_text = ""
    try:
        preset_file = preset_path(data.get("preset", CUSTOM), presets_dir)
        if preset_file is not None:
            preset_text = preset_file.read_text(encoding="utf-8")
            preset_warnings = apply_preset(data, data["preset"], preset_text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PolicyError([str(exc)]) from exc

    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(exc)) from exc

    errors: list[str] = []
    warnings = preset_warnings + _not_implemented(policy)
    policy._preset_file, policy._preset_text = preset_file, preset_text
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
            # A planned Control (docs/backlog.md) stays in the Policy and is skipped until
            # its code exists. The console shows the warning, so a typo is still visible.
            warnings.append(f"controls.{control_id}: Control not implemented yet, skipped")
            continue
        unknown = set(settings.params) - set(cls.Params.model_fields)
        if unknown:
            errors.append(f"controls.{control_id}.params: unknown keys {sorted(unknown)}")
        try:
            settings._parsed_params = cls.Params.model_validate(settings.params)
        except ValidationError as exc:
            errors.extend(_format_validation_error(exc, f"controls.{control_id}.params."))
        settings._supported_stages = frozenset(cls.stages)
        settings._feature = cls.feature
        settings._feature_on = getattr(policy.features, cls.feature)
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
    policy._warnings = warnings
    return policy


def _not_implemented(policy: Policy) -> list[str]:
    """Planned settings that are set in the Policy but have no effect yet."""
    warnings = []
    for index, agent in enumerate(policy.agents):
        for name in ("enabled", "require_user"):
            if getattr(agent, name) is not None:
                warnings.append(f"agents.{index}.{name}: not implemented yet, ignored")
    if policy.audit.retention_days is not None:
        warnings.append("audit.retention_days: not implemented yet, ignored")
    if policy.observability:
        warnings.append("observability: not implemented yet, ignored")
    return warnings

