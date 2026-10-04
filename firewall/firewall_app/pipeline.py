"""The transport-agnostic Check pipeline: Check -> Controls (in Policy order) -> Decision."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from firewall_app.controls.base import REGISTRY, ControlContext, Registry
from firewall_app.domain import (
    Action,
    Check,
    Decision,
    Finding,
    Mode,
    Verdict,
    most_severe,
)
from firewall_app.policy.schema import ControlSettings, Policy

logger = logging.getLogger("firewall.pipeline")


@dataclass(frozen=True, slots=True)
class PipelineResult:
    decision: Decision
    before: Check  # the Check as received
    after: Check  # the Check after redactions; its content is what the caller may use


def cap_by_mode(verdict: Verdict, mode: Mode) -> Action:
    """Rule 5: the Mode caps what a Verdict can do to the outcome."""
    if mode == Mode.monitor:
        return Action.allow
    if mode == Mode.redact:
        if verdict.action != Action.allow and verdict.rewritten is not None:
            return Action.redact
        return Action.allow
    return verdict.action


async def _evaluate(
    control_id: str,
    settings: ControlSettings,
    check: Check,
    policy: Policy,
    registry: Registry,
    ctx: ControlContext,
) -> Verdict:
    cls = registry.get(control_id)
    started = time.perf_counter()
    try:
        if cls is None:
            raise LookupError(f"Control {control_id!r} is not registered")
        verdict = await cls(ctx).evaluate(check, settings.parsed_params)
        if not isinstance(verdict, Verdict):
            raise TypeError(f"evaluate returned {type(verdict).__name__}, expected Verdict")
        verdict = verdict.model_copy(deep=True)
    except Exception as exc:
        # Rule 4: a failing Control never surfaces as an HTTP 500.
        logger.exception("Control %s failed on Check %s", control_id, check.check_id)
        on_error = settings.on_error or policy.defaults.on_error
        verdict = Verdict(
            action=Action(on_error),
            reason=f"control error: {type(exc).__name__}",
            risk_score=1.0 if on_error == "block" else 0.0,
            error=True,
        )
    verdict.control = control_id
    verdict.mode = settings.mode
    verdict.latency_ms = (time.perf_counter() - started) * 1000
    if verdict.error:
        # on_error is the explicit fail behaviour; only `monitor` may still neutralise it.
        verdict.effective_action = Action.allow if settings.mode == Mode.monitor else verdict.action
    else:
        verdict.effective_action = cap_by_mode(verdict, settings.mode)
    for finding in verdict.findings:
        finding.control = finding.control or control_id
    return verdict


def _explain(verdicts: list[Verdict], action: Action) -> str:
    """Rule 6: a human-readable reason naming the Control that decided."""
    if action == Action.allow:
        flagged = [v for v in verdicts if v.action != Action.allow]
        # An allowing Verdict with Findings is a warning (e.g. a budget almost used up).
        warned = [v for v in verdicts if v.action == Action.allow and v.findings]
        parts = []
        if flagged:
            notes = ", ".join(f"{v.control} ({v.mode}): {v.reason}" for v in flagged)
            parts.append(f"recorded without enforcement: {notes}")
        if warned:
            parts.append("warnings: " + ", ".join(f"{v.control}: {v.reason}" for v in warned))
        return "Allowed; " + "; ".join(parts) if parts else "No Control objected"
    deciding = [v for v in verdicts if v.effective_action == action]
    if action == Action.redact:
        return "Redacted by " + "; ".join(f"{v.control}: {v.reason}" for v in deciding)
    verb = "Blocked" if action == Action.block else "Held for review"
    first = deciding[0]
    return f"{verb} by {first.control}: {first.reason}"


async def run_check(
    check: Check,
    policy: Policy,
    registry: Registry = REGISTRY,
    ctx: ControlContext | None = None,
) -> PipelineResult:
    ctx = ctx or ControlContext()
    started = time.perf_counter()
    current = check
    verdicts: list[Verdict] = []

    for control_id, settings in policy.controls.items():
        # Rule 1: Policy order, skipping Controls that are off (by Mode or by their feature)
        # or not active at this Stage.
        if not settings.active or check.stage not in settings.effective_stages:
            continue
        # A planned Control without code yet (see Policy.warnings).
        if control_id not in registry:
            continue
        verdict = await _evaluate(control_id, settings, current, policy, registry, ctx)
        verdicts.append(verdict)
        # Rule 2: redactions chain into the Check later Controls see.
        if verdict.effective_action == Action.redact and verdict.rewritten is not None:
            current = current.with_content(verdict.rewritten)
        # Rule 3: short-circuit on the first effective block.
        if verdict.effective_action == Action.block:
            break

    action = most_severe(v.effective_action for v in verdicts)
    findings: list[Finding] = [finding for v in verdicts for finding in v.findings]
    decision = Decision(
        action=action,
        reason=_explain(verdicts, action),
        risk_score=max((v.risk_score for v in verdicts), default=0.0),
        findings=findings,
        verdicts=verdicts,
        policy_version=policy.version,
        latency_ms=(time.perf_counter() - started) * 1000,  # Rule 7
    )
    return PipelineResult(decision=decision, before=check, after=current)


def denied(check: Check, policy: Policy, reason: str, finding: Finding) -> PipelineResult:
    """A block Decision made before any Control ran (unknown Agent, disallowed model)."""
    decision = Decision(
        action=Action.block,
        reason=reason,
        risk_score=1.0,
        findings=[finding],
        policy_version=policy.version,
    )
    return PipelineResult(decision=decision, before=check, after=check)

