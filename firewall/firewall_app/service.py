"""The one entry point both transports use: identity gate -> pipeline -> Audit Event."""

from __future__ import annotations

from firewall_app.controls.base import REGISTRY, ControlContext, Registry
from firewall_app.domain import Check, Finding
from firewall_app.identity import Identity
from firewall_app.pipeline import PipelineResult, denied, run_check
from firewall_app.policy.schema import Policy
from firewall_app.storage.audit import AuditEvent, AuditStore

UNKNOWN_AGENT_REASON = "unknown agent"


class CheckService:
    def __init__(self, audit: AuditStore, registry: Registry = REGISTRY) -> None:
        self.audit = audit
        self.registry = registry
        self.ctx = ControlContext(db=audit.sessions)

    async def run(self, check: Check, policy: Policy, identity: Identity) -> PipelineResult:
        """Run one Check and persist its Audit Event (allowed ones too).

        A failed audit write raises: without evidence the Check fails closed."""
        await self.audit.init()  # stateful Controls read their tables before the first append
        if not identity.allowed:
            finding = Finding(
                control="identity", type="unknown_agent", detail="missing or unknown agent key"
            )
            result = denied(check, policy, UNKNOWN_AGENT_REASON, finding)
        else:
            result = await run_check(check, policy, self.registry, self.ctx)
        await self.record(result, policy)
        return result

    async def record(self, result: PipelineResult, policy: Policy) -> None:
        """Every Audit Event goes through here; `features.audit: false` writes none."""
        if not policy.features.audit:
            return
        await self.audit.append(AuditEvent.from_result(result, policy))
