"""Console summary: every number on the web console, derived from Audit Events and the Policy."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any

from firewall_app.domain import Action, Mode
from firewall_app.storage.audit import AuditEvent, AuditStore, percentile

ANOMALY_RATIO = 10
ANOMALY_MIN_CALLS = 20


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _bucket(now: datetime, ts: datetime, size: timedelta, count: int) -> int | None:
    """Index of the bucket holding `ts`, where the last bucket ends at `now`."""
    index = count - 1 - int((now - ts) / size)
    return index if 0 <= index < count else None


def _posture(policy, last_error: str | None, agents_seen: set[str], registry) -> dict:
    # Planned Controls without code enforce nothing: they do not count as coverage.
    implemented = {cid: c for cid, c in policy.controls.items() if cid in registry}
    registered = len(registry.all())
    controls = list(implemented.values())
    enforcing = [c for c in controls if c.active and c.mode in (Mode.block, Mode.redact)]
    known = {agent.id for agent in policy.agents}
    seen_known = agents_seen & known
    components = [
        {
            "name": "Control coverage",
            "weight": 40,
            "score": len(enforcing) / registered if registered else 0.0,
            "detail": f"{len(enforcing)} of {registered} registered Controls enforce "
            "(block or redact)",
            "gaps": [cid for cid, c in implemented.items() if not c.active],
        },
        {
            "name": "Agent accountability",
            "weight": 35,
            "score": len(seen_known) / len(agents_seen) if agents_seen else 1.0,
            "detail": f"{len(seen_known)} of {len(agents_seen)} active Agents have an Owner",
            "gaps": sorted(agents_seen - known),
        },
        {
            "name": "Policy health",
            "weight": 25,
            "score": 0.0 if last_error else 1.0,
            "detail": "Policy file has an error; last good version is active"
            if last_error
            else "Policy file valid",
            "gaps": [],
        },
    ]
    total = 0.0
    for component in components:
        component["points"] = round(component["weight"] * component["score"], 1)
        component["score"] = round(component["score"], 3)
        total += component["points"]
    score = round(total)
    grade = "Strong" if score >= 85 else "Fair" if score >= 65 else "Weak"
    return {"score": score, "grade": grade, "components": components}


async def build_summary(
    audit: AuditStore, policy_store, now: datetime | None = None
) -> dict[str, Any]:
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    since = now - timedelta(hours=24)
    policy = policy_store.get()

    events: list[AuditEvent] = []
    async for event in audit.iter_events(since=since):
        events.append(event)

    minutes = [{"t": _iso(now - timedelta(minutes=59 - i)), "requests": 0, "blocked": 0}
               for i in range(60)]
    hourly = [{"t": _iso(now - timedelta(hours=23 - i)), "tokens": 0, "requests": 0, "blocked": 0}
              for i in range(24)]
    by_action: dict[str, int] = defaultdict(int)
    by_stage: dict[str, int] = defaultdict(int)
    by_model: dict[str, dict[str, int]] = defaultdict(lambda: {"tokens": 0, "requests": 0})
    by_agent: dict[str, dict[str, Any]] = {}
    by_control: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"fired": 0, "blocked": 0, "last_fired": None}
    )
    latencies: list[float] = []
    five_min: dict[str, list[int]] = defaultdict(lambda: [0] * 288)
    tokens = 0

    for event in events:
        blocked = event.action in (Action.block, Action.review)
        by_action[event.action] += 1
        by_stage[event.stage] += 1
        latencies.append(event.total_latency_ms)
        used = (event.prompt_tokens or 0) + (event.completion_tokens or 0)
        tokens += used
        if event.model:
            by_model[event.model]["requests"] += 1
            by_model[event.model]["tokens"] += used
        agent = by_agent.setdefault(
            event.agent_id,
            {"agent": event.agent_id, "owner": event.owner, "team": event.team, "checks": 0,
             "blocked": 0, "redacted": 0, "tokens": 0},
        )
        agent["checks"] += 1
        agent["blocked"] += event.action == Action.block
        agent["redacted"] += event.action == Action.redact
        agent["tokens"] += used
        for verdict in event.verdicts:
            if verdict.get("effective_action", verdict["action"]) == Action.allow:
                continue
            stats = by_control[verdict["control"]]
            stats["fired"] += 1
            stats["blocked"] += verdict.get("effective_action") == Action.block
            if stats["last_fired"] is None or event.ts > stats["last_fired"]:
                stats["last_fired"] = event.ts
        slot = _bucket(now, event.ts, timedelta(minutes=1), 60)
        if slot is not None:
            minutes[slot]["requests"] += 1
            minutes[slot]["blocked"] += blocked
        slot = _bucket(now, event.ts, timedelta(hours=1), 24)
        if slot is not None:
            hourly[slot]["requests"] += 1
            hourly[slot]["blocked"] += blocked
            hourly[slot]["tokens"] += used
        slot = _bucket(now, event.ts, timedelta(minutes=5), 288)
        if slot is not None:
            five_min[event.agent_id][slot] += 1

    anomalies = []
    for agent_id, buckets in five_min.items():
        last, history = buckets[-1], buckets[:-1]
        baseline = median(history)
        if last >= ANOMALY_MIN_CALLS and last >= ANOMALY_RATIO * max(baseline, 1):
            anomalies.append(
                {"agent": agent_id, "owner": by_agent[agent_id]["owner"], "last_5m": last,
                 "baseline_5m": baseline, "ratio": round(last / max(baseline, 1), 1)}
            )

    controls = []
    for control_id, settings in policy.controls.items():
        stats = by_control.get(control_id, {"fired": 0, "blocked": 0, "last_fired": None})
        controls.append(
            {"id": control_id, "mode": settings.mode.value, "description": settings.description,
             "feature": settings.feature, "feature_on": settings.feature_on,
             "stages": sorted(str(s) for s in settings.effective_stages),
             "fired_24h": stats["fired"], "blocked_24h": stats["blocked"],
             "last_fired": _iso(stats["last_fired"])}
        )

    feed = [
        {"event_id": e.check_id, "ts": _iso(e.ts), "agent": e.agent_id, "owner": e.owner,
         "decision": str(e.action), "stage": str(e.stage), "reason": e.reason,
         "risk_score": e.risk_score, "model": e.model,
         "controls": [v["control"] for v in e.verdicts
                      if v.get("effective_action", v["action"]) != Action.allow]}
        for e in sorted(events, key=lambda e: e.ts, reverse=True)
        if e.action != Action.allow
    ][:50]

    requests = len(events)
    blocked_total = by_action[Action.block] + by_action[Action.review]
    return {
        "generated_at": _iso(now),
        "policy": {"version": policy.version, "note": policy.version_note,
                   "preset": policy.preset,
                   "path": str(policy_store.path), "last_error": policy_store.last_error},
        "features": policy.features.model_dump(),
        "posture": _posture(policy, policy_store.last_error, set(by_agent),
                            policy_store.registry),
        "totals_24h": {
            "requests": requests,
            "allowed": by_action[Action.allow],
            "blocked": blocked_total,
            "redacted": by_action[Action.redact],
            "review": by_action[Action.review],
            "block_rate": blocked_total / requests if requests else 0.0,
            "tokens": tokens,
            "latency_p50_ms": percentile(latencies, 50),
            "latency_p95_ms": percentile(latencies, 95),
        },
        "threats": {
            "by_control": sorted(
                ([cid, s["blocked"]] for cid, s in by_control.items() if s["blocked"]),
                key=lambda row: -row[1]),
            "by_stage": sorted(by_stage.items(), key=lambda row: -row[1]),
            "by_agent": sorted(by_agent.values(), key=lambda a: -a["blocked"])[:8],
        },
        "controls": controls,
        "usage": {
            "by_model": sorted(({"key": k, **v} for k, v in by_model.items()),
                               key=lambda r: -r["tokens"]),
            "by_agent": sorted(by_agent.values(), key=lambda a: -a["tokens"]),
            "hourly": hourly,
        },
        "realtime": {"minutes": minutes, "anomalies": anomalies, "feed": feed},
        "agents": sorted(by_agent),
    }
