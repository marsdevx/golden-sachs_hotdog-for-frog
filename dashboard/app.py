"""AI Control Layer dashboard (skeleton). Run: `streamlit run app.py`."""

from __future__ import annotations

import pandas as pd
import streamlit as st
from dashboard_app.api import MODES, AdminAPIError, AdminClient

st.set_page_config(page_title="AI Control Layer", layout="wide")
api = AdminClient()


def show_error(exc: Exception) -> None:
    st.error(f"Firewall admin API error: {exc}")


def overview() -> None:
    st.header("Overview")
    metrics = api.metrics()
    by_action = metrics["by_action"]
    p95 = metrics["latency_ms"]["total"]["p95"]
    columns = st.columns(5)
    columns[0].metric("Checks", metrics["total_checks"])
    columns[1].metric("Blocked", by_action.get("block", 0))
    columns[2].metric("Redacted", by_action.get("redact", 0))
    columns[3].metric("Tokens", metrics["tokens"]["total"])
    columns[4].metric("p95 latency (ms)", "n/a" if p95 is None else f"{p95:.1f}")

    st.subheader("By Agent")
    if metrics["by_agent"]:
        st.dataframe(pd.DataFrame.from_dict(metrics["by_agent"], orient="index"))
    st.subheader("By Control")
    if metrics["by_control"]:
        controls = pd.DataFrame.from_dict(metrics["by_control"], orient="index")
        latency = metrics["latency_ms"]["controls"]
        controls["p50_ms"] = [latency.get(cid, {}).get("p50") for cid in controls.index]
        controls["p95_ms"] = [latency.get(cid, {}).get("p95") for cid in controls.index]
        st.dataframe(controls)


def controls_page() -> None:
    st.header("Controls")
    policy = api.policy()
    st.caption(f"Policy version {policy['version']} · {policy.get('path', '')}")
    if policy["last_error"]:
        st.warning(f"The Policy file has an error; the last good version is active: "
                   f"{policy['last_error']}")
    for control in api.controls():
        with st.container(border=True):
            left, middle, right = st.columns([5, 2, 1])
            left.markdown(f"**{control['id']}**  \n{control['description']}")
            left.caption(f"Stages: {', '.join(control['stages'])}")
            mode = middle.selectbox(
                "Mode",
                MODES,
                index=MODES.index(control["mode"]),
                key=f"mode-{control['id']}",
            )
            if right.button("Apply", key=f"apply-{control['id']}"):
                try:
                    result = api.patch_control(control["id"], mode=mode)
                    st.success(f"{control['id']} is now {mode} (Policy {result['version']})")
                except AdminAPIError as exc:
                    show_error(exc)
    with st.expander("Policy YAML"):
        st.code(policy["yaml"], language="yaml")


def events_page() -> None:
    st.header("Events")
    columns = st.columns(4)
    stage = columns[0].selectbox("Stage", ["any", "input", "output", "tool_call", "tool_result"])
    action = columns[1].selectbox("Action", ["any", "allow", "redact", "review", "block"])
    agent_id = columns[2].text_input("Agent id")
    limit = columns[3].number_input("Limit", min_value=1, max_value=1000, value=100)
    filters = {"stage": stage, "action": action, "agent_id": agent_id}
    events = api.events(limit=int(limit), **filters)
    if events:
        frame = pd.DataFrame(events)
        frame["controls"] = [
            ", ".join(f"{v['control']}={v['effective_action']}" for v in event["verdicts"])
            for event in events
        ]
        shown = ["ts", "stage", "transport", "agent_id", "owner", "user", "model", "action",
                 "reason", "risk_score", "controls", "policy_version", "total_latency_ms",
                 "prompt_tokens", "completion_tokens"]
        st.dataframe(frame[shown], width="stretch")
    else:
        st.info("No Audit Events match.")
    export_filters = {key: value for key, value in filters.items() if value not in ("any", "")}
    left, right = st.columns(2)
    left.download_button(
        "Export JSONL",
        data=api.export("jsonl", **export_filters),
        file_name="audit-events.jsonl",
        mime="application/x-ndjson",
    )
    right.download_button(
        "Export CSV",
        data=api.export("csv", **export_filters),
        file_name="audit-events.csv",
        mime="text/csv",
    )


PAGES = {"Overview": overview, "Controls": controls_page, "Events": events_page}
page = st.sidebar.radio("Page", list(PAGES))
try:
    PAGES[page]()
except AdminAPIError as exc:
    show_error(exc)
