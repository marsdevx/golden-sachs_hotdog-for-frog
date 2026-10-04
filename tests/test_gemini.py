"""Tests for the Gemini transport (/gemini/): Gemini CLI's Code Assist traffic through the
firewall, against a fake Google server that records what it receives."""

import json

import httpx
import pytest
from conftest import AGENT_KEY, BASE_POLICY
from fastapi.testclient import TestClient

HEADERS = {"X-Agent-Key": AGENT_KEY, "Authorization": "Bearer google-oauth-token"}
STREAM = "/gemini/v1internal:streamGenerateContent?alt=sse"
POLICY = BASE_POLICY + """  sensitive_data:
    mode: redact
    stages: [input, output]
    params:
      categories:
        - name: email
          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']
"""


class FakeGoogle(httpx.AsyncBaseTransport):
    """Answers like the Code Assist server: SSE chunks wrapped in `response`."""

    def __init__(self, chunks=("Hello ", "there."), status=200):
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict] = []
        self.chunks = chunks
        self.status = status

    async def handle_async_request(self, request):
        self.requests.append(request)
        raw = await request.aread()
        self.bodies.append(json.loads(raw) if raw else {})
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"code": self.status}})
        if request.url.path.endswith(":loadCodeAssist"):
            return httpx.Response(200, json={"currentTier": {"id": "free-tier"}})
        events = [{"response": {"candidates": [{"content": {"role": "model", "parts": [
            {"text": text}]}}]}} for text in self.chunks]
        events[-1]["response"]["usageMetadata"] = {"promptTokenCount": 12,
                                                    "candidatesTokenCount": 3}
        if request.url.path.endswith(":generateContent"):
            merged = {"response": {"candidates": [{"content": {"role": "model", "parts": [
                {"text": "".join(self.chunks)}]}}], "usageMetadata": {
                "promptTokenCount": 12, "candidatesTokenCount": 3}}}
            return httpx.Response(200, json=merged)
        body = "".join(f"data: {json.dumps(e)}\r\n\r\n" for e in events)
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})


def ask(*texts, extra_parts=()):
    contents = [{"role": "user", "parts": [{"text": t} for t in texts] + list(extra_parts)}]
    return {"model": "gemini-2.5-pro", "project": "p-1", "user_prompt_id": "u-1",
            "request": {"contents": contents,
                        "systemInstruction": {"parts": [{"text": "You are Gemini CLI."}]}}}


def reply_text(response) -> str:
    events = [json.loads(line[5:]) for line in response.text.splitlines()
              if line.startswith("data:")]
    return "".join(part["text"] for e in events for c in e["response"]["candidates"]
                   for part in c["content"]["parts"])


@pytest.fixture
def google():
    return FakeGoogle()


@pytest.fixture
def client(make_firewall_app, google):
    return TestClient(make_firewall_app(POLICY, upstream_transport=google))


def test_setup_calls_pass_through_with_google_auth_only(client, google):
    response = client.post("/gemini/v1internal:loadCodeAssist", json={"metadata": {}},
                           headers=HEADERS)
    assert response.json() == {"currentTier": {"id": "free-tier"}}
    sent = google.requests[0]
    assert str(sent.url) == "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
    assert sent.headers["authorization"] == "Bearer google-oauth-token"
    assert "x-agent-key" not in sent.headers
    assert client.get("/v1/settings/events").json() == []  # not a model call


def test_allowed_stream_is_relayed_and_audited(client, google):
    response = client.post(STREAM, json=ask("What is a firewall?"), headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert reply_text(response) == "Hello there."
    assert google.requests[0].url.params["alt"] == "sse"
    assert google.bodies[0]["request"]["contents"][0]["parts"][0]["text"] == "What is a firewall?"

    events = client.get("/v1/settings/events").json()
    assert {(e["stage"], e["transport"], e["action"]) for e in events} == {
        ("input", "gemini", "allow"), ("output", "gemini", "allow")}
    output = next(e for e in events if e["stage"] == "output")
    assert (output["prompt_tokens"], output["completion_tokens"]) == (12, 3)
    assert output["model"] == "gemini-2.5-pro"


def test_blocked_prompt_never_reaches_google(client, google):
    response = client.post(STREAM, json=ask("Any news on Project Falcon?"), headers=HEADERS)
    assert response.status_code == 200
    assert reply_text(response).startswith("AI Control Layer: Blocked by keyword_blocklist")
    assert google.requests == []


def test_prompt_is_redacted_before_it_leaves(client, google):
    client.post(STREAM, json=ask("Mail jan.kowalski@bank.example please"), headers=HEADERS)
    sent = google.bodies[0]["request"]
    assert sent["contents"][0]["parts"][0]["text"] == "Mail [EMAIL] please"
    assert sent["systemInstruction"]["parts"][0]["text"] == "You are Gemini CLI."


def test_tool_results_sent_to_google_are_checked(client, google):
    result = {"functionResponse": {"name": "read_file",
                                   "response": {"output": "owner: jan@bank.example"}}}
    client.post(STREAM, json=ask("Read it", extra_parts=[result]), headers=HEADERS)
    part = google.bodies[0]["request"]["contents"][0]["parts"][1]
    assert part["functionResponse"] == {"name": "read_file",
                                        "response": {"output": "owner: [EMAIL]"}}


def test_reply_split_over_chunks_is_redacted_whole(make_firewall_app):
    google = FakeGoogle(chunks=("Write to jan.kow", "alski@bank.example today"))
    client = TestClient(make_firewall_app(POLICY, upstream_transport=google))
    response = client.post(STREAM, json=ask("Who?"), headers=HEADERS)
    assert reply_text(response) == "Write to [EMAIL] today"


def test_blocked_reply_is_replaced(make_firewall_app):
    google = FakeGoogle(chunks=("Project Falcon closes ", "on Friday."))
    client = TestClient(make_firewall_app(POLICY, upstream_transport=google))
    response = client.post(STREAM, json=ask("Any deals?"), headers=HEADERS)
    assert reply_text(response).startswith("AI Control Layer: Blocked by keyword_blocklist")
    assert "Friday" not in response.text


def test_non_streaming_generate_content(client):
    response = client.post("/gemini/v1internal:generateContent", json=ask("Hi"),
                           headers=HEADERS)
    assert response.json()["response"]["candidates"][0]["content"]["parts"][0]["text"] == (
        "Hello there.")


def test_unknown_agent_is_blocked_before_google(client, google):
    response = client.post(STREAM, json=ask("Hi"),
                           headers={"Authorization": "Bearer google-oauth-token"})
    assert "unknown agent" in reply_text(response)
    assert google.requests == []


def test_google_errors_are_relayed(make_firewall_app):
    client = TestClient(make_firewall_app(POLICY, upstream_transport=FakeGoogle(status=429)))
    response = client.post(STREAM, json=ask("Hi"), headers=HEADERS)
    assert response.status_code == 429
    assert response.json() == {"error": {"code": 429}}


def test_thoughts_are_not_checked_or_changed(make_firewall_app):
    google = FakeGoogle()
    client = TestClient(make_firewall_app(POLICY, upstream_transport=google))
    thought = {"text": "thinking about project falcon", "thought": True}
    response = client.post(STREAM, json=ask("Hi", extra_parts=[thought]), headers=HEADERS)
    assert reply_text(response) == "Hello there."
    sent = google.bodies[0]["request"]["contents"][0]["parts"][1]
    assert sent == thought


def test_audit_off_and_input_validation_off_apply_to_gemini(make_firewall_app, google):
    policy = POLICY.replace("controls:\n", "features: {input_validation: false, audit: false}\n"
                            "controls:\n")
    client = TestClient(make_firewall_app(policy, upstream_transport=google))
    response = client.post(STREAM, json=ask("Any news on Project Falcon?"), headers=HEADERS)
    assert reply_text(response) == "Hello there."
    assert client.get("/v1/settings/events").json() == []


# --- Gemini API key sign-in: plain (unwrapped) Gemini API ---------------------------------


class FakeGeminiApi(httpx.AsyncBaseTransport):
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict] = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        self.bodies.append(json.loads(await request.aread()))
        events = [{"candidates": [{"content": {"role": "model", "parts": [{"text": t}]}}]}
                  for t in ("Mail jan@bank", ".example now")]
        events[-1]["usageMetadata"] = {"promptTokenCount": 9, "candidatesTokenCount": 4}
        body = "".join(f"data: {json.dumps(e)}\r\n\r\n" for e in events)
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})


def test_api_key_sign_in_goes_to_the_gemini_api(make_firewall_app):
    google = FakeGeminiApi()
    client = TestClient(make_firewall_app(POLICY, upstream_transport=google))
    path = "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    body = {"contents": [{"role": "user", "parts": [{"text": "Who to mail?"}]}]}
    response = client.post(path, json=body,
                           headers={"X-Agent-Key": AGENT_KEY, "x-goog-api-key": "k-123"})

    sent = google.requests[0]
    assert str(sent.url).startswith("https://generativelanguage.googleapis.com/v1beta/models/")
    assert sent.headers["x-goog-api-key"] == "k-123"
    assert "x-agent-key" not in sent.headers
    events = [json.loads(line[5:]) for line in response.text.splitlines()
              if line.startswith("data:")]
    text = "".join(p["text"] for e in events for c in e["candidates"]
                   for p in c["content"]["parts"])
    assert text == "Mail [EMAIL] now"

    output = next(e for e in client.get("/v1/settings/events").json() if e["stage"] == "output")
    assert output["model"] == "gemini-2.5-flash"
    assert (output["prompt_tokens"], output["completion_tokens"]) == (9, 4)


def test_api_key_sign_in_blocked_prompt(make_firewall_app):
    google = FakeGeminiApi()
    client = TestClient(make_firewall_app(POLICY, upstream_transport=google))
    body = {"contents": [{"role": "user", "parts": [{"text": "Project Falcon?"}]}]}
    response = client.post("/gemini/v1beta/models/gemini-2.5-flash:generateContent",
                           json=body, headers={"X-Agent-Key": AGENT_KEY})
    assert response.json()["candidates"][0]["content"]["parts"][0]["text"].startswith(
        "AI Control Layer: Blocked")
    assert google.requests == []
