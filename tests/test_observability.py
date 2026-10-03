import pytest
from conftest import AGENT_KEY, BASE_POLICY
from fastapi.testclient import TestClient
from firewall_app.domain import Message
from firewall_app.observability.tracing import Telemetry
from firewall_app.providers import registry
from firewall_app.providers.base import ModelResponse
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from test_proxy import RecordingUpstream


@pytest.fixture
def telemetry():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield Telemetry(provider.get_tracer("test")), exporter
    provider.shutdown()


def call(app, text="Hello", model="remote-model"):
    return TestClient(app).post("/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY},
                               json={"model": model,
                                     "messages": [{"role": "user", "content": text}]})


def test_common_manager_records_usage_once(make_firewall_app, telemetry):
    observer, exporter = telemetry
    app = make_firewall_app(upstream_transport=RecordingUpstream())
    app.state.telemetry = observer
    assert call(app).status_code == 200
    (span,) = exporter.get_finished_spans()
    assert span.attributes["llm.token_count.prompt"] == 11
    assert span.attributes["llm.token_count.completion"] == 7
    assert span.attributes["llm.token_count.total"] == 18
    assert span.attributes["firewall.agent_id"] == "test-agent"
    assert span.end_time >= span.start_time
    assert "Hello" not in str(span.attributes)
    assert AGENT_KEY not in str(span.attributes)


def test_blocked_input_has_no_model_consumption(make_firewall_app, telemetry):
    observer, exporter = telemetry
    app = make_firewall_app()
    app.state.telemetry = observer
    assert call(app, "project falcon").json()["firewall"]["action"] == "block"
    assert not exporter.get_finished_spans()


def test_blocked_output_still_records_consumption(make_firewall_app, telemetry):
    observer, exporter = telemetry
    app = make_firewall_app(upstream_transport=RecordingUpstream("project falcon"))
    app.state.telemetry = observer
    assert call(app).json()["firewall"]["action"] == "block"
    assert exporter.get_finished_spans()[0].attributes["llm.token_count.total"] == 18


def test_new_adapter_gets_telemetry_without_changes(make_firewall_app, telemetry, monkeypatch):
    class NewAdapter:
        def __init__(self, connection, client):
            pass

        async def chat(self, request):
            return ModelResponse(model=request.model,
                                 message=Message(role="assistant", content="OK"))

    monkeypatch.setattr(registry, "_factories", dict(registry._factories))
    registry.register("new", NewAdapter)
    policy = BASE_POLICY.replace('base_url: "http://upstream.test/v1"',
                                 'base_url: "http://upstream.test/v1"\n    provider: new')
    observer, exporter = telemetry
    app = make_firewall_app(policy)
    app.state.telemetry = observer
    assert call(app).status_code == 200
    (span,) = exporter.get_finished_spans()
    assert span.attributes["firewall.provider"] == "new"
    assert "llm.token_count.prompt" not in span.attributes
    assert "llm.token_count.total" not in span.attributes


def test_provider_error_recorded_without_claiming_zero_tokens(make_firewall_app, telemetry):
    observer, exporter = telemetry
    app = make_firewall_app(upstream_transport=RecordingUpstream(fail="connect"))
    app.state.telemetry = observer
    assert call(app).status_code == 502
    (span,) = exporter.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert "llm.token_count.total" not in span.attributes


def test_broken_instrumentation_does_not_break_generation(make_firewall_app):
    class BrokenTracer:
        def start_span(self, *args, **kwargs):
            raise RuntimeError("broken telemetry")

    app = make_firewall_app()
    app.state.telemetry = Telemetry(BrokenTracer())
    assert call(app, model="mock").status_code == 200


def test_export_failure_does_not_break_generation(make_firewall_app):
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class OfflineExporter(SpanExporter):
        def export(self, spans):
            return SpanExportResult.FAILURE

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(OfflineExporter()))
    try:
        app = make_firewall_app()
        app.state.telemetry = Telemetry(provider.get_tracer("offline"))
        assert call(app, model="mock").status_code == 200
    finally:
        provider.shutdown()


def test_configured_batch_exporter_sends_spans(monkeypatch):
    from firewall_app.observability.tracing import configure
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import SpanExportResult

    exported = []

    def export(self, spans):
        exported.extend(spans)
        return SpanExportResult.SUCCESS

    monkeypatch.setattr(OTLPSpanExporter, "export", export)
    observer = configure("http://collector.test/v1/traces", "test-project")
    try:
        assert observer.provider is not None
        with observer.llm("new-model", "new-provider") as observation:
            observation.attributes({"llm.token_count.prompt": 5})
        assert observer.provider.force_flush(timeout_millis=2000)
        assert len(exported) == 1
        assert exported[0].resource.attributes["openinference.project.name"] == "test-project"
        assert exported[0].attributes["llm.token_count.prompt"] == 5
    finally:
        observer.shutdown()
