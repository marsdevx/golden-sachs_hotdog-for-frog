from __future__ import annotations

import logging
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger(__name__)


class Observation:
    def __init__(self, span=None):
        self.span = span

    def attributes(self, values):
        if self.span is not None:
            try:
                self.span.set_attributes({k: v for k, v in values.items() if v is not None})
            except Exception:
                logger.warning("Could not record telemetry attributes")


class Telemetry:
    def __init__(self, tracer=None, provider=None):
        self.tracer = tracer or trace.NoOpTracer()
        self.provider = provider

    @contextmanager
    def llm(self, model, provider, context=None):
        span = None
        try:
            span = self.tracer.start_span("llm.generate", attributes={
                "openinference.span.kind": "LLM",
                "llm.model_name": model,
                "llm.request.model_name": model,
                "firewall.provider": provider,
                **(context or {}),
            })
        except Exception:
            logger.warning("Could not start telemetry span")
        observation = Observation(span)
        try:
            yield observation
        except BaseException as exc:
            if span is not None:
                try:
                    # Exception messages can contain request content or credentials.
                    span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                except Exception:
                    logger.warning("Could not record telemetry error")
            raise
        else:
            if span is not None:
                try:
                    span.set_status(Status(StatusCode.OK))
                except Exception:
                    logger.warning("Could not record telemetry status")
        finally:
            if span is not None:
                try:
                    span.end()
                except Exception:
                    logger.warning("Could not finish telemetry span")

    def shutdown(self):
        if self.provider is not None:
            try:
                self.provider.shutdown()
            except Exception:
                logger.warning("Could not shut down telemetry exporter")


def configure(endpoint: str | None, project: str) -> Telemetry:
    if not endpoint:
        return Telemetry()
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({
            "service.name": "ai-firewall", "openinference.project.name": project,
        }))
        provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=endpoint, timeout=2),
            max_queue_size=2048, max_export_batch_size=256, schedule_delay_millis=1000,
        ))
        return Telemetry(provider.get_tracer("firewall.models"), provider)
    except Exception:
        logger.warning("Telemetry initialization failed; continuing without tracing")
        return Telemetry()
