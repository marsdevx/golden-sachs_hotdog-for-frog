"""Semantic Injection detection (OWASP LLM01): a local classifier model catches rephrased
Injection that `injection_heuristics` misses. Runs after it in every Preset.

Scans the new `user` and `tool` messages at `input` (those after the last `assistant`
message; history was scanned on earlier turns) and the whole Resource result at
`tool_result`. The text is split into overlapping windows of `window_tokens`, every window is
scored and the text's score is the highest. Direct and indirect Injection are handled like in
`injection_heuristics`: indirect removes the flagged windows.

When the `onnx` backend cannot run (no `ml` extra, model missing and no network) the Control
raises and the Policy's `on_error` decides; it never fails open on its own.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from firewall_app.controls.base import Control, control
from firewall_app.controls.injection_heuristics import Hit, injection_verdict, sources
from firewall_app.controls.injection_model import MockScorer, onnx_scorer
from firewall_app.domain import Check, Finding, Stage, Verdict


@control("injection_classifier")
class InjectionClassifier(Control):
    stages = {Stage.input, Stage.tool_result}
    feature = "input_validation"
    description = (
        "A local AI model checks whether text tries to hijack the AI, catching reworded "
        "attacks the fixed patterns miss; removes it from documents."
    )

    class Params(BaseModel):
        backend: Literal["onnx", "mock"] = "onnx"
        model: str = "protectai/deberta-v3-base-prompt-injection-v2"
        model_dir: str | None = None  # local copy (Docker bakes it in); else HF cache
        threshold: float = Field(0.9, ge=0, le=1)
        on_indirect: Literal["redact", "block"] = "redact"
        window_tokens: int = Field(512, ge=16, le=512)  # the model's maximum is 512
        window_overlap: int = Field(64, ge=0)
        mock_scores: dict[str, float] = Field(default_factory=dict)  # substring -> score

        @model_validator(mode="after")
        def _overlap_fits(self):
            if self.window_overlap >= self.window_tokens - 2:
                raise ValueError("window_overlap must be smaller than window_tokens - 2")
            return self

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        texts = sources(check, new_only=True)
        if not texts:
            return Verdict()
        hits = await asyncio.to_thread(self._score, texts, params)
        return injection_verdict(check, hits, params.on_indirect)

    def _score(self, texts, params: Params) -> list[Hit]:
        """Blocking: model loading and inference run in a worker thread."""
        if params.backend == "mock":
            scorer = MockScorer(params.mock_scores)
        else:
            scorer = onnx_scorer(params.model, params.model_dir)
        hits: list[Hit] = []
        for source in texts:
            windows = scorer.windows(source.text, params.window_tokens, params.window_overlap)
            for number, window in enumerate(windows, 1):
                if window.score < params.threshold:
                    continue
                hits.append(Hit(
                    source=source,
                    finding=Finding(
                        control=self.id,
                        type="injection_model",
                        detail=f"score {window.score:.2f} in window {number} of {len(windows)}, "
                               f"{source.label}",
                    ),
                    remove=(window.start, window.end),
                    risk=window.score,
                    name=f"model score {window.score:.2f}",
                ))
        return hits
