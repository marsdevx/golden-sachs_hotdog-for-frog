"""Scoring backends for `injection_classifier`: windowing plus one model call per window.

`onnx` runs ProtectAI's `deberta-v3-base-prompt-injection-v2` with `onnxruntime` and
`tokenizers` (the optional `ml` extra; no torch). `mock` scores by substring, for tests.

The ONNX model is loaded once per process and cached here. That is a read-only model, not
Control state, so the "no state in module globals" rule does not apply to it.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

MODEL_DIR_ENV = "INJECTION_MODEL_DIR"  # a local copy of the model (the Docker image bakes it in)
MODEL_FILES = ("model.onnx", "tokenizer.json", "config.json")


class ModelUnavailable(RuntimeError):
    """The `onnx` backend cannot run: extra not installed, or model missing and no network."""


@dataclass(frozen=True, slots=True)
class Window:
    start: int  # character span of the window in the scored text
    end: int
    score: float


def split(offsets: list[tuple[int, int]], size: int, overlap: int) -> list[tuple[int, int]]:
    """Token ranges [first, last) of windows of `size` tokens overlapping by `overlap`.
    Every token is in some window: an Injection at the end of a long text is still scored."""
    if not offsets:
        return []
    step = max(1, size - overlap)
    ranges = []
    first = 0
    while True:
        last = min(first + size, len(offsets))
        ranges.append((first, last))
        if last == len(offsets):
            return ranges
        first += step


class MockScorer:
    """Words are tokens; a window scores the highest `scores` substring it contains."""

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores = {key.lower(): value for key, value in scores.items()}

    def windows(self, text: str, window_tokens: int, overlap: int) -> list[Window]:
        offsets = [match.span() for match in re.finditer(r"\S+", text)]
        result = []
        # Like the real model: two of the window's tokens are special tokens.
        for first, last in split(offsets, max(1, window_tokens - 2), overlap):
            start, end = offsets[first][0], offsets[last - 1][1]
            chunk = text[start:end].lower()
            score = max((s for key, s in self.scores.items() if key in chunk), default=0.0)
            result.append(Window(start, end, score))
        return result


class OnnxScorer:
    def __init__(self, directory: Path) -> None:
        try:
            import numpy as np
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ModelUnavailable("install the 'ml' extra: uv sync --extra ml") from exc
        self.np = np
        self.tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        config = json.loads((directory / "config.json").read_text())
        labels = {label.upper(): int(index) for index, label in config["id2label"].items()}
        self.injection = labels["INJECTION"]
        self.cls = self.tokenizer.token_to_id("[CLS]")
        self.sep = self.tokenizer.token_to_id("[SEP]")
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = min(4, os.cpu_count() or 1)
        self.session = onnxruntime.InferenceSession(
            str(directory / "model.onnx"), options, providers=["CPUExecutionProvider"]
        )
        self.inputs = {model_input.name for model_input in self.session.get_inputs()}

    def windows(self, text: str, window_tokens: int, overlap: int) -> list[Window]:
        encoding = self.tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = encoding.ids, encoding.offsets
        # One window per run: batching is no faster on CPU and pads the short last window.
        return [
            Window(offsets[first][0], offsets[last - 1][1],
                   self._score([self.cls, *ids[first:last], self.sep]))
            for first, last in split(offsets, max(1, window_tokens - 2), overlap)
        ]

    def _score(self, sequence: list[int]) -> float:
        np = self.np
        input_ids = np.array([sequence], dtype=np.int64)
        feed = {"input_ids": input_ids, "attention_mask": np.ones_like(input_ids)}
        if "token_type_ids" in self.inputs:
            feed["token_type_ids"] = np.zeros_like(input_ids)
        (logits,) = self.session.run(None, {k: v for k, v in feed.items() if k in self.inputs})
        row = logits[0].tolist()
        top = max(row)
        exps = [math.exp(value - top) for value in row]
        return exps[self.injection] / sum(exps)


def _resolve(model: str, model_dir: str | None) -> Path:
    """The folder holding MODEL_FILES: `model_dir`, the env var, or a Hugging Face download."""
    local = model_dir or os.getenv(MODEL_DIR_ENV)
    if local:
        for candidate in (Path(local), Path(local) / "onnx"):
            if all((candidate / name).is_file() for name in MODEL_FILES):
                return candidate
        raise ModelUnavailable(f"model files {MODEL_FILES} not found in {local}")
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise ModelUnavailable("install the 'ml' extra: uv sync --extra ml") from exc
    try:
        paths = [hf_hub_download(model, f"onnx/{name}") for name in MODEL_FILES]
    except Exception as exc:  # network, missing repo, missing file
        raise ModelUnavailable(f"cannot download {model}: {type(exc).__name__}") from exc
    return Path(paths[0]).parent


_lock = threading.Lock()
_loaded: dict[tuple[str, str | None], OnnxScorer] = {}


def onnx_scorer(model: str, model_dir: str | None) -> OnnxScorer:
    """The cached model; loaded (and downloaded, if needed) on first use. Blocking."""
    key = (model, model_dir)
    with _lock:
        if key not in _loaded:
            _loaded[key] = OnnxScorer(_resolve(model, model_dir))
        return _loaded[key]

