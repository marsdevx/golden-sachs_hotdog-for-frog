FROM python:3.12-slim
WORKDIR /service
# The injection_classifier model is baked in, so the image runs offline and the first request
# is fast. Its own layer, before the code: a code change does not download it again.
ENV INJECTION_MODEL_DIR=/models/prompt-injection
RUN pip install --no-cache-dir "huggingface_hub>=0.23,<2" \
 && python -c "from huggingface_hub import snapshot_download; snapshot_download('protectai/deberta-v3-base-prompt-injection-v2', allow_patterns=['onnx/model.onnx', 'onnx/tokenizer.json', 'onnx/config.json'], local_dir='$INJECTION_MODEL_DIR')"
COPY pyproject.toml ./
COPY firewall_app ./firewall_app
RUN pip install --no-cache-dir ".[ml]"
EXPOSE 8001
CMD ["uvicorn", "firewall_app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8001"]
