# Adding a model provider

Every model call follows `input checks → ProviderManager → adapter → output checks`.
The client supplies `model` and `messages`; only the server policy selects the adapter
and its URL. Model adapters live in `firewall/firewall_app/providers/`.

The registry currently includes:

- `ollama`: Ollama's OpenAI-compatible endpoint; URL includes `/v1`.
- `openai_compatible`: the same wire protocol for other compatible servers.
- `mock`: local echo for tests and demos; usage is a word count.

## Add a route without writing code

For a server that already supports the compatible protocol, add an upstream entry
and allow its model in `policies/standard.yaml`:

```yaml
upstreams:
  - models: ["qwen3:4b"]
    provider: ollama
    base_url: http://localhost:11434/v1
    base_url_env: OLLAMA_API_BASE
  - models: ["another-model"]
    provider: openai_compatible
    base_url: https://model-server.example/v1
    api_key_env: MODEL_SERVER_KEY
allowed_models: ["qwen3:4b", "another-model"]
```

`base_url_env` optionally overrides the URL. `api_key_env` names an environment
variable on the firewall, never the actual secret. If a configured key is absent,
the call fails closed. Each model has exactly one route; duplicate routes and unknown
provider names are rejected during policy validation. Policy changes hot reload.
Older entries without `provider` use `openai_compatible`, or `mock` for `mock://`.
There is no implicit route: even mock must have an upstream entry.

## Add a new protocol

1. Create `providers/example.py` with a constructor `(connection, client)` and
   `async chat(request: ModelRequest) -> ModelResponse`. The supplied `httpx.AsyncClient`
   carries the timeout and test transport; do not create a separate client.
2. Translate `request.model`, the already checked `request.messages`, and supported
   `request.options` to the provider protocol. Use `connection.base_url` and
   `connection.api_key`. Do not recover original messages from elsewhere.
3. Normalize the response into `ModelResponse`: assistant text, model and `Usage`.
   Leave unknown token counts as `None`. Do not estimate them as if reported by the model.
4. Import the class in `providers/__init__.py` and register it:

   ```python
   registry.register("example", ExampleAdapter)
   ```

5. Use `provider: example` in a model route, restart firewall to load the new Python
   module, and test the route. No changes to chat, proxy or Controls are needed.

Adapters perform generation only. The proxy owns checks and audit; it serializes the
checked response instead of forwarding arbitrary provider fields. The current contract
supports one non-streaming text response. Multiple choices, tool calls and streaming
need an explicit extension to the contract and checks before they can be exposed.

See `tests/test_providers.py` for an example adapter registered in a test and exercised
through the real input/output pipeline, including block and redact decisions.
