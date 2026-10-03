# One Check pipeline behind two transports: check API and OpenAI-compatible proxy

The firewall core is a transport-agnostic pipeline (Check → Controls → Decision). Two thin adapters sit on top of it: a **check API** (`POST /v1/check/{stage}`), where the Agent calls the firewall around its own LLM and tool calls, and an **OpenAI-compatible proxy** (`POST /v1/chat/completions`), where the firewall calls the Upstream itself so integration is "change the base URL". We keep both because the check API is the only way to govern `tool_call`/`tool_result` Stages and is trivial to test, while the proxy is the zero-code "Monday rollout" story the mentor and judges value. Controls must never know which transport delivered the Check.

## Consequences

- Token usage reaches budget Controls by two routes: reported by the Agent in check-API mode, filled in from the Upstream's response in proxy mode. Controls read it only from the Check.
- The proxy forwards to OpenAI-compatible Upstreams only (Ollama speaks this natively). Provider-specific adapters are out of the core.
