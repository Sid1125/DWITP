# AI Layer Module

Ollama-based classification layer. Receives `analysis.ready` messages, calls Ollama API with sanitized content, validates output via `AIClassificationOutput` pydantic model, flags high-risk findings for human review.

## API

- `call_ollama(content)` → `str | None` — sends content to Ollama `/api/generate` with system prompt enforcing JSON-only output.
- `parse_ai_output(raw)` → `AIClassificationOutput | None` — validates JSON + pydantic schema.
- `handle_finding(finding)` — sets `requires_human_review = True` for `HIGH_RISK_CATEGORIES`.

## Threat Model

- **Prompt injection** — mitigated by `sanitize_for_llm()` upstream and the system prompt's adversarial notice.
- **Ollama hallucination** — mitigated by output schema validation via pydantic.
- **Network isolation** — Ollama reachable only on `ai_net` network.

## Test Coverage

Not tested — requires live Ollama API endpoint. Infra-dependent exclusion documented in `pyproject.toml`.
