# wardcat-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes
[wardcat](https://github.com/oguzhantopcu0/wardcat)'s **on-prem PII detection and
anonymization** as tools any agent can call — Claude Desktop, Cursor, a
self-hosted bot, a RAG pipeline. Use it as a **guardrail**: sanitize inputs
before they reach an LLM, or gate them with a semantic "is this sensitive?"
check.

> **Runs locally, stays local.** The server runs on your machine over stdio;
> the text, the models, and all detection stay on-prem — nothing is sent
> anywhere. Publishing this package ships *code you run yourself*, not a hosted
> service.

## Tools

| Tool | Description |
|------|-------------|
| `scan(text, entities?)` | Detect PII and return the **sanitized text** plus a PII-free summary — entity types, actions, confidence. The summary never carries raw values; `sanitized_text` echoes the original only under the `warn` action. Pass `entities` to limit the call to a subset of the enabled types. |
| `redact(text, action, entities?)` | Like `scan`, but you choose the **action per call**: `redact` drops the value (`[EMAIL]`), `mask` keeps a hint (`b***@acme.com`, last-4 of a card), `hash` gives a stable salted pseudonym (`[EMAIL:3245e00b…]`), `warn` leaves the text untouched but still reports what was found. Defaults to `WARDCAT_ACTION`. |
| `is_sensitive(text)` | Holistic LLM yes/no on whether the text contains sensitive information. Requires the LLM layer (`WARDCAT_LLM_MODEL`). |
| `server_info()` | Report the enabled entity types, the default action, and whether the NER / LLM layers are active — so an agent can discover capabilities without trial and error. |

All tools return **structured output** (a typed schema, not a JSON string) and are annotated read-only.

> **Threat model — what this protects.** wardcat-mcp guards what leaves the
> *agent*: it sanitizes text before it is logged, stored, or forwarded to a
> downstream API. It does **not** hide anything from the host LLM that is
> orchestrating the tool call — by the time a model invokes `scan`, it has
> already read the raw text (and it may be retained in that provider's context
> or logs). To filter text *before* it reaches any LLM, call the
> [wardcat](https://github.com/oguzhantopcu0/wardcat) library in-process instead.

## Install & run

Not published to PyPI — run it straight from the repository (its wardcat
dependency does come from PyPI, so this needs no other source):

```bash
# Run directly from GitHub, no install:
uvx --from git+https://github.com/oguzhantopcu0/wardcat-mcp.git wardcat-mcp
# from a local clone:
uv run wardcat-mcp
# with the SpaCy NER layer (PERSON/ORG/ADDRESS), from a clone:
uv run --extra ner wardcat-mcp
```

## Add it to an MCP client

Claude Desktop (`claude_desktop_config.json`), Cursor, Cline, Zed, etc.:

```json
{
  "mcpServers": {
    "wardcat": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/oguzhantopcu0/wardcat-mcp.git", "wardcat-mcp"],
      "env": {
        "WARDCAT_SALT": "your-secret-salt",
        "WARDCAT_ACTION": "redact",
        "WARDCAT_LLM_MODEL": "llama3.2:3b"
      }
    }
  }
}
```

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `WARDCAT_SALT` | `""` | Hashing salt (required for the `hash` action). |
| `WARDCAT_ENTITIES` | broad structural + name set | Comma-separated entity types to enable. |
| `WARDCAT_ACTION` | `redact` | `warn` \| `hash` \| `redact` \| `mask`. |
| `WARDCAT_SPACY_MODEL` | — | Enable SpaCy NER with this model (needs the `ner` extra). |
| `WARDCAT_LLM_MODEL` | — | Enable the on-prem LLM layer via Ollama (e.g. `llama3.2:3b`). |
| `WARDCAT_LLM_BASE_URL` | `http://localhost:11434` | Ollama endpoint. |

## Development

```bash
uv sync --dev
uv run pytest        # deterministic, regex-only — no models or network needed
uv run ruff check .
uv run mypy src
```

## Disclaimer

wardcat is a **best-effort** PII detector — it does not catch everything and is
**not legal advice or a substitute for compliance review** (e.g. GDPR/KVKK).
Validate it against your own data. Provided "as is" (MIT).

## License

MIT — see [LICENSE](LICENSE).
