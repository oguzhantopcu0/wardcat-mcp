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
| `scan(text)` | Detect PII and return the **sanitized text** plus a PII-free summary (entity types, actions, confidence — never the raw values). |
| `is_sensitive(text)` | Holistic LLM yes/no on whether the text contains sensitive information. Requires the LLM layer (`WARDCAT_LLM_MODEL`). |

## Install & run

Not on PyPI yet — run from source (wardcat itself is source-only for now):

```bash
uvx --from git+https://github.com/oguzhantopcu0/wardcat-mcp.git wardcat-mcp
# or, cloned locally:
uv run wardcat-mcp
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

## Disclaimer

wardcat is a **best-effort** PII detector — it does not catch everything and is
**not legal advice or a substitute for compliance review** (e.g. GDPR/KVKK).
Validate it against your own data. Provided "as is" (MIT).

## License

MIT — see [LICENSE](LICENSE).
