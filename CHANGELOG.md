# Changelog

All notable changes to `wardcat-mcp` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Dockerfile** (+ `.dockerignore`) for running the stdio server in a container:
  `docker run -i --rm -e WARDCAT_SALT=... wardcat-mcp`. Multi-stage, non-root,
  optional SpaCy NER via `--build-arg EXTRAS='[ner]'`. README documents the flow.

## [0.1.0] — 2026-07-14

First tagged version — an MCP server wrapping the
[wardcat](https://github.com/oguzhantopcu0/wardcat) PII-detection library.
Installed from source / GitHub (not published to PyPI):
`uvx --from git+https://github.com/oguzhantopcu0/wardcat-mcp.git wardcat-mcp`.

### Added

- MCP server (`FastMCP`, **stdio**) exposing wardcat's on-prem PII detection as tools:
  - `scan(text, entities?)` — sanitize + PII-free summary.
  - `redact(text, action, entities?)` — per-call `warn`/`hash`/`redact`/`mask`.
  - `is_sensitive(text)` — holistic LLM yes/no (needs the LLM layer).
  - `server_info()` — discovery of enabled entities, default action, and active layers.
- **Structured tool output** — every tool returns a typed schema (`outputSchema` +
  `structuredContent`), not a JSON string — and is annotated **read-only**.
- Per-call `entities` subset on `scan`/`redact`, with no-silent-drop validation.
- A warning (at startup and per call) when the `hash` action is used without
  `WARDCAT_SALT` (unsalted hashes are reversible).
- A **threat-model** note in the README: the server protects what leaves the
  agent, not what the orchestrating LLM has already read.

### Notes

- Depends on `wardcat>=1.0.1,<1.2` from PyPI (pinned to one minor while it uses a
  few wardcat internals that are not yet public API).
- The guard is built lazily on first use, so importing the package never loads a
  SpaCy model.
