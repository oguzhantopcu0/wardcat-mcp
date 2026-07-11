"""wardcat MCP server.

Exposes wardcat's on-prem PII detection as MCP tools so any agent (Claude
Desktop, Cursor, a self-hosted bot, …) can sanitize its inputs/outputs without
writing code. Runs locally over stdio — the text, the models and the detection
all stay on the machine; nothing is sent anywhere.

Configure with environment variables:
    WARDCAT_SALT         hashing salt (required for the `hash` action)
    WARDCAT_ENTITIES     comma-separated entity types to enable
                         (default: a broad structural + name set)
    WARDCAT_ACTION       warn | hash | redact | mask   (default: redact)
    WARDCAT_LLM_MODEL    if set, enables the LLM layer via Ollama (e.g. llama3.2:3b)
    WARDCAT_LLM_BASE_URL Ollama base URL (default: http://localhost:11434)
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from wardcat import Backend, Wardcat, all_entities

mcp = FastMCP("wardcat")

# Structural, regex-detectable PII — always safe to enable (deterministic, no model).
_STRUCTURAL_ENTITIES = [
    "EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "TC_ID", "IP_ADDRESS",
    "IPv6", "MAC_ADDRESS", "JWT", "UUID", "SSN", "NIN", "PASSPORT",
    "EU_NATIONAL_ID", "CUSTOM_SECRET",
]  # fmt: skip
# Names/orgs/addresses — only useful when a NER or LLM layer is active.
_NAME_ENTITIES = ["PERSON", "ORG", "ADDRESS"]


def _build_guard() -> Wardcat:
    """Build one shared guard from the environment (configured once at startup)."""
    action = os.environ.get("WARDCAT_ACTION", "redact")

    guard = Wardcat(salt=os.environ.get("WARDCAT_SALT", ""))

    # NER (names/orgs/addresses) needs a SpaCy model; enable it only if one is set.
    ner_model = os.environ.get("WARDCAT_SPACY_MODEL")
    if ner_model:
        guard = guard.with_ner(spacy_model=ner_model)

    # Optional on-prem LLM layer (contextual detection + is_sensitive).
    llm_model = os.environ.get("WARDCAT_LLM_MODEL")
    if llm_model:
        guard = guard.with_llm(
            backend=Backend.OLLAMA,
            model=llm_model,
            base_url=os.environ.get("WARDCAT_LLM_BASE_URL", "http://localhost:11434"),
        )

    env_entities = os.environ.get("WARDCAT_ENTITIES", "")
    if env_entities:
        entities = [e.strip() for e in env_entities.split(",") if e.strip()]
    else:
        # Default: structural PII, plus names only if a model layer can detect them.
        entities = list(_STRUCTURAL_ENTITIES)
        if ner_model or llm_model:
            entities += _NAME_ENTITIES

    known = set(all_entities())
    guard = guard.add_entities([e for e in entities if e in known], action=action)
    return guard


guard = _build_guard()


@mcp.tool()
async def scan(text: str) -> dict:
    """Detect PII in `text` and return the sanitized text plus a PII-free summary.

    The raw sensitive values are never returned — only the entity types, the
    action applied, and the sanitized text — so the tool output is safe to log.
    """
    result = await guard.scan_async(text)
    return {
        "sanitized_text": result.sanitized_text,
        "is_clean": result.is_clean,
        "violation_count": len(result.violations),
        "violations": [
            {"type": v.entity_type, "action": v.action, "confidence": v.confidence}
            for v in result.violations
        ],
        "warnings": result.warnings,
    }


@mcp.tool()
async def is_sensitive(text: str) -> bool:
    """Return True if `text` contains sensitive information (holistic LLM gate).

    Requires the LLM layer (set WARDCAT_LLM_MODEL). Use it as a guardrail before
    forwarding text to an external service.
    """
    return await guard.is_sensitive_async(text)


def main() -> None:
    """Console-script entry point — runs the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
