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
    WARDCAT_SPACY_MODEL  if set, enables the SpaCy NER layer with this model
    WARDCAT_LLM_MODEL    if set, enables the LLM layer via Ollama (e.g. llama3.2:3b)
    WARDCAT_LLM_BASE_URL Ollama base URL (default: http://localhost:11434)
"""

from __future__ import annotations

import logging
import os

# Pydantic (used by FastMCP to build tool output schemas from these TypedDicts)
# requires typing_extensions.TypedDict on Python < 3.12. typing_extensions ships
# as a transitive dependency of pydantic/mcp.
from typing_extensions import TypedDict

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from wardcat import (
    Backend,
    ConfigError,
    Violation,
    Wardcat,
    all_entities,
    registered_actions,
)

logger = logging.getLogger("wardcat_mcp")

mcp = FastMCP("wardcat")

# The salt and default action are fixed at startup from the environment; the
# redact tool can still override the action per call.
_SALT = os.environ.get("WARDCAT_SALT", "")
_DEFAULT_ACTION = os.environ.get("WARDCAT_ACTION", "redact")
_VALID_ACTIONS = registered_actions()  # {"warn", "hash", "redact", "mask"}

# Structural, regex-detectable PII — always safe to enable (deterministic, no model).
_STRUCTURAL_ENTITIES = [
    "EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "TC_ID", "IP_ADDRESS",
    "IPv6", "MAC_ADDRESS", "JWT", "UUID", "SSN", "NIN", "PASSPORT",
    "EU_NATIONAL_ID", "CUSTOM_SECRET",
]  # fmt: skip
# Names/orgs/addresses — only useful when a NER or LLM layer is active.
_NAME_ENTITIES = ["PERSON", "ORG", "ADDRESS"]


# --- Structured tool output (TypedDicts give the tools an outputSchema) --------


class ViolationSummary(TypedDict):
    """A single detected entity — its type, the action applied, and confidence.

    Deliberately PII-free: never carries the raw matched value.
    """

    type: str
    action: str
    confidence: float


class ScanOutput(TypedDict):
    """Result of `scan`: sanitized text plus a PII-free summary."""

    sanitized_text: str
    is_clean: bool
    violation_count: int
    violations: list[ViolationSummary]
    warnings: list[str]


class RedactOutput(ScanOutput):
    """Result of `redact`: like ScanOutput, plus the action that was applied."""

    action: str


class ServerInfo(TypedDict):
    """What this server can detect and how it will anonymize by default."""

    enabled_entities: list[str]
    default_action: str
    valid_actions: list[str]
    ner_enabled: bool
    llm_enabled: bool


def _ner_enabled() -> bool:
    return bool(os.environ.get("WARDCAT_SPACY_MODEL"))


def _llm_enabled() -> bool:
    return bool(os.environ.get("WARDCAT_LLM_MODEL"))


def _build_guard() -> Wardcat:
    """Build one shared guard from the environment (configured once at startup)."""
    action = _DEFAULT_ACTION

    guard = Wardcat(salt=_SALT)

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
    unknown = [e for e in entities if e not in known]
    if unknown:
        # Don't drop silently — a typo in WARDCAT_ENTITIES (e.g. "EMIAL") would
        # otherwise disable a filter with no signal. Warn to stderr (stdout is
        # the MCP protocol channel) and carry on with the recognized types.
        logger.warning(
            "ignoring unknown WARDCAT_ENTITIES: %s (see wardcat.all_entities() for valid types)",
            ", ".join(unknown),
        )

    # The hash action is only pseudonymous with a secret salt; warn once at
    # startup if hashing is the default but no salt was provided.
    if action == "hash" and not _SALT:
        logger.warning(
            "WARDCAT_ACTION=hash but WARDCAT_SALT is empty — hashes are unsalted "
            "and reversible by rainbow table. Set WARDCAT_SALT in production."
        )

    guard = guard.add_entities([e for e in entities if e in known], action=action)
    return guard


# Built lazily so importing this module never triggers SpaCy model loading /
# auto-download; the guard is created on the first tool call.
_guard: Wardcat | None = None


def _get_guard() -> Wardcat:
    global _guard
    if _guard is None:
        _guard = _build_guard()
    return _guard


def _salt_warnings(action: str) -> list[str]:
    """A per-call warning when `hash` is used without a salt (unsalted → reversible)."""
    if action == "hash" and not _SALT:
        return [
            "hash action used without a salt (WARDCAT_SALT is empty): the "
            "pseudonyms are unsalted and reversible by rainbow table."
        ]
    return []


def _validate_entities(entities: list[str] | None) -> set[str] | None:
    """Normalize a per-call ``entities`` subset, or ``None`` for "all enabled".

    Anything requested that the server didn't enable at startup is rejected
    loudly rather than silently narrowing to nothing — the same no-silent-drop
    principle applied to the startup config.
    """
    if not entities:
        return None
    requested = {e.strip() for e in entities if e.strip()}
    enabled = _get_guard().enabled_entities()
    unknown = requested - enabled
    if unknown:
        raise ValueError(
            f"entities {sorted(unknown)} are not enabled on this server; enabled: {sorted(enabled)}"
        )
    return requested


def _summarize(violations: list[Violation]) -> list[ViolationSummary]:
    return [
        {"type": v.entity_type, "action": v.action, "confidence": v.confidence} for v in violations
    ]


@mcp.tool(annotations=ToolAnnotations(title="Scan for PII", readOnlyHint=True))
async def scan(text: str, entities: list[str] | None = None) -> ScanOutput:
    """Detect PII in `text` and return the sanitized text plus a PII-free summary.

    The `violations` summary never contains raw sensitive values — only entity
    types, the action applied, and confidence — so it is always safe to log.
    `sanitized_text` echoes the original text only when the server's action is
    `warn` (which reports without altering); for `redact`/`mask`/`hash` the
    sensitive values are removed.

    Pass `entities` to narrow this call to a subset of the server's enabled
    types (e.g. `["EMAIL", "IBAN"]`); omit it to apply every enabled filter.
    Requesting a type the server didn't enable is an error.
    """
    keep = _validate_entities(entities)
    result = await _get_guard().scan_async(text)
    if keep is not None:
        # Re-anonymize the detected spans, keeping only the requested subset.
        result = result.reapply(_DEFAULT_ACTION, entities=keep)
    sanitized, violations = result.sanitized_text, result.violations
    return {
        "sanitized_text": sanitized,
        "is_clean": len(violations) == 0,
        "violation_count": len(violations),
        "violations": _summarize(violations),
        "warnings": list(result.warnings) + _salt_warnings(_DEFAULT_ACTION),
    }


@mcp.tool(annotations=ToolAnnotations(title="Redact PII", readOnlyHint=True))
async def redact(text: str, action: str = "", entities: list[str] | None = None) -> RedactOutput:
    """Detect PII in `text` and anonymize every match with `action`.

    Unlike `scan`, you pick the action per call: `redact` drops the value
    (`[EMAIL]`), `mask` keeps a hint (`b***@acme.com`, last-4 of a card), `hash`
    yields a stable salted pseudonym (`[EMAIL:3245e00b…]`), and `warn` leaves the
    text untouched but still reports what was found. `action` defaults to the
    server's WARDCAT_ACTION.

    The `violations` summary never contains raw values; `sanitized_text` still
    holds the original text under `action="warn"` (which reports only).

    Pass `entities` to anonymize only a subset of the server's enabled types
    (e.g. `["EMAIL", "IBAN"]`), leaving other detected PII untouched; omit it to
    anonymize everything. Requesting a type the server didn't enable is an error.
    """
    action = action or _DEFAULT_ACTION
    if action not in _VALID_ACTIONS:
        raise ValueError(f"unknown action {action!r}; choose one of {sorted(_VALID_ACTIONS)}")
    keep = _validate_entities(entities)
    result = await _get_guard().scan_async(text)
    # One detection, re-anonymized under the requested action (and optional subset).
    result = result.reapply(action, entities=keep)
    return {
        "sanitized_text": result.sanitized_text,
        "is_clean": result.is_clean,
        "action": action,
        "violation_count": len(result.violations),
        "violations": _summarize(result.violations),
        "warnings": list(result.warnings) + _salt_warnings(action),
    }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Is this text sensitive?", readOnlyHint=True, openWorldHint=True
    )
)
async def is_sensitive(text: str) -> bool:
    """Return True if `text` contains sensitive information (holistic LLM gate).

    Requires the on-prem LLM layer: set WARDCAT_LLM_MODEL (e.g. `llama3.2:3b`).
    Use it as a guardrail before forwarding text to an external service.
    """
    try:
        return await _get_guard().is_sensitive_async(text)
    except ConfigError as exc:
        raise ValueError(
            "is_sensitive requires the LLM layer, which is not configured. Start "
            "the server with WARDCAT_LLM_MODEL set (e.g. 'llama3.2:3b'), and "
            "optionally WARDCAT_LLM_BASE_URL for a non-default Ollama endpoint."
        ) from exc


@mcp.tool(annotations=ToolAnnotations(title="Server capabilities", readOnlyHint=True))
async def server_info() -> ServerInfo:
    """Report what this server detects and how it anonymizes by default.

    Lets an agent discover the enabled entity types, the default action, and
    whether the NER / LLM layers are active — without probing by trial and error.
    """
    return {
        "enabled_entities": sorted(_get_guard().enabled_entities()),
        "default_action": _DEFAULT_ACTION,
        "valid_actions": sorted(_VALID_ACTIONS),
        "ner_enabled": _ner_enabled(),
        "llm_enabled": _llm_enabled(),
    }


def main() -> None:
    """Console-script entry point — runs the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
