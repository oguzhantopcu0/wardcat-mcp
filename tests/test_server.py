"""Tests for the wardcat MCP server.

Everything here uses only regex-detectable structural PII (EMAIL, CREDIT_CARD),
so the suite is deterministic and needs no SpaCy model or Ollama — no network,
no downloads.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from wardcat import Wardcat

import wardcat_mcp.server as server

TEXT = "mail bob@acme.com card 4111 1111 1111 1111"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def guard(monkeypatch):
    """Patch the server's shared guard with a deterministic regex-only one."""
    monkeypatch.setattr(server, "_SALT", "test-salt")
    monkeypatch.setattr(server, "_DEFAULT_ACTION", "redact")
    g = Wardcat(salt="test-salt").add_entities(["EMAIL", "CREDIT_CARD"], action="redact")
    monkeypatch.setattr(server, "_guard", g)
    return g


# --- _build_guard (environment configuration) --------------------------------


def test_build_guard_enables_structural_pii_by_default(monkeypatch):
    monkeypatch.delenv("WARDCAT_ENTITIES", raising=False)
    monkeypatch.delenv("WARDCAT_SPACY_MODEL", raising=False)
    monkeypatch.delenv("WARDCAT_LLM_MODEL", raising=False)

    enabled = server._build_guard().enabled_entities()

    assert "EMAIL" in enabled
    assert "CREDIT_CARD" in enabled
    # Name entities need a NER/LLM layer, which isn't configured here.
    assert "PERSON" not in enabled


def test_build_guard_honors_custom_entities_and_action(monkeypatch):
    monkeypatch.setenv("WARDCAT_ENTITIES", "EMAIL")
    monkeypatch.setattr(server, "_DEFAULT_ACTION", "mask")

    g = server._build_guard()

    assert g.enabled_entities() == {"EMAIL"}
    assert g.get_entity_action("EMAIL") == "mask"


def test_build_guard_warns_on_unknown_entities(monkeypatch, caplog):
    monkeypatch.setenv("WARDCAT_ENTITIES", "EMAIL, NOT_A_REAL_ENTITY")

    with caplog.at_level(logging.WARNING, logger="wardcat_mcp"):
        g = server._build_guard()

    # The bad type is dropped, but not silently — it's surfaced as a warning.
    assert g.enabled_entities() == {"EMAIL"}
    assert "NOT_A_REAL_ENTITY" in caplog.text


# --- scan tool ---------------------------------------------------------------


def test_scan_redacts_and_reports(guard):
    out = run(server.scan(TEXT))

    assert "[EMAIL]" in out["sanitized_text"]
    assert "[CREDIT_CARD]" in out["sanitized_text"]
    assert out["is_clean"] is False
    assert out["violation_count"] == 2
    assert {v["type"] for v in out["violations"]} == {"EMAIL", "CREDIT_CARD"}


def test_scan_never_leaks_raw_values(guard):
    blob = json.dumps(run(server.scan(TEXT)))

    assert "bob@acme.com" not in blob
    assert "4111" not in blob


def test_scan_clean_text_is_untouched(guard):
    out = run(server.scan("nothing sensitive here"))

    assert out["is_clean"] is True
    assert out["violation_count"] == 0
    assert out["sanitized_text"] == "nothing sensitive here"


# --- redact tool (per-call action) -------------------------------------------


@pytest.mark.parametrize(
    "action,predicate",
    [
        ("redact", lambda s: "[EMAIL]" in s and "bob@acme.com" not in s),
        ("mask", lambda s: "b**@acme.com" in s),
        ("hash", lambda s: "[EMAIL:" in s and "bob@acme.com" not in s),
        ("warn", lambda s: "bob@acme.com" in s),
    ],
)
def test_redact_applies_requested_action(guard, action, predicate):
    out = run(server.redact(TEXT, action))

    assert out["action"] == action
    assert predicate(out["sanitized_text"])


def test_redact_defaults_to_server_action(guard, monkeypatch):
    monkeypatch.setattr(server, "_DEFAULT_ACTION", "mask")

    out = run(server.redact("mail bob@acme.com"))

    assert out["action"] == "mask"
    assert "b**@acme.com" in out["sanitized_text"]


def test_redact_rejects_unknown_action(guard):
    with pytest.raises(ValueError, match="unknown action"):
        run(server.redact("x", "bogus"))


def test_redact_warn_reports_without_changing_text(guard):
    out = run(server.redact("mail bob@acme.com", "warn"))

    assert out["sanitized_text"] == "mail bob@acme.com"
    assert out["violation_count"] == 1
    assert out["violations"][0]["action"] == "warn"


def test_redact_never_leaks_raw_values(guard):
    for action in ("redact", "mask", "hash"):
        blob = json.dumps(run(server.redact(TEXT, action)))
        assert "bob@acme.com" not in blob
        assert "4111" not in blob


def test_redact_matches_a_natively_configured_guard(monkeypatch):
    """re-anonymizing detected spans must equal scanning with that action natively."""
    monkeypatch.setattr(server, "_SALT", "s")
    monkeypatch.setattr(server, "_DEFAULT_ACTION", "redact")
    monkeypatch.setattr(
        server,
        "_guard",
        Wardcat(salt="s").add_entities(["EMAIL", "CREDIT_CARD"], action="redact"),
    )

    for action in ("warn", "hash", "redact", "mask"):
        native = Wardcat(salt="s").add_entities(["EMAIL", "CREDIT_CARD"], action=action)
        expected = run(native.scan_async(TEXT)).sanitized_text
        actual = run(server.redact(TEXT, action))["sanitized_text"]
        assert actual == expected, action


# --- per-call entities subset ------------------------------------------------


def test_scan_narrows_to_requested_entities(guard):
    out = run(server.scan(TEXT, entities=["EMAIL"]))

    # Only EMAIL is anonymized; the card is left in place this call.
    assert "[EMAIL]" in out["sanitized_text"]
    assert "4111 1111 1111 1111" in out["sanitized_text"]
    assert out["violation_count"] == 1
    assert {v["type"] for v in out["violations"]} == {"EMAIL"}


def test_redact_narrows_to_requested_entities(guard):
    out = run(server.redact(TEXT, "mask", entities=["CREDIT_CARD"]))

    # Only the card is masked; the email is untouched this call.
    assert "bob@acme.com" in out["sanitized_text"]
    assert "4111 1111 1111 1111" not in out["sanitized_text"]
    assert {v["type"] for v in out["violations"]} == {"CREDIT_CARD"}


def test_scan_subset_matching_nothing_is_clean(guard):
    # Text has only a card; asking for EMAIL leaves it clean *for this call*.
    out = run(server.scan("card 4111 1111 1111 1111", entities=["EMAIL"]))

    assert out["violation_count"] == 0
    assert out["is_clean"] is True
    assert "4111 1111 1111 1111" in out["sanitized_text"]


def test_empty_entities_list_applies_all_enabled(guard):
    assert run(server.scan(TEXT, entities=[]))["violation_count"] == 2


def test_scan_rejects_entity_not_enabled(guard):
    with pytest.raises(ValueError, match="not enabled"):
        run(server.scan(TEXT, entities=["IBAN"]))


def test_redact_rejects_entity_not_enabled(guard):
    with pytest.raises(ValueError, match="not enabled"):
        run(server.redact(TEXT, "redact", entities=["NOT_A_REAL_ENTITY"]))


# --- is_sensitive tool -------------------------------------------------------


def test_is_sensitive_requires_llm_layer(guard):
    # No LLM layer configured — the tool must surface an MCP-user-facing error
    # (env var to set), not wardcat's internal "with_llm(...)" advice.
    with pytest.raises(ValueError, match="WARDCAT_LLM_MODEL"):
        run(server.is_sensitive("mail bob@acme.com"))


# --- salt warnings -----------------------------------------------------------


def test_hash_without_salt_warns_per_call(monkeypatch, guard):
    monkeypatch.setattr(server, "_SALT", "")

    out = run(server.redact("mail bob@acme.com", "hash"))

    assert any("unsalted" in w for w in out["warnings"])


def test_hash_with_salt_has_no_salt_warning(guard):
    # The fixture sets a salt, so hashing must not emit the unsalted warning.
    out = run(server.redact("mail bob@acme.com", "hash"))

    assert not any("unsalted" in w for w in out["warnings"])


# --- server_info discovery tool ----------------------------------------------


def test_server_info_reports_capabilities(guard):
    info = run(server.server_info())

    assert set(info["enabled_entities"]) == {"EMAIL", "CREDIT_CARD"}
    assert info["default_action"] == "redact"
    assert set(info["valid_actions"]) == {"warn", "hash", "redact", "mask"}
    assert info["ner_enabled"] is False
    assert info["llm_enabled"] is False


# --- MCP protocol layer (tools registered with structured output) ------------


def test_tools_exposed_with_structured_output_over_mcp(guard):
    """Drive the server through an in-memory MCP session, not just the functions."""
    from mcp.shared.memory import create_connected_server_and_client_session

    async def exercise():
        async with create_connected_server_and_client_session(server.mcp._mcp_server) as client:
            listed = await client.list_tools()
            names = {t.name for t in listed.tools}
            assert {"scan", "redact", "is_sensitive", "server_info"} <= names
            # scan must advertise an output schema and return structured content.
            scan_tool = next(t for t in listed.tools if t.name == "scan")
            assert scan_tool.outputSchema is not None
            assert scan_tool.annotations and scan_tool.annotations.readOnlyHint

            result = await client.call_tool("scan", {"text": TEXT})
            assert result.structuredContent is not None
            assert result.structuredContent["violation_count"] == 2
            # The raw PII must not appear anywhere in the tool result.
            assert "bob@acme.com" not in str(result.structuredContent)

    run(exercise())
