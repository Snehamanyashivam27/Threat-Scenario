from __future__ import annotations

from rag.generation.context_builder import ContextBuilder
from rag.models.document import RetrievedChunk


def test_tactic_list_never_appends_related_products():
    chunk = RetrievedChunk(
        chunk_id="T1078::chunk-1",
        score=0.9,
        source="enterprise-attack.json",
        document_id="attack-pattern--1078",
        metadata={"attack_id": "T1078", "title": "Valid Accounts"},
        text=(
            "Technique Name: Valid Accounts ATT&CK ID: T1078 "
            "Tactic: initial-access; persistence; privilege-escalation; defense-evasion "
            "Description: Adversaries may obtain and abuse credentials of existing accounts."
        ),
    )

    context = ContextBuilder().build([chunk], query="What is Valid Accounts?")

    assert "related products" not in context.lower()
    assert "defense-evasion" in context.lower() or "defense evasion" in context.lower()
