from __future__ import annotations

from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector, QueryIntent, detect_query_intent
from rag.retrieval.query_understanding import (
    concept_match_score,
    expand_query_for_retrieval,
    extract_security_concepts,
    has_security_concept,
)


def _execution_through_api_chunk() -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id="T0871::chunk-1",
        score=0.95,
        source="ics-attack.json",
        document_id="attack-pattern--execution-api",
        metadata={"attack_id": "T0871", "title": "Execution through API", "rrf_score": 0.95},
        text=(
            "Technique Name: Execution through API ATT&CK ID: T0871 "
            "Description: Adversaries may attempt to leverage Application Program Interfaces (APIs) "
            "used for communication between control software and the hardware."
        ),
    )


def _exploit_public_facing_chunk(attack_id: str, source: str) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=f"{attack_id}::chunk-1",
        score=0.7,
        source=source,
        document_id=f"attack-pattern--{attack_id}",
        metadata={"attack_id": attack_id, "title": "Exploit Public-Facing Application", "rrf_score": 0.7},
        text=(
            f"Technique Name: Exploit Public-Facing Application ATT&CK ID: {attack_id} "
            "Description: Adversaries may exploit Internet-facing systems to gain initial access, "
            "including remote code execution against exposed services."
        ),
    )


def test_rce_query_detected_as_threat_scenario():
    query = "unauthorized remote code execution in industrial control systems"
    assert detect_query_intent(query) == QueryIntent.THREAT_SCENARIO_QUERY
    assert has_security_concept(query)
    assert extract_security_concepts(query)[0].name == "remote_code_execution"


def test_expand_query_for_rce_adds_exploit_terms():
    query = "unauthorized remote code execution in industrial control systems"
    expanded = expand_query_for_retrieval(query)
    assert "exploit public-facing application" in expanded.lower()


def test_concept_match_penalizes_execution_only_technique():
    query = "unauthorized remote code execution in industrial control systems"
    assert concept_match_score(query, _execution_through_api_chunk()) < 0
    assert concept_match_score(query, _exploit_public_facing_chunk("T0819", "ics-attack.json")) > 0


def test_context_selector_prefers_rce_relevant_techniques():
    retrieved = [
        _execution_through_api_chunk(),
        _exploit_public_facing_chunk("T0819", "ics-attack.json"),
        _exploit_public_facing_chunk("T1190", "enterprise-attack.json"),
    ]
    query = "unauthorized remote code execution in industrial control systems"

    selected = ContextSelector().select(query, retrieved)
    selected_ids = {chunk.metadata["attack_id"] for chunk in selected}

    assert "T0871" not in selected_ids
    assert "T0819" in selected_ids or "T1190" in selected_ids


def test_scenario_query_detected_for_phishing_chain():
    assert detect_query_intent("How could phishing lead to unauthorized access?") == QueryIntent.THREAT_SCENARIO_QUERY


def test_spearphishing_definition_is_general_concept_not_scenario():
    assert detect_query_intent("What is spearphishing?") == QueryIntent.GENERAL_CONCEPT_QUERY


def test_expand_query_skips_subtechnique_terms_for_concept_definition():
    query = "What is spearphishing?"
    expanded = expand_query_for_retrieval(query)
    assert expanded == query
    assert "attachment" not in expanded.lower()
