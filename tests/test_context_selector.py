from __future__ import annotations

from rag.generation.answer_service import DeterministicAnswerService
from rag.generation.context_builder import ContextBuilder
from rag.generation.rag_assistant import RAGAssistant
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector, QueryIntent, detect_query_intent


def _exploit_public_facing_chunk(attack_id: str, source: str, chunk_suffix: str) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=f"{attack_id}::chunk-1",
        score=0.9,
        source=source,
        document_id=f"attack-pattern--{chunk_suffix}",
        metadata={"attack_id": attack_id, "title": "Exploit Public-Facing Application", "rrf_score": 0.9},
        text=(
            f"Technique Name: Exploit Public-Facing Application ATT&CK ID: {attack_id} "
            "Tactic: initial-access Platforms: Linux Description: Adversaries may exploit Internet-facing systems. "
            "Detection: Monitor exposed services. Mitigations: Patch exposed services."
        ),
    )


def _noise_chunk(attack_id: str, title: str, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=f"{attack_id}::chunk-1",
        score=score,
        source="enterprise-attack.json",
        document_id=f"attack-pattern--{attack_id}",
        metadata={"attack_id": attack_id, "title": title, "rrf_score": score},
        text=f"Technique Name: {title} ATT&CK ID: {attack_id} Tactic: resource-development Description: Adversaries may exploit related capabilities.",
    )


def _cisa_chunk() -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id="ICSA-20-123-01::chunk-1",
        score=0.85,
        source="CISA_ICS_ADV_Master.csv",
        document_id="ICSA-20-123-01",
        metadata={"title": "Siemens Advisory"},
        text="Advisory: Siemens Advisory Vendor: Siemens Product: SCALANCE CVE: CVE-2020-0001",
    )


def test_detect_attack_technique_lookup_intent():
    assert detect_query_intent("What is Exploit Public-Facing Application?") == QueryIntent.ATTACK_TECHNIQUE_LOOKUP


def test_context_selector_keeps_matching_techniques_only():
    retrieved = [
        _exploit_public_facing_chunk("T1190", "enterprise-attack.json", "enterprise"),
        _exploit_public_facing_chunk("T0819", "ics-attack.json", "ics"),
        _noise_chunk("T1588.005", "Exploit Capabilities", 0.88),
        _noise_chunk("T1595", "Active Scanning", 0.87),
        _noise_chunk("T1597.001", "Search Open Technical Databases", 0.86),
    ]

    selected = ContextSelector().select("What is Exploit Public-Facing Application?", retrieved)
    selected_ids = {chunk.metadata["attack_id"] for chunk in selected}

    assert selected_ids == {"T1190", "T0819"}
    assert "T1588.005" not in selected_ids
    assert "T1595" not in selected_ids
    assert "T1597.001" not in selected_ids


def test_attack_lookup_prioritizes_attack_over_cisa():
    retrieved = [
        _cisa_chunk(),
        _exploit_public_facing_chunk("T1190", "enterprise-attack.json", "enterprise"),
        _exploit_public_facing_chunk("T0819", "ics-attack.json", "ics"),
    ]

    selected = ContextSelector().select("What is Exploit Public-Facing Application?", retrieved)
    assert all("attack" in chunk.source for chunk in selected)
    assert all(chunk.metadata["attack_id"] in {"T1190", "T0819"} for chunk in selected)


def test_context_builder_groups_frameworks():
    selected = [
        _exploit_public_facing_chunk("T1190", "enterprise-attack.json", "enterprise"),
        _exploit_public_facing_chunk("T0819", "ics-attack.json", "ics"),
    ]
    context = ContextBuilder().build(selected, query="What is Exploit Public-Facing Application?")

    assert "Enterprise ATT&CK" in context
    assert "ICS ATT&CK" in context
    assert "Technique: Exploit Public-Facing Application (T1190)" in context
    assert "Technique: Exploit Public-Facing Application (T0819)" in context
    assert "Description:" in context
    assert "Detection:" in context
    assert "Mitigation:" in context


class FakeRetriever:
    def retrieve(self, query: str, k: int = 10):
        return [
            _exploit_public_facing_chunk("T0819", "ics-attack.json", "ics"),
            _exploit_public_facing_chunk("T1190", "enterprise-attack.json", "enterprise"),
            _noise_chunk("T1588.005", "Exploit Capabilities", 0.7),
            _noise_chunk("T1595", "Active Scanning", 0.65),
            _noise_chunk("T1597.001", "Search Open Technical Databases", 0.6),
            _cisa_chunk(),
        ]


def test_rag_assistant_filters_noise_before_answer():
    assistant = RAGAssistant(FakeRetriever(), DeterministicAnswerService())
    result = assistant.ask("What is Exploit Public-Facing Application?", k=5)

    assert "T1190" in result.answer
    assert "T0819" in result.answer
    assert "T1588.005" not in result.answer
    assert "T1595" not in result.answer
    assert "T1597.001" not in result.answer
    assert "The most relevant ATT&CK context is" not in result.answer
    assert "Top retrieved chunks" not in result.answer
    assert "\nSources\n" not in result.answer
    assert result.sources[0].document_source in {"Enterprise ATT&CK", "ICS ATT&CK"}
