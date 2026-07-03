from __future__ import annotations

from rag.generation.answer_service import DeterministicAnswerService
from rag.generation.context_builder import ContextBuilder
from rag.generation.rag_assistant import RAGAssistant
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector, QueryIntent, detect_query_intent


def _spearphishing_chunk(attack_id: str, title: str, source: str, description: str) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=f"{attack_id}::chunk-1",
        score=0.8,
        source=source,
        document_id=f"attack-pattern--{attack_id}",
        metadata={"attack_id": attack_id, "title": title, "rrf_score": 0.8},
        text=(
            f"Technique Name: {title} ATT&CK ID: {attack_id} "
            f"Tactic: initial-access Description: {description}"
        ),
    )


def test_spearphishing_detected_as_general_concept_query():
    assert detect_query_intent("What is spearphishing?") == QueryIntent.GENERAL_CONCEPT_QUERY


def test_context_selector_keeps_multiple_spearphishing_techniques():
    retrieved = [
        _spearphishing_chunk(
            "T1566.003",
            "Spearphishing via Service",
            "enterprise-attack.json",
            "Adversaries may send spearphishing messages through third-party services.",
        ),
        _spearphishing_chunk(
            "T1566.001",
            "Spearphishing Attachment",
            "enterprise-attack.json",
            "Adversaries may send spearphishing emails with a malicious attachment.",
        ),
        _spearphishing_chunk(
            "T1566.002",
            "Spearphishing Link",
            "enterprise-attack.json",
            "Adversaries may send spearphishing emails with a malicious link.",
        ),
        _spearphishing_chunk(
            "T0865",
            "Spearphishing Attachment",
            "ics-attack.json",
            "Adversaries may send spearphishing emails with malicious attachments to compromise ICS users.",
        ),
        _spearphishing_chunk(
            "T0832",
            "Spearphishing Attachment",
            "ics-attack.json",
            "Adversaries may use spearphishing attachment techniques in ICS environments.",
        ),
    ]

    selected = ContextSelector().select("What is spearphishing?", retrieved)
    selected_ids = {chunk.metadata["attack_id"] for chunk in selected}

    assert "T1566.001" in selected_ids
    assert "T1566.002" in selected_ids
    assert len({chunk_id for chunk_id in selected_ids if chunk_id.startswith("T1566")}) >= 2


def test_deterministic_concept_answer_summarizes_multiple_techniques():
    chunks = [
        _spearphishing_chunk(
            "T1566.001",
            "Spearphishing Attachment",
            "enterprise-attack.json",
            "Adversaries may send spearphishing emails with a malicious attachment.",
        ),
        _spearphishing_chunk(
            "T1566.002",
            "Spearphishing Link",
            "enterprise-attack.json",
            "Adversaries may send spearphishing emails with a malicious link.",
        ),
        _spearphishing_chunk(
            "T0865",
            "Spearphishing Attachment",
            "ics-attack.json",
            "Adversaries may send spearphishing emails with malicious attachments to compromise ICS users.",
        ),
    ]
    context = ContextBuilder().build(chunks, query="What is spearphishing?")

    answer = DeterministicAnswerService().generate("What is spearphishing?", context)

    assert "cybersecurity concept" in answer.lower()
    assert "T1566.001" in answer
    assert "T1566.002" in answer
    assert "T0865" in answer
    assert "Spearphishing via Service is an ATT&CK technique" not in answer


class HallucinatingAnswerService:
    def generate(self, query: str, context: str) -> str:
        return "Spearphishing via Service is an ATT&CK technique in which adversaries may use unrelated generic advice."


class SpearphishingRetriever:
    def retrieve(self, query: str, k: int = 10):
        return [
            _spearphishing_chunk(
                "T1566.003",
                "Spearphishing via Service",
                "enterprise-attack.json",
                "Adversaries may send spearphishing messages through third-party services.",
            ),
            _spearphishing_chunk(
                "T1566.001",
                "Spearphishing Attachment",
                "enterprise-attack.json",
                "Adversaries may send spearphishing emails with a malicious attachment.",
            ),
            _spearphishing_chunk(
                "T0865",
                "Spearphishing Attachment",
                "ics-attack.json",
                "Adversaries may send spearphishing emails with malicious attachments to compromise ICS users.",
            ),
        ]


def test_rag_assistant_uses_concept_formatter_for_spearphishing():
    assistant = RAGAssistant(SpearphishingRetriever(), HallucinatingAnswerService())
    result = assistant.ask("What is spearphishing?", k=5)

    assert "cybersecurity concept" in result.answer.lower()
    assert "T1566.001" in result.answer
    assert "unrelated generic advice" not in result.answer
