from __future__ import annotations

from rag.generation.answer_service import DeterministicAnswerService
from rag.generation.context_builder import ContextBuilder
from rag.generation.answer_cleanup import strip_embedded_sources
from rag.generation.rag_assistant import RAGAssistant
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector


class FakeRetriever:
    def retrieve(self, query: str, k: int = 10):
        return [
            RetrievedChunk(
                chunk_id="chunk-1",
                score=0.9,
                source="ics-attack.json",
                document_id="attack-pattern--1",
                metadata={"attack_id": "T0819", "title": "Exploit Public-Facing Application", "rrf_score": 0.9},
                text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T0819 Tactic: initial-access Platforms: Control Server Description: Adversaries may exploit public-facing applications in operational technology environments. Detection: Monitor externally exposed services. Mitigations: Segment externally facing systems.",
            ),
            RetrievedChunk(
                chunk_id="chunk-2",
                score=0.8,
                source="enterprise-attack.json",
                document_id="attack-pattern--2",
                metadata={"attack_id": "T1190", "title": "Exploit Public-Facing Application", "rrf_score": 0.8},
                text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190 Tactic: initial-access Platforms: Linux; Windows Description: Adversaries may exploit a weakness in an Internet-facing host or system. Detection: Monitor application logs. Mitigations: Patch exposed services.",
            ),
            RetrievedChunk(
                chunk_id="chunk-3",
                score=0.7,
                source="CISA_ICS_ADV_Master.csv",
                document_id="ICSA-20-123-01",
                metadata={"title": "Siemens SCALANCE X200 Web Server Advisory"},
                text="Advisory: Siemens SCALANCE X200 Web Server Advisory Identifier: ICSA-20-123-01 Vendor: Siemens Product: SCALANCE X200, SCALANCE X204-2, SCALANCE X204IRT, SCALANCE X206-1, SCALANCE X208, SCALANCE XF204 Affected Products: firmware versions 1.0, 1.1, 1.2, 1.3, 1.4, 1.5 CVE: CVE-2020-0001 Severity: High Sector: Critical Manufacturing",
            ),
        ]


def test_rag_assistant_generates_clean_answer_from_structured_context():
    assistant = RAGAssistant(FakeRetriever(), DeterministicAnswerService())
    result = assistant.ask("Explain T1190 Exploit Public-Facing Application", k=5)

    assert result.question == "Explain T1190 Exploit Public-Facing Application"
    assert "T0819" in result.answer
    assert "T1190" in result.answer
    assert "The most relevant ATT&CK context is" not in result.answer
    assert "firmware versions 1.0" not in result.answer
    assert "SCALANCE X206-1" not in result.answer
    assert result.sources[0].document_source in {"Enterprise ATT&CK", "ICS ATT&CK"}
    assert "Vector Results" not in result.answer
    assert "BM25 Results" not in result.answer
    assert "RRF Results" not in result.answer
    assert "chunk_id" not in result.answer
    assert "\nSources\n" not in result.answer


def test_strip_embedded_sources_removes_trailing_sources_section():
    answer = (
        "Exploit Public-Facing Application involves adversaries exploiting weaknesses in internet-facing systems.\n\n"
        "Sources\n"
        "* Enterprise ATT&CK\n"
        "* ICS ATT&CK\n"
    )

    cleaned = strip_embedded_sources(answer)

    assert cleaned == "Exploit Public-Facing Application involves adversaries exploiting weaknesses in internet-facing systems."
    assert "Sources" not in cleaned


def test_strip_embedded_sources_handles_colon_and_duplicate_blocks():
    answer = (
        "Exploit Public-Facing Application involves adversaries exploiting weaknesses.\n\n"
        "Sources\n"
        "* Enterprise ATT&CK\n"
        "* ICS ATT&CK\n\n"
        "Sources:\n"
        "* Enterprise ATT&CK T1190\n"
        "* ICS ATT&CK T0819\n"
    )

    cleaned = strip_embedded_sources(answer)

    assert cleaned == "Exploit Public-Facing Application involves adversaries exploiting weaknesses."
    assert "Sources" not in cleaned


def test_structured_context_groups_attack_and_summarizes_advisory():
    chunks = ContextSelector().select(
        "Exploit Public-Facing Application",
        FakeRetriever().retrieve("Exploit Public-Facing Application"),
    )
    context = ContextBuilder().build(chunks, query="Exploit Public-Facing Application")

    assert "Enterprise ATT&CK" in context
    assert "Exploit Public-Facing Application (T1190)" in context
    assert "ICS ATT&CK" in context
    assert "Exploit Public-Facing Application (T0819)" in context
    assert "Supporting Advisories" not in context
    assert "firmware versions 1.0" not in context
    assert "SCALANCE X206-1" not in context
    assert "Score" not in context
    assert "chunk_id" not in context
