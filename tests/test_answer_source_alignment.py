from __future__ import annotations

from rag.generation.answer_service import DeterministicAnswerService
from rag.generation.context_builder import ContextBuilder
from rag.generation.rag_assistant import RAGAssistant
from rag.models.document import RetrievedChunk


def _domain_account_chunks() -> list[RetrievedChunk]:
    return [
        RetrievedChunk(
            chunk_id="T1136.002::chunk-1",
            score=0.95,
            source="enterprise-attack.json",
            document_id="attack-pattern--T1136.002",
            metadata={"attack_id": "T1136.002", "title": "Create Account: Domain Account", "rrf_score": 0.95},
            text=(
                "Technique Name: Create Account: Domain Account ATT&CK ID: T1136.002 "
                "Tactic: persistence Description: Adversaries may create a domain account to maintain access."
            ),
        ),
        RetrievedChunk(
            chunk_id="T1078.002::chunk-1",
            score=0.9,
            source="enterprise-attack.json",
            document_id="attack-pattern--T1078.002",
            metadata={"attack_id": "T1078.002", "title": "Domain Accounts", "rrf_score": 0.9},
            text=(
                "Technique Name: Domain Accounts ATT&CK ID: T1078.002 "
                "Tactic: initial-access Description: Adversaries may obtain and abuse credentials of a domain account."
            ),
        ),
    ]


def test_deterministic_answer_anchors_to_primary_context_technique():
    query = "What is the Create Account: Domain Account technique?"
    context = ContextBuilder().build(_domain_account_chunks(), query=query)

    answer = DeterministicAnswerService().generate(query, context)

    assert "T1136.002" in answer
    assert "Create Account: Domain Account" in answer
    assert "T1078.002" not in answer


def test_sources_match_context_chunks_for_domain_accounts():
    chunks = _domain_account_chunks()
    context = ContextBuilder().build(chunks, query="What is Domain Accounts?")
    sources = ContextBuilder().build_sources(chunks)

    assert "T1136.002" in context
    assert "T1078.002" in context
    assert [source.attack_id for source in sources] == ["T1136.002", "T1078.002"]


class DomainAccountRetriever:
    def retrieve(self, query: str, k: int = 10):
        return _domain_account_chunks()


def test_rag_assistant_sources_align_with_primary_answer_for_explicit_technique():
    assistant = RAGAssistant(DomainAccountRetriever(), DeterministicAnswerService())
    result = assistant.ask("What is the Create Account: Domain Account technique?", k=5)

    assert "T1136.002" in result.answer
    assert result.sources
    assert result.sources[0].attack_id == "T1136.002"
