from __future__ import annotations

from rag.models.document import ChunkDocument, RetrievedChunk
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.context_selector import ContextSelector, QueryIntent, detect_query_intent, tactic_match_score
from rag.retrieval.rrf import reciprocal_rank_fusion


def test_rrf_breaks_score_ties_deterministically():
    # Symmetric ranks produce identical fused scores; chunk_id breaks ties deterministically.
    left = [
        RetrievedChunk(chunk_id="b", score=1.0, source="vector", document_id="doc-b", metadata={}, text="b"),
        RetrievedChunk(chunk_id="a", score=0.9, source="vector", document_id="doc-a", metadata={}, text="a"),
    ]
    right = [
        RetrievedChunk(chunk_id="a", score=1.0, source="bm25", document_id="doc-a", metadata={}, text="a"),
        RetrievedChunk(chunk_id="b", score=0.9, source="bm25", document_id="doc-b", metadata={}, text="b"),
    ]

    first = reciprocal_rank_fusion([left, right])
    second = reciprocal_rank_fusion([left, right])

    assert [item.chunk_id for item in first] == [item.chunk_id for item in second]
    assert abs(first[0].score - first[1].score) < 1e-12
    assert first[0].chunk_id == "a"


def test_bm25_deduplicates_expanded_query_terms():
    chunks = [
        ChunkDocument(
            document_id="doc-a",
            chunk_id="a",
            source="test",
            title="Exploit",
            original_text="exploit public-facing application remote code execution",
        ),
        ChunkDocument(
            document_id="doc-b",
            chunk_id="b",
            source="test",
            title="Other",
            original_text="unrelated content only",
        ),
    ]
    retriever = BM25Retriever(chunks)
    repeated_query = "exploit exploit exploit public-facing application"
    single_query = "exploit public-facing application"

    repeated_score = retriever.retrieve(repeated_query, k=1)[0].score
    single_score = retriever.retrieve(single_query, k=1)[0].score

    assert repeated_score == single_score


def test_context_selector_honors_pool_size_override():
    noise = [
        RetrievedChunk(
            chunk_id=f"T{i:04d}::chunk-1",
            score=0.5,
            source="enterprise-attack.json",
            document_id=f"doc-{i}",
            metadata={"attack_id": f"T{i:04d}", "title": f"Noise Technique {i}"},
            text=f"Technique Name: Noise Technique {i} ATT&CK ID: T{i:04d} Description: unrelated noise.",
        )
        for i in range(14)
    ]
    target = RetrievedChunk(
        chunk_id="T1190::chunk-1",
        score=0.4,
        source="enterprise-attack.json",
        document_id="attack-pattern--T1190",
        metadata={"attack_id": "T1190", "title": "Exploit Public-Facing Application", "rrf_score": 0.4},
        text=(
            "Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190 "
            "Tactic: initial-access Description: Adversaries may exploit Internet-facing systems."
        ),
    )
    chunks = noise + [target]
    query = "What is Exploit Public-Facing Application?"

    small_pool = ContextSelector().select(query, chunks, pool_size=10)
    large_pool = ContextSelector().select(query, chunks, pool_size=15)

    assert "T1190" not in {chunk.metadata.get("attack_id") for chunk in small_pool}
    assert "T1190" in {chunk.metadata.get("attack_id") for chunk in large_pool}


def test_tactic_lookup_intent_detected():
    assert detect_query_intent("What is the Initial Access tactic?") == QueryIntent.ATTACK_TACTIC_LOOKUP


def test_tactic_match_score_matches_metadata_tactic():
    chunk = RetrievedChunk(
        chunk_id="T1190::chunk-1",
        score=0.5,
        source="enterprise-attack.json",
        document_id="attack-pattern--T1190",
        metadata={"attack_id": "T1190", "title": "Exploit Public-Facing Application"},
        text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190 Tactic: initial-access Description: Example.",
    )

    assert tactic_match_score(chunk, "initial access") > 0
