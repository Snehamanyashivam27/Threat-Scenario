from __future__ import annotations

from pathlib import Path

import pytest

from rag.context.context_generator import DeterministicContextGenerator
from rag.context.cache import ContextCache
from rag.chunking.contextual_chunker import ContextualChunker
from rag.embeddings.embedding_service import DeterministicEmbeddingService
from rag.ingestion.loaders import load_attack_bundle, load_cisa_advisories
from rag.ingestion.parser import parse_attack_bundle, parse_cisa_advisories
from rag.models.document import ChunkDocument, RetrievedChunk
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.rrf import reciprocal_rank_fusion
from rag.retrieval.vector_retriever import VectorRetriever
from rag.vectorstore.chroma_store import ChromaStore


ROOT = Path(__file__).resolve().parents[1]


def _sample_chunks():
    enterprise = load_attack_bundle(ROOT / "enterprise-attack.json")
    advisories = load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")
    attack_docs = parse_attack_bundle(enterprise, source_name="enterprise-attack.json")[:2]
    advisory_docs = parse_cisa_advisories(advisories[:2], source_name="CISA_ICS_ADV_Master.csv")
    documents = attack_docs + advisory_docs
    raw = ContextualChunker().chunk_documents(documents)
    return DeterministicContextGenerator(cache=ContextCache()).enrich_chunks(raw)


def test_document_loading():
    enterprise = load_attack_bundle(ROOT / "enterprise-attack.json")
    advisories = load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")
    assert enterprise["type"] == "bundle"
    assert len(enterprise["objects"]) > 0
    assert len(advisories) > 0


def test_contextual_chunking():
    chunks = _sample_chunks()
    assert chunks
    assert all(chunk.text for chunk in chunks)
    assert any(chunk.text.startswith("Technique Name:") for chunk in chunks)
    assert any("ATT&CK ID:" in chunk.text for chunk in chunks)
    assert any("Tactic:" in chunk.text for chunk in chunks)
    assert any("Platforms:" in chunk.text for chunk in chunks)
    assert any("Description:" in chunk.text for chunk in chunks)
    assert any("Advisory:" in chunk.text for chunk in chunks)


def test_embedding_generation():
    embeddings = DeterministicEmbeddingService().embed_documents(["alpha beta", "gamma delta"])
    assert len(embeddings) == 2
    assert len(embeddings[0]) == 32


def test_chroma_indexing():
    chunks = _sample_chunks()[:4]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    results = store.similarity_search("remote access", k=2)
    assert len(results) == 2
    assert results[0].text


def test_chroma_persistence_round_trip(tmp_path):
    chunks = _sample_chunks()[:4]
    persist_directory = tmp_path / "chroma"
    store = ChromaStore(DeterministicEmbeddingService(), persist_directory=persist_directory)
    if store._backend != "chroma":
        pytest.skip("chromadb is required for the persistence test")

    store.add_chunks(chunks)
    reopened = ChromaStore(DeterministicEmbeddingService(), persist_directory=persist_directory)
    results = reopened.similarity_search("advisory", k=2)
    assert results
    assert persist_directory.exists()
    assert any(result.document_id for result in results)


def test_bm25_retrieval():
    chunks = _sample_chunks()[:8]
    retriever = BM25Retriever(chunks)
    results = retriever.retrieve("industrial control system advisory", k=3)
    assert len(results) == 3
    assert results[0].text


def test_bm25_ignores_zero_score_matches():
    chunks = [
        ChunkDocument(document_id="doc-a", chunk_id="a", source="test", title="Alpha", original_text="alpha beta"),
        ChunkDocument(document_id="doc-b", chunk_id="b", source="test", title="Gamma", original_text="gamma delta"),
    ]
    retriever = BM25Retriever(chunks)

    assert retriever.retrieve("unmatched-token", k=2) == []
    assert retriever.retrieve("!!!", k=2) == []


def test_vector_retrieval():
    chunks = _sample_chunks()[:8]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    retriever = VectorRetriever(store)
    results = retriever.retrieve("threat mitigation", k=3)
    assert len(results) == 3


def test_rrf_ranking():
    left = [
        RetrievedChunk(chunk_id="a", score=1.0, source="vector", document_id="doc-a", metadata={}, text="a"),
        RetrievedChunk(chunk_id="b", score=0.9, source="vector", document_id="doc-b", metadata={}, text="b"),
    ]
    right = [
        RetrievedChunk(chunk_id="b", score=1.0, source="bm25", document_id="doc-b", metadata={}, text="b"),
        RetrievedChunk(chunk_id="a", score=0.9, source="bm25", document_id="doc-a", metadata={}, text="a"),
    ]
    fused = reciprocal_rank_fusion([left, right])
    assert len(fused) == 2
    assert fused[0].score >= fused[1].score


def test_exact_name_bias_updates_returned_score_and_preserves_rrf_score():
    results = [
        RetrievedChunk(chunk_id="generic", score=0.9, source="vector", document_id="doc-g", metadata={"title": "Generic"}, text="Technique: Generic"),
        RetrievedChunk(chunk_id="exact", score=0.1, source="bm25", document_id="doc-e", metadata={"title": "Exact Match"}, text="Technique: Exact Match"),
    ]

    ranked = HybridRetriever._apply_exact_name_bias("Exact Match", results)

    assert ranked[0].chunk_id == "exact"
    assert ranked[0].score == 1.1
    assert ranked[0].metadata["rrf_score"] == 0.1
    assert ranked[0].score >= ranked[1].score


def test_hybrid_retrieval():
    chunks = _sample_chunks()[:12]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    vector = VectorRetriever(store)
    bm25 = BM25Retriever(chunks)
    hybrid = HybridRetriever(vector, bm25)
    results = hybrid.retrieve("critical vulnerability advisory", k=5)
    assert 0 < len(results) <= 5
    assert results[0].score >= results[-1].score


class RecordingRetriever:
    def __init__(self, source: str):
        self.source = source
        self.requested_k: int | None = None

    def retrieve(self, query: str, k: int = 5):
        self.requested_k = k
        return [
            RetrievedChunk(
                chunk_id=f"{self.source}-{index}",
                score=float(20 - index),
                source=self.source,
                document_id=f"doc-{index}",
                metadata={"title": f"Title {index}"},
                text=f"Technique Name: Title {index}",
            )
            for index in range(k)
        ]


def test_hybrid_retrieval_uses_twenty_candidates_before_rrf():
    vector = RecordingRetriever("vector")
    bm25 = RecordingRetriever("bm25")
    hybrid = HybridRetriever(vector, bm25)

    results = hybrid.retrieve("query", k=5)

    assert vector.requested_k == 20
    assert bm25.requested_k == 20
    assert len(results) == 5


def test_attack_query_bias_prefers_attack_sources_over_cisa():
    results = [
        RetrievedChunk(chunk_id="cisa", score=0.5, source="CISA_ICS_ADV_Master.csv", document_id="advisory", metadata={"title": "Exploit Public-Facing Application"}, text="Advisory: Siemens"),
        RetrievedChunk(chunk_id="attack", score=0.4, source="enterprise-attack.json", document_id="attack", metadata={"title": "Exploit Public-Facing Application", "attack_id": "T1190"}, text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190"),
    ]

    ranked = HybridRetriever._apply_query_source_bias("Explain T1190", results)

    assert ranked[0].chunk_id == "attack"
    assert ranked[0].metadata["source_bias"] > 0
    assert ranked[1].metadata["source_bias"] < 0


def test_advisory_query_bias_allows_cisa_sources():
    results = [
        RetrievedChunk(chunk_id="cisa", score=0.4, source="CISA_ICS_ADV_Master.csv", document_id="advisory", metadata={"title": "Siemens Advisory"}, text="Advisory: Siemens"),
        RetrievedChunk(chunk_id="attack", score=0.4, source="enterprise-attack.json", document_id="attack", metadata={"title": "Exploit Public-Facing Application", "attack_id": "T1190"}, text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190"),
    ]

    ranked = HybridRetriever._apply_query_source_bias("Which CISA advisories mention CVE-2020-0001?", results)

    assert ranked[0].chunk_id == "cisa"
    assert ranked[0].metadata["source_bias"] > 0
