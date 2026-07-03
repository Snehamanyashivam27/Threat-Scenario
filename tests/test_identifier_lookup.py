from __future__ import annotations

from pathlib import Path

from rag.context.cache import ContextCache
from rag.context.context_generator import DeterministicContextGenerator
from rag.chunking.contextual_chunker import ContextualChunker
from rag.embeddings.embedding_service import DeterministicEmbeddingService
from rag.ingestion.loaders import load_cisa_advisories
from rag.ingestion.parser import parse_cisa_advisories
from rag.models.document import ChunkDocument, RetrievedChunk
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.context_selector import ContextSelector
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.identifier_lookup import lookup_by_identifiers
from rag.retrieval.vector_retriever import VectorRetriever
from rag.vectorstore.chroma_store import ChromaStore


def _siemens_cve_chunk() -> ChunkDocument:
    return ChunkDocument(
        document_id="1749",
        chunk_id="1749::chunk-1",
        source="CISA_ICS_ADV_Master.csv",
        title="Siemens Web Server of SCALANCE X200 (Update A)",
        original_text=(
            "Advisory: Siemens Web Server of SCALANCE X200 (Update A) "
            "Identifier: 1749 "
            "Vendor: Siemens "
            "Product: Siemens Web Server of SCALANCE X200 "
            "CVE: CVE-2021-25668, CVE-2021-25669 "
            "CWE: CWE-122, CWE-121 "
            "Severity: Critical "
            "Sector: Critical Manufacturing"
        ),
        metadata={"kind": "cisa-ics-advisory"},
    )


def _fuji_cve_chunk(document_id: str, cve: str, cwe: str) -> ChunkDocument:
    return ChunkDocument(
        document_id=document_id,
        chunk_id=f"{document_id}::chunk-1",
        source="CISA_ICS_ADV_Master.csv",
        title=f"Fuji Electric V-Server {document_id}",
        original_text=(
            f"Advisory: Fuji Electric V-Server {document_id} "
            f"Identifier: {document_id} "
            "Vendor: Fuji Electric "
            "Product: V-Server "
            f"CVE: {cve} "
            f"CWE: {cwe} "
            "Severity: High "
            "Sector: Critical Manufacturing"
        ),
        metadata={"kind": "cisa-ics-advisory"},
    )


def _attack_chunk(attack_id: str, source: str) -> ChunkDocument:
    return ChunkDocument(
        document_id=f"attack-pattern--{attack_id}",
        chunk_id=f"{attack_id}::chunk-1",
        source=source,
        title="Exploit Public-Facing Application",
        original_text=(
            f"Technique Name: Exploit Public-Facing Application ATT&CK ID: {attack_id} "
            "Tactic: initial-access Platforms: Linux Description: Adversaries may exploit Internet-facing systems."
        ),
        metadata={"kind": "attack-pattern", "attack_id": attack_id},
        attack_id=attack_id,
    )


def test_identifier_lookup_returns_matching_cve_only():
    chunks = [
        _fuji_cve_chunk("834", "CVE-2018-5442", "CWE-121"),
        _siemens_cve_chunk(),
        _fuji_cve_chunk("725", "CVE-2017-9639", "CWE-119"),
    ]

    results = lookup_by_identifiers(chunks, "Explain CVE-2021-25668")

    assert len(results) == 1
    assert results[0].document_id == "1749"
    assert results[0].metadata["retrieval_method"] == "identifier"


def test_identifier_lookup_returns_both_attack_frameworks_for_technique_id():
    chunks = [
        _attack_chunk("T1190", "enterprise-attack.json"),
        _attack_chunk("T0819", "ics-attack.json"),
        _siemens_cve_chunk(),
    ]

    results = lookup_by_identifiers(chunks, "Explain T1190")

    assert {item.document_id for item in results} == {"attack-pattern--T1190"}


def test_hybrid_retriever_skips_rrf_for_identifier_queries():
    chunks = [
        _fuji_cve_chunk("834", "CVE-2018-5442", "CWE-121"),
        _siemens_cve_chunk(),
        _fuji_cve_chunk("725", "CVE-2017-9639", "CWE-119"),
    ]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    hybrid = HybridRetriever(VectorRetriever(store), BM25Retriever(chunks))

    vector_results, bm25_results, fused_results = hybrid.retrieve_with_debug("Explain CVE-2021-25668", k=5)

    assert vector_results == []
    assert bm25_results == []
    assert len(fused_results) == 1
    assert fused_results[0].document_id == "1749"


def test_context_selector_filters_unrelated_cisa_advisories_for_cve_query():
    chunks = [
        _fuji_cve_chunk("834", "CVE-2018-5442", "CWE-121"),
        _siemens_cve_chunk(),
        _fuji_cve_chunk("725", "CVE-2017-9639", "CWE-119"),
    ]
    retrieved = [
        _as_retrieved(chunks[0], score=0.9),
        _as_retrieved(chunks[1], score=0.8),
        _as_retrieved(chunks[2], score=0.7),
    ]

    selected = ContextSelector().select("Explain CVE-2021-25668", retrieved)

    assert len(selected) == 1
    assert selected[0].document_id == "1749"


def _as_retrieved(chunk: ChunkDocument, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk.chunk_id,
        score=score,
        source=chunk.source,
        document_id=chunk.document_id,
        metadata=dict(chunk.metadata),
        text=chunk.original_text,
        contextual_text=chunk.contextual_text,
    )


ROOT = Path(__file__).resolve().parents[1]


def test_cve_lookup_uses_identifier_path_on_real_cisa_data():
    rows = load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")
    documents = parse_cisa_advisories(rows, source_name="CISA_ICS_ADV_Master.csv")
    chunks = DeterministicContextGenerator(cache=ContextCache()).enrich_chunks(ContextualChunker().chunk_documents(documents))
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    hybrid = HybridRetriever(VectorRetriever(store), BM25Retriever(chunks))

    results = hybrid.retrieve("Explain CVE-2021-25668", k=5)

    assert results
    assert results[0].document_id == "1749"
    assert results[0].metadata.get("retrieval_method") == "identifier"
    assert all("CVE-2021-25668" in item.text for item in results)
