from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from rag.chunking.contextual_chunker import ContextualChunker
from rag.context.cache import ContextCache
from rag.context.context_generator import DeterministicContextGenerator
from rag.context.strategies.cisa_advisory import CisaAdvisoryContextStrategy
from rag.context.strategies.enterprise_attack import EnterpriseAttackContextStrategy
from rag.context.strategies.ics_attack import IcsAttackContextStrategy
from rag.embeddings.embedding_service import DeterministicEmbeddingService, EmbeddingService
from rag.ingestion.loaders import load_attack_bundle, load_cisa_advisories
from rag.ingestion.parser import parse_attack_bundle, parse_cisa_advisories
from rag.models.document import ChunkDocument
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.vector_retriever import VectorRetriever
from rag.vectorstore.chroma_store import ChromaStore


ROOT = Path(__file__).resolve().parents[1]


def _sample_documents(limit_attack: int = 2, limit_advisory: int = 2):
    enterprise = load_attack_bundle(ROOT / "enterprise-attack.json")
    ics = load_attack_bundle(ROOT / "ics-attack.json")
    advisories = load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")
    attack_docs = parse_attack_bundle(enterprise, source_name="enterprise-attack.json")[:limit_attack]
    ics_docs = parse_attack_bundle(ics, source_name="ics-attack.json")[:limit_attack]
    advisory_docs = parse_cisa_advisories(advisories[:limit_advisory], source_name="CISA_ICS_ADV_Master.csv")
    return attack_docs + ics_docs + advisory_docs


def _raw_chunks():
    return ContextualChunker().chunk_documents(_sample_documents())


def _enriched_chunks(cache_path: Path | None = None):
    cache = ContextCache(cache_path) if cache_path else ContextCache()
    generator = DeterministicContextGenerator(cache=cache)
    return generator.enrich_chunks(_raw_chunks())


def _enterprise_chunk() -> ChunkDocument:
    return ChunkDocument(
        document_id="attack--enterprise",
        chunk_id="attack--enterprise::chunk-1",
        source="enterprise-attack.json",
        title="Exploit Public-Facing Application",
        original_text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T1190 Tactic: initial-access Platforms: Linux; Windows Description: Adversaries may exploit a weakness in an Internet-facing host.",
        metadata={"kind": "attack-pattern", "source_type": "enterprise-attack.json", "attack_id": "T1190", "tactic": ["initial-access"], "platform": ["Linux", "Windows"]},
        attack_id="T1190",
        tactic=["initial-access"],
        platform=["Linux", "Windows"],
        hash="enterprise-hash",
    )


def _ics_chunk() -> ChunkDocument:
    return ChunkDocument(
        document_id="attack--ics",
        chunk_id="attack--ics::chunk-1",
        source="ics-attack.json",
        title="Exploit Public-Facing Application",
        original_text="Technique Name: Exploit Public-Facing Application ATT&CK ID: T0819 Tactic: initial-access Platforms: Control Server Description: Adversaries may exploit public-facing applications in OT environments.",
        metadata={"kind": "attack-pattern", "source_type": "ics-attack.json", "attack_id": "T0819", "tactic": ["initial-access"], "platform": ["Control Server"]},
        attack_id="T0819",
        tactic=["initial-access"],
        platform=["Control Server"],
        hash="ics-hash",
    )


def _cisa_chunk() -> ChunkDocument:
    return ChunkDocument(
        document_id="ICSA-20-123-01",
        chunk_id="ICSA-20-123-01::chunk-1",
        source="CISA_ICS_ADV_Master.csv",
        title="Siemens SCALANCE X200 Web Server Advisory",
        original_text="Advisory: Siemens SCALANCE X200 Web Server Advisory Identifier: ICSA-20-123-01 Vendor: Siemens Product: SCALANCE X200 CVE: CVE-2020-0001 CWE: CWE-79 Severity: High",
        metadata={
            "kind": "cisa-ics-advisory",
            "source_type": "CISA_ICS_ADV_Master.csv",
            "sections": {
                "vendor": "Siemens",
                "product": "SCALANCE X200",
                "cves": "CVE-2020-0001",
                "cwes": "CWE-79",
                "severity": "High",
            },
        },
        hash="cisa-hash",
    )


def test_enterprise_context_summary():
    summary = EnterpriseAttackContextStrategy().generate(_enterprise_chunk())
    assert "MITRE ATT&CK Enterprise Technique" in summary
    assert "T1190" in summary
    assert "Exploit Public-Facing Application" in summary
    assert "Initial Access" in summary


def test_ics_context_summary():
    summary = IcsAttackContextStrategy().generate(_ics_chunk())
    assert "MITRE ATT&CK for ICS Technique" in summary
    assert "T0819" in summary
    assert "industrial control system" in summary.lower()


def test_cisa_context_summary():
    summary = CisaAdvisoryContextStrategy().generate(_cisa_chunk())
    assert "CISA ICS Advisory" in summary
    assert "Siemens" in summary
    assert "CVE" in summary
    assert "CWE" in summary


def test_original_text_unchanged_after_enrichment():
    raw = _enterprise_chunk()
    enriched = DeterministicContextGenerator(cache=ContextCache()).enrich_chunk(raw)
    assert enriched.original_text == raw.original_text
    assert enriched.contextual_text
    assert enriched.text == raw.original_text


def test_embedding_uses_context_plus_original():
    chunk = DeterministicContextGenerator(cache=ContextCache()).enrich_chunk(_enterprise_chunk())
    captured: list[list[str]] = []

    class RecordingEmbeddingService(EmbeddingService):
        def embed_documents(self, texts):
            captured.extend(list(texts))
            return DeterministicEmbeddingService().embed_documents(texts)

        def embed_query(self, text: str):
            return DeterministicEmbeddingService().embed_query(text)

        def embedding_dimension(self) -> int:
            return 32

    store = ChromaStore(RecordingEmbeddingService())
    store.add_chunks([chunk])

    assert captured == [f"{chunk.contextual_text}\n\n{chunk.original_text}"]


def test_bm25_indexes_original_only():
    chunk = DeterministicContextGenerator(cache=ContextCache()).enrich_chunk(_enterprise_chunk())
    unique_phrase = "zebraquartz marker phrase"
    chunk_with_marker = ChunkDocument(
        document_id=chunk.document_id,
        chunk_id=chunk.chunk_id,
        source=chunk.source,
        title=chunk.title,
        original_text=f"{chunk.original_text} {unique_phrase}",
        contextual_text=chunk.contextual_text,
        metadata=dict(chunk.metadata),
        attack_id=chunk.attack_id,
        tactic=chunk.tactic,
        platform=chunk.platform,
        hash=chunk.hash,
    )
    retriever = BM25Retriever([chunk_with_marker])
    assert "zebraquartz" in retriever.tokenized_chunks[0]
    assert "MITRE ATT&CK Enterprise Technique" not in " ".join(retriever.tokenized_chunks[0])


def test_vector_retrieval_returns_both_fields():
    chunks = _enriched_chunks()[:4]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    retriever = VectorRetriever(store)
    results = retriever.retrieve("initial access exploit", k=2)
    assert results
    assert all(result.text for result in results)
    assert all(result.contextual_text for result in results)
    assert all("Technique Name:" in result.text or "Advisory:" in result.text for result in results)


def test_context_cache_reuse(tmp_path):
    cache_path = tmp_path / "contexts.json"
    generator = DeterministicContextGenerator(cache=ContextCache(cache_path))
    chunk = _enterprise_chunk()

    first = generator.enrich_chunk(chunk)
    with patch.object(EnterpriseAttackContextStrategy, "generate", return_value="patched summary") as mocked:
        second = generator.enrich_chunk(chunk)
        mocked.assert_not_called()

    assert first.contextual_text == second.contextual_text
    assert cache_path.exists()


def test_context_not_generated_at_retrieval():
    retrieval_modules = [
        ROOT / "rag" / "retrieval" / "vector_retriever.py",
        ROOT / "rag" / "retrieval" / "bm25_retriever.py",
        ROOT / "rag" / "retrieval" / "hybrid_retriever.py",
        ROOT / "rag" / "retrieval" / "rrf.py",
        ROOT / "rag" / "vectorstore" / "chroma_store.py",
    ]
    for module_path in retrieval_modules:
        source = module_path.read_text(encoding="utf-8")
        assert "ContextGenerator" not in source
        assert "DeterministicContextGenerator" not in source
        assert "enrich_chunk" not in source


def test_hybrid_retrieval_returns_contextual_summary():
    chunks = _enriched_chunks()[:8]
    store = ChromaStore(DeterministicEmbeddingService())
    store.add_chunks(chunks)
    hybrid = HybridRetriever(VectorRetriever(store), BM25Retriever(chunks))
    results = hybrid.retrieve("critical vulnerability advisory", k=3)
    assert results
    assert all(result.contextual_text for result in results)
