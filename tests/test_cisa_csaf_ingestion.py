from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from rag.chunking.contextual_chunker import ContextualChunker
from rag.context.cache import ContextCache
from rag.context.context_generator import DeterministicContextGenerator
from rag.embeddings.embedding_service import DeterministicEmbeddingService
from rag.ingestion.csaf.discovery import discover_advisory_ids_from_master_csv
from rag.ingestion.csaf.documents import cve_detail_to_source_document, load_csaf_source_documents
from rag.ingestion.csaf.downloader import CsafDownloader
from rag.ingestion.csaf.parser import CsafParseError, parse_csaf_document, parse_csaf_file
from rag.ingestion.loaders import load_attack_bundle, load_cisa_advisories
from rag.ingestion.parser import parse_attack_bundle, parse_cisa_advisories
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.identifier_lookup import lookup_by_identifiers
from rag.retrieval.vector_retriever import VectorRetriever
from rag.vectorstore.chroma_store import ChromaStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "cisa_csaf"


def test_parse_single_cve_advisory():
    records = parse_csaf_file(FIXTURES / "icsa-25-162-03.json")
    assert len(records) == 1
    record = records[0]
    assert record.cve_id == "CVE-2024-41797"
    assert record.advisory_id == "ICSA-25-162-03"
    assert record.cwe_ids == ["CWE-269"]
    assert record.vendor
    assert record.description
    assert record.prerequisites.network_access in {None, "remote", "local", "adjacent", "physical"}


def test_parse_multi_cve_advisory_keeps_per_cve_cwe_binding():
    records = parse_csaf_file(FIXTURES / "icsa-24-326-03.json")
    assert len(records) == 2
    by_cve = {record.cve_id: record for record in records}

    assert by_cve["CVE-2024-8933"].cwe_ids == ["CWE-924"]
    assert by_cve["CVE-2024-8935"].cwe_ids == ["CWE-290"]
    assert by_cve["CVE-2024-8933"].cwe_ids != by_cve["CVE-2024-8935"].cwe_ids
    assert "CWE-290" not in by_cve["CVE-2024-8933"].cwe_ids
    assert "CWE-924" not in by_cve["CVE-2024-8935"].cwe_ids


def test_product_and_version_extraction():
    records = parse_csaf_file(FIXTURES / "icsa-24-326-03.json")
    record = next(item for item in records if item.cve_id == "CVE-2024-8933")
    assert record.vendor == "Schneider Electric"
    assert record.product
    assert record.affected_versions


def test_missing_optional_fields_remain_empty():
    records = parse_csaf_file(FIXTURES / "sparse-optional-fields.json")
    assert len(records) == 1
    record = records[0]
    assert record.cve_id == "CVE-2099-0001"
    assert record.cwe_ids == []
    assert record.cvss_score is None
    assert record.severity is None
    assert record.prerequisites.authentication_required is None
    assert record.effects == []


def test_duplicate_cve_within_advisory_is_deduped():
    data = json.loads((FIXTURES / "sparse-optional-fields.json").read_text())
    data["vulnerabilities"].append(dict(data["vulnerabilities"][0]))
    records = parse_csaf_document(data)
    assert len(records) == 1


def test_malformed_advisory_raises():
    with pytest.raises(CsafParseError):
        parse_csaf_file(FIXTURES / "malformed.json")


def test_cached_advisory_skips_download(tmp_path):
    cache_dir = tmp_path / "cisa_csaf"
    cache_dir.mkdir()
    cached = cache_dir / "ICSA-25-162-03.json"
    cached.write_text((FIXTURES / "icsa-25-162-03.json").read_text(encoding="utf-8"), encoding="utf-8")

    opener = MagicMock()
    downloader = CsafDownloader(cache_dir=cache_dir, opener=opener)
    result = downloader.download("ICSA-25-162-03", refresh=False)

    assert result.status == "cached"
    assert result.path == cached
    opener.assert_not_called()


def test_failed_download_is_resilient(tmp_path):
    def failing_opener(request, timeout=30):  # noqa: ARG001
        raise TimeoutError("network down")

    downloader = CsafDownloader(
        cache_dir=tmp_path / "cisa_csaf",
        opener=failing_opener,
        max_retries=2,
        backoff_seconds=0.0,
    )
    result = downloader.download("ICSA-24-326-03", refresh=True)
    assert result.status == "unavailable"
    assert result.path is None


def test_exact_cve_and_advisory_lookup_after_ingestion():
    documents = load_csaf_source_documents(FIXTURES)
    chunks = DeterministicContextGenerator(cache=ContextCache()).enrich_chunks(
        ContextualChunker().chunk_documents(documents)
    )

    cve_hits = lookup_by_identifiers(chunks, "CVE-2024-8935")
    assert cve_hits
    assert any("CVE-2024-8935" in item.text for item in cve_hits)
    assert any(item.metadata.get("kind") == "cisa-csaf-cve" for item in cve_hits)

    advisory_hits = lookup_by_identifiers(chunks, "ICSA-24-326-03")
    assert advisory_hits
    assert any("ICSA-24-326-03" in item.document_id.upper() or "ICSA-24-326-03" in item.text for item in advisory_hits)


def test_product_based_retrieval():
    documents = load_csaf_source_documents(FIXTURES)
    chunks = DeterministicContextGenerator(cache=ContextCache()).enrich_chunks(
        ContextualChunker().chunk_documents(documents)
    )
    bm25 = BM25Retriever(chunks)
    results = bm25.retrieve("Schneider Electric Modicon M340 CVE authentication bypass", k=5)
    assert results
    assert any("CVE-2024-8935" in item.text or "CVE-2024-8933" in item.text for item in results)


def test_existing_attack_and_csv_ingestion_still_works(tmp_path):
    enterprise = parse_attack_bundle(load_attack_bundle(ROOT / "enterprise-attack.json"), "enterprise-attack.json")
    ics = parse_attack_bundle(load_attack_bundle(ROOT / "ics-attack.json"), "ics-attack.json")
    csv_docs = parse_cisa_advisories(load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")[:5], "CISA_ICS_ADV_Master.csv")
    assert enterprise
    assert ics
    assert csv_docs
    assert all(doc.source == "enterprise-attack.json" for doc in enterprise)
    assert all(doc.source == "ics-attack.json" for doc in ics)
    assert all(doc.metadata.get("kind") == "cisa-ics-advisory" for doc in csv_docs)

    empty_csaf = tmp_path / "empty_csaf"
    empty_csaf.mkdir()
    assert load_csaf_source_documents(empty_csaf) == []



def test_csaf_enrichment_enters_existing_hybrid_pipeline(tmp_path):
    store = ChromaStore(
        DeterministicEmbeddingService(),
        persist_directory=tmp_path / "chroma",
    )
    # Build a tiny mixed corpus: sample ATT&CK + CSV + CSAF fixtures.
    enterprise = parse_attack_bundle(load_attack_bundle(ROOT / "enterprise-attack.json"), "enterprise-attack.json")[:1]
    ics = parse_attack_bundle(load_attack_bundle(ROOT / "ics-attack.json"), "ics-attack.json")[:1]
    csv_docs = parse_cisa_advisories(load_cisa_advisories(ROOT / "CISA_ICS_ADV_Master.csv")[:1], "CISA_ICS_ADV_Master.csv")
    csaf_docs = load_csaf_source_documents(FIXTURES)
    documents = enterprise + ics + csv_docs + csaf_docs
    chunks = DeterministicContextGenerator(cache=ContextCache()).enrich_chunks(
        ContextualChunker().chunk_documents(documents)
    )
    store.add_chunks(chunks)

    bm25 = BM25Retriever(chunks)
    vector = VectorRetriever(store)
    hybrid = HybridRetriever(vector, bm25)

    results = hybrid.retrieve("CVE-2024-41797", k=5)
    assert results
    assert any("CVE-2024-41797" in item.text for item in results)

    # Existing RRF path still returns ATT&CK content for technique queries.
    technique_results = hybrid.retrieve("initial access exploit public-facing application", k=5)
    assert technique_results


def test_discover_advisory_ids_from_master_csv_filters():
    ids = discover_advisory_ids_from_master_csv(
        ROOT / "CISA_ICS_ADV_Master.csv",
        vendor="Siemens",
        product="RUGGEDCOM",
        limit=5,
    )
    assert ids
    assert all(item.startswith(("ICSA-", "ICSMA-", "ICSALERT-")) for item in ids)
    assert len(ids) <= 5


def test_source_document_preserves_cve_metadata():
    record = parse_csaf_file(FIXTURES / "icsa-24-347-01.json")[0]
    document = cve_detail_to_source_document(record)
    assert document.metadata["kind"] == "cisa-csaf-cve"
    assert document.metadata["document_type"] == "cve_detail"
    assert document.metadata["source_type"] == "cisa_csaf"
    assert document.metadata["cve_id"] == record.cve_id
    assert document.metadata["advisory_id"] == record.advisory_id
    assert record.cve_id in document.text
    assert record.advisory_id in document.text
