from __future__ import annotations

from pathlib import Path

from rag.chunking.contextual_chunker import ContextualChunker
from rag.context.context_generator import ContextGenerator
from rag.embeddings.embedding_service import EmbeddingService
from rag.ingestion.csaf.documents import load_csaf_source_documents
from rag.ingestion.loaders import load_attack_bundle, load_cisa_advisories
from rag.ingestion.parser import parse_attack_bundle, parse_cisa_advisories
from rag.ingestion.preprocessing import normalize_source_document
from rag.models.document import ChunkDocument
from rag.runtime import create_context_generator, chroma_collection_name
from rag.vectorstore.chroma_store import ChromaStore


class KnowledgeBasePipeline:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        persist_directory: str | Path | None = None,
        context_generator: ContextGenerator | None = None,
        collection_name: str | None = None,
    ):
        self.embedding_service = embedding_service
        resolved_collection = collection_name or chroma_collection_name(embedding_service)
        self.store = ChromaStore(
            embedding_service=embedding_service,
            persist_directory=persist_directory,
            collection_name=resolved_collection,
        )
        self.chunker = ContextualChunker()
        self.context_generator = context_generator or create_context_generator()

    def build_chunks(
        self,
        enterprise_attack_path: str | Path,
        ics_attack_path: str | Path,
        advisories_path: str | Path,
        csaf_dir: str | Path | None = None,
    ) -> list[ChunkDocument]:
        documents = []
        documents.extend(parse_attack_bundle(load_attack_bundle(enterprise_attack_path), source_name="enterprise-attack.json"))
        documents.extend(parse_attack_bundle(load_attack_bundle(ics_attack_path), source_name="ics-attack.json"))
        documents.extend(parse_cisa_advisories(load_cisa_advisories(advisories_path), source_name="CISA_ICS_ADV_Master.csv"))

        # CSAF per-CVE details enrich the KB; they do not replace CSV advisory documents.
        resolved_csaf_dir = Path(csaf_dir) if csaf_dir is not None else Path(advisories_path).resolve().parent / "data" / "cisa_csaf"
        if resolved_csaf_dir.exists():
            documents.extend(load_csaf_source_documents(resolved_csaf_dir))

        normalized = [normalize_source_document(document) for document in documents]
        raw_chunks = self.chunker.chunk_documents(normalized)
        return self.context_generator.enrich_chunks(raw_chunks)

    def index(self, chunks: list[ChunkDocument]) -> None:
        self.store.add_chunks(chunks)
