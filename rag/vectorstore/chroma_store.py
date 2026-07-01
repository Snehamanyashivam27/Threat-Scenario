from __future__ import annotations

import json
import os
from math import sqrt
from pathlib import Path
from typing import Any, Iterable

from rag.embeddings.embedding_service import EmbeddingService
from rag.models.document import ChunkDocument, RetrievedChunk


class ChromaStore:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        persist_directory: str | Path | None = None,
        collection_name: str = "rag_chunks_contextual",
    ):
        self.embedding_service = embedding_service
        self.persist_directory = Path(persist_directory) if persist_directory else None
        self.collection_name = collection_name
        self._backend = "memory"
        self._records: list[ChunkDocument] = []
        self._embeddings: list[list[float]] = []
        self._collection = None

        try:
            import chromadb
        except ImportError:
            if self.persist_directory is not None:
                raise RuntimeError("chromadb is required for persistent storage")
            return

        self._backend = "chroma"
        if self.persist_directory:
            self.persist_directory.mkdir(parents=True, exist_ok=True)
        if self.persist_directory:
            self._client = chromadb.PersistentClient(path=str(self.persist_directory))
        else:
            self._client = chromadb.EphemeralClient()
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"embedding_dimension": str(embedding_service.embedding_dimension())},
        )

    def has_indexed_chunks(self) -> bool:
        return self.chunk_count() > 0

    def chunk_count(self) -> int:
        if self._backend == "chroma" and self._collection is not None:
            return self._collection.count()
        return len(self._records)

    def add_chunks(self, chunks: Iterable[ChunkDocument]) -> None:
        chunk_list = list(chunks)
        if not chunk_list:
            return

        batch_size = int(os.getenv("RAG_INDEX_BATCH_SIZE", "32"))
        if self._backend == "chroma" and self._collection is not None:
            for start in range(0, len(chunk_list), batch_size):
                batch = chunk_list[start : start + batch_size]
                embeddings = self.embedding_service.embed_documents([chunk.embedding_text() for chunk in batch])
                self._collection.upsert(
                    ids=[chunk.chunk_id for chunk in batch],
                    documents=[chunk.original_text for chunk in batch],
                    metadatas=[self._serialize_metadata(chunk) for chunk in batch],
                    embeddings=embeddings,
                )
            self._ensure_collection_metadata()
            self._persist_if_supported()
            return

        embeddings = self.embedding_service.embed_documents([chunk.embedding_text() for chunk in chunk_list])
        self._records.extend(chunk_list)
        self._embeddings.extend(embeddings)

    def similarity_search(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        if self._backend == "chroma" and self._collection is not None:
            return self._chroma_similarity_search(query, k)
        return self._memory_similarity_search(query, k)

    def _memory_similarity_search(self, query: str, k: int) -> list[RetrievedChunk]:
        if not self._records:
            return []
        query_vector = self.embedding_service.embed_query(query)
        scored = [
            (self._cosine_similarity(query_vector, embedding), chunk)
            for chunk, embedding in zip(self._records, self._embeddings, strict=False)
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [self._to_retrieved_chunk(chunk, score) for score, chunk in scored[:k]]

    def _chroma_similarity_search(self, query: str, k: int) -> list[RetrievedChunk]:
        query_embedding = self.embedding_service.embed_query(query)
        self._validate_query_dimension(query_embedding)
        response = self._collection.query(query_embeddings=[query_embedding], n_results=k, include=["documents", "metadatas", "distances"])
        results: list[RetrievedChunk] = []
        ids = response.get("ids", [[]])[0]
        documents = response.get("documents", [[]])[0]
        metadatas = response.get("metadatas", [[]])[0]
        distances = response.get("distances", [[]])[0]
        for chunk_id, text, metadata, distance in zip(ids, documents, metadatas, distances, strict=False):
            metadata = metadata or {}
            score = 1.0 / (1.0 + float(distance))
            original_text = str(metadata.get("original_text") or text or "")
            contextual_text = str(metadata.get("contextual_text") or "")
            results.append(
                RetrievedChunk(
                    chunk_id=str(chunk_id),
                    score=score,
                    source=str(metadata.get("source") or metadata.get("source_type") or "chroma"),
                    document_id=str(metadata.get("document_id") or chunk_id),
                    metadata=dict(metadata),
                    text=original_text,
                    contextual_text=contextual_text,
                )
            )
        return results

    def _to_retrieved_chunk(self, chunk: ChunkDocument, score: float) -> RetrievedChunk:
        return RetrievedChunk(
            chunk_id=chunk.chunk_id,
            score=score,
            source=chunk.source,
            document_id=chunk.document_id,
            metadata=self._serialize_metadata(chunk),
            text=chunk.original_text,
            contextual_text=chunk.contextual_text,
        )

    @staticmethod
    def _serialize_metadata(chunk: ChunkDocument) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source": chunk.source,
            "document_id": chunk.document_id,
            "chunk_id": chunk.chunk_id,
            "title": chunk.title,
            "attack_id": chunk.attack_id or "",
            "hash": chunk.hash,
            "original_text": chunk.original_text,
            "contextual_text": chunk.contextual_text,
            "tactic": ", ".join(chunk.tactic),
            "technique": ", ".join(chunk.technique),
            "platform": ", ".join(chunk.platform),
            "references": ", ".join(chunk.references),
        }
        for key, value in chunk.metadata.items():
            if key == "sections":
                metadata["sections_json"] = json.dumps(value, sort_keys=True)
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                metadata[f"meta_{key}"] = value if value is not None else ""
            else:
                metadata[f"meta_{key}_json"] = json.dumps(value, sort_keys=True)
        return metadata

    def _persist_if_supported(self) -> None:
        persist = getattr(self._client, "persist", None)
        if callable(persist):
            persist()

    def _ensure_collection_metadata(self) -> None:
        if self._collection is None:
            return
        expected = str(self.embedding_service.embedding_dimension())
        current = (self._collection.metadata or {}).get("embedding_dimension")
        if current != expected:
            self._collection.modify(metadata={"embedding_dimension": expected})

    def _validate_query_dimension(self, query_embedding: list[float]) -> None:
        if self._collection is None:
            return
        metadata = self._collection.metadata or {}
        stored = metadata.get("embedding_dimension")
        if stored is None:
            return
        expected = int(stored)
        actual = len(query_embedding)
        if expected != actual:
            raise RuntimeError(
                f"Embedding dimension mismatch for collection '{self.collection_name}': "
                f"index expects {expected}, current embedding service produces {actual}. "
                f"Rebuild with --reindex after switching between --deterministic and Ollama modes."
            )

    @staticmethod
    def _cosine_similarity(left: list[float], right: list[float]) -> float:
        if not left or not right:
            return 0.0
        numerator = sum(l * r for l, r in zip(left, right, strict=False))
        left_norm = sqrt(sum(value * value for value in left)) or 1.0
        right_norm = sqrt(sum(value * value for value in right)) or 1.0
        return numerator / (left_norm * right_norm)
