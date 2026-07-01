from __future__ import annotations

from rag.models.document import RetrievedChunk
from rag.vectorstore.chroma_store import ChromaStore


class VectorRetriever:
    def __init__(self, store: ChromaStore):
        self.store = store

    def retrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        return self.store.similarity_search(query, k=k)
