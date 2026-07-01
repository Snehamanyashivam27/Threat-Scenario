from __future__ import annotations

import pytest

from rag.embeddings.embedding_service import OllamaEmbeddingService


class FakeOllamaClient:
    def __init__(self):
        self.calls: list[list[str]] = []

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        return [[float(index), 1.0] for index in range(len(texts))]


from rag.embeddings.embedding_service import DeterministicEmbeddingService, OllamaEmbeddingService
from rag.runtime import chroma_collection_name


def test_chroma_collection_name_separates_embedding_backends():
    assert chroma_collection_name(DeterministicEmbeddingService()) == "rag_chunks_contextual_det32"
    assert chroma_collection_name(OllamaEmbeddingService(model="nomic-embed-text")) == "rag_chunks_contextual_ollama-nomic-embed-text"


def test_ollama_embedding_service_batches_requests(monkeypatch):
    service = OllamaEmbeddingService(batch_size=2, max_retries=1)
    fake_client = FakeOllamaClient()
    monkeypatch.setattr(service, "_client", lambda: fake_client)

    embeddings = service.embed_documents(["a", "b", "c", "d", "e"])

    assert len(embeddings) == 5
    assert fake_client.calls == [["a", "b"], ["c", "d"], ["e"]]


def test_ollama_embedding_service_retries_failed_batches(monkeypatch):
    service = OllamaEmbeddingService(batch_size=2, max_retries=3)

    class FlakyClient:
        def __init__(self):
            self.attempts = 0

        def embed_documents(self, texts: list[str]) -> list[list[float]]:
            self.attempts += 1
            if self.attempts < 2:
                raise RuntimeError("runner unavailable")
            return [[1.0, 0.0] for _ in texts]

    flaky = FlakyClient()
    monkeypatch.setattr(service, "_client", lambda: flaky)
    monkeypatch.setattr("rag.embeddings.embedding_service.time.sleep", lambda _seconds: None)

    embeddings = service.embed_documents(["only-batch"])

    assert embeddings == [[1.0, 0.0]]
    assert flaky.attempts == 2


def test_ollama_embedding_service_raises_after_exhausted_retries(monkeypatch):
    service = OllamaEmbeddingService(batch_size=1, max_retries=2)

    class FailingClient:
        def embed_documents(self, texts: list[str]) -> list[list[float]]:
            raise RuntimeError("runner unavailable")

    monkeypatch.setattr(service, "_client", lambda: FailingClient())
    monkeypatch.setattr("rag.embeddings.embedding_service.time.sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="Ollama embedding failed"):
        service.embed_documents(["x"])
