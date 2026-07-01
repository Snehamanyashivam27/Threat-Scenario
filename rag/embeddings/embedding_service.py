from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from hashlib import blake2b
from math import sqrt
from typing import Iterable


class EmbeddingService(ABC):
    @abstractmethod
    def embed_documents(self, texts: Iterable[str]) -> list[list[float]]:
        raise NotImplementedError

    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        raise NotImplementedError

    @abstractmethod
    def embedding_dimension(self) -> int:
        raise NotImplementedError

    def collection_suffix(self) -> str:
        return f"dim{self.embedding_dimension()}"


class OllamaEmbeddingService(EmbeddingService):
    KNOWN_MODEL_DIMENSIONS = {
        "nomic-embed-text": 768,
        "mxbai-embed-large": 1024,
    }

    def __init__(
        self,
        model: str = "nomic-embed-text",
        base_url: str | None = None,
        batch_size: int | None = None,
        max_retries: int = 3,
    ):
        self.model = model
        self.base_url = base_url
        self.batch_size = batch_size or int(os.getenv("RAG_OLLAMA_EMBED_BATCH_SIZE", "16"))
        self.max_retries = max_retries
        self._client_instance = None
        self._cached_dimension: int | None = None

    def collection_suffix(self) -> str:
        slug = self.model.replace(":", "-").replace(".", "-").lower()
        return f"ollama-{slug}"

    def embedding_dimension(self) -> int:
        if self._cached_dimension is not None:
            return self._cached_dimension
        for key, dimension in self.KNOWN_MODEL_DIMENSIONS.items():
            if key in self.model:
                self._cached_dimension = dimension
                return dimension
        self._cached_dimension = len(self.embed_query("dimension probe"))
        return self._cached_dimension

    def _client(self):
        if self._client_instance is not None:
            return self._client_instance
        try:
            from langchain_ollama import OllamaEmbeddings
        except ImportError as error:  # pragma: no cover
            raise RuntimeError("langchain-ollama is required for Ollama embeddings") from error
        kwargs = {"model": self.model}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client_instance = OllamaEmbeddings(**kwargs)
        return self._client_instance

    def embed_documents(self, texts: Iterable[str]) -> list[list[float]]:
        text_list = list(texts)
        if not text_list:
            return []

        client = self._client()
        embeddings: list[list[float]] = []
        for start in range(0, len(text_list), self.batch_size):
            batch = text_list[start : start + self.batch_size]
            embeddings.extend(self._embed_batch_with_retry(client, batch))
        return embeddings

    def embed_query(self, text: str) -> list[float]:
        return self._embed_batch_with_retry(self._client(), [text])[0]

    def _embed_batch_with_retry(self, client, batch: list[str]) -> list[list[float]]:
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                return client.embed_documents(batch)
            except Exception as error:  # pragma: no cover - exercised against live Ollama
                last_error = error
                if attempt + 1 >= self.max_retries:
                    break
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(
            f"Ollama embedding failed after {self.max_retries} attempts for batch size {len(batch)}"
        ) from last_error


class DeterministicEmbeddingService(EmbeddingService):
    def __init__(self, dimensions: int = 32):
        self.dimensions = dimensions

    def collection_suffix(self) -> str:
        return f"det{self.dimensions}"

    def embedding_dimension(self) -> int:
        return self.dimensions

    def embed_documents(self, texts: Iterable[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vector(text)

    def _vector(self, text: str) -> list[float]:
        buckets = [0.0] * self.dimensions
        tokens = [token for token in text.lower().split() if token]
        if not tokens:
            return buckets
        for token in tokens:
            digest = blake2b(token.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            weight = (int.from_bytes(digest[4:], "big") % 1000) / 1000.0 + 1.0
            buckets[index] += weight
        norm = sqrt(sum(value * value for value in buckets)) or 1.0
        return [value / norm for value in buckets]
