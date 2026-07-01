from __future__ import annotations

import os
from pathlib import Path

from rag.context.cache import ContextCache
from rag.context.context_generator import ContextGenerator, DeterministicContextGenerator
from rag.embeddings.embedding_service import DeterministicEmbeddingService, EmbeddingService, OllamaEmbeddingService
from rag.generation.answer_service import DeterministicAnswerService, AnswerService, OllamaAnswerService


def create_embedding_service(use_deterministic: bool | None = None) -> EmbeddingService:
    if use_deterministic is True:
        return DeterministicEmbeddingService()
    if use_deterministic is None and os.getenv("RAG_USE_DETERMINISTIC_EMBEDDINGS") == "1":
        return DeterministicEmbeddingService()

    model = os.getenv("RAG_OLLAMA_MODEL", "nomic-embed-text")
    base_url = os.getenv("RAG_OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL")
    return OllamaEmbeddingService(model=model, base_url=base_url)


def create_answer_service(use_deterministic: bool | None = None) -> AnswerService:
    if use_deterministic is True:
        return DeterministicAnswerService()
    if use_deterministic is None and os.getenv("RAG_USE_DETERMINISTIC_ANSWERING") == "1":
        return DeterministicAnswerService()

    model = os.getenv("RAG_OLLAMA_CHAT_MODEL", "qwen2.5:14b")
    base_url = os.getenv("RAG_OLLAMA_BASE_URL") or os.getenv("OLLAMA_BASE_URL")
    return OllamaAnswerService(model=model, base_url=base_url)


def default_context_cache_path(root: str | Path | None = None) -> Path:
    if env_path := os.getenv("RAG_CONTEXT_CACHE_PATH"):
        return Path(env_path)
    base = Path(root) if root is not None else Path.cwd()
    return base / ".rag" / "context_cache" / "contexts.json"


def create_context_generator(cache_path: str | Path | None = None, root: str | Path | None = None) -> ContextGenerator:
    resolved_path = Path(cache_path) if cache_path is not None else default_context_cache_path(root)
    return DeterministicContextGenerator(cache=ContextCache(resolved_path))


def default_persist_directory(root: str | Path | None = None) -> Path:
    if env_path := os.getenv("RAG_CHROMA_PATH"):
        return Path(env_path)
    base = Path(root) if root is not None else Path.cwd()
    return base / ".rag" / "chroma"


def chroma_collection_name(embedding_service: EmbeddingService) -> str:
    return f"rag_chunks_contextual_{embedding_service.collection_suffix()}"
