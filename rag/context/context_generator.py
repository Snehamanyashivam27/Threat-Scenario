from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace
from typing import Iterable

from rag.context.cache import ContextCache
from rag.context.strategies import (
    CisaAdvisoryContextStrategy,
    CisaCsafCveContextStrategy,
    EnterpriseAttackContextStrategy,
    GenericContextStrategy,
    IcsAttackContextStrategy,
)
from rag.context.strategies.base import ContextStrategy
from rag.models.document import ChunkDocument
from rag.utils.progress import report_progress


class ContextGenerator(ABC):
    @abstractmethod
    def enrich_chunk(self, chunk: ChunkDocument) -> ChunkDocument:
        raise NotImplementedError

    def enrich_chunks(self, chunks: Iterable[ChunkDocument]) -> list[ChunkDocument]:
        return [self.enrich_chunk(chunk) for chunk in chunks]


class DeterministicContextGenerator(ContextGenerator):
    def __init__(self, cache: ContextCache | None = None, strategies: list[ContextStrategy] | None = None):
        self.cache = cache or ContextCache()
        self.strategies = strategies or [
            EnterpriseAttackContextStrategy(),
            IcsAttackContextStrategy(),
            CisaCsafCveContextStrategy(),
            CisaAdvisoryContextStrategy(),
            GenericContextStrategy(),
        ]

    def enrich_chunk(self, chunk: ChunkDocument, *, persist: bool = True) -> ChunkDocument:
        content_hash = chunk.hash
        if self.cache is not None:
            cached = self.cache.get(chunk.chunk_id, content_hash)
            if cached is not None:
                return replace(chunk, contextual_text=cached)

        contextual_text = self._generate_context(chunk)
        if self.cache is not None:
            self.cache.set(chunk.chunk_id, content_hash, contextual_text, persist=persist)
        return replace(chunk, contextual_text=contextual_text)

    def enrich_chunks(self, chunks: Iterable[ChunkDocument]) -> list[ChunkDocument]:
        items = list(chunks)
        total = len(items)
        report_progress("Adding context prefixes", 0, total)
        enriched: list[ChunkDocument] = []
        for index, chunk in enumerate(items, start=1):
            enriched.append(self.enrich_chunk(chunk, persist=False))
            if index == total or index % max(1, total // 20) == 0:
                if self.cache is not None:
                    self.cache.flush()
            report_progress("Adding context prefixes", index, total)
        if self.cache is not None:
            self.cache.flush()
        return enriched

    def _generate_context(self, chunk: ChunkDocument) -> str:
        for strategy in self.strategies:
            if strategy.supports(chunk):
                return strategy.generate(chunk)
        return GenericContextStrategy().generate(chunk)
