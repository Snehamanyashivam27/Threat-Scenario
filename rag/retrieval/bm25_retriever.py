from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

from rag.models.document import ChunkDocument, RetrievedChunk


class BM25Retriever:
    def __init__(self, chunks: Iterable[ChunkDocument], k1: float = 1.5, b: float = 0.75):
        self.chunks = list(chunks)
        self.k1 = k1
        self.b = b
        self.tokenized_chunks = [self._tokenize(chunk.original_text) for chunk in self.chunks]
        self.document_lengths = [len(tokens) for tokens in self.tokenized_chunks]
        self.average_document_length = sum(self.document_lengths) / len(self.document_lengths) if self.document_lengths else 0.0
        self.document_frequencies = Counter()
        for tokens in self.tokenized_chunks:
            for token in set(tokens):
                self.document_frequencies[token] += 1

    def retrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        if not self.chunks:
            return []
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        scored = [(self._score(query_tokens, index), chunk) for index, chunk in enumerate(self.chunks)]
        scored = [(score, chunk) for score, chunk in scored if score > 0.0]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [self._to_hit(chunk, score) for score, chunk in scored[:k]]

    def _score(self, query_tokens: list[str], document_index: int) -> float:
        document_tokens = self.tokenized_chunks[document_index]
        if not query_tokens or not document_tokens:
            return 0.0
        term_frequencies = Counter(document_tokens)
        document_length = len(document_tokens)
        score = 0.0
        for token in query_tokens:
            frequency = term_frequencies.get(token, 0)
            if not frequency:
                continue
            document_frequency = self.document_frequencies.get(token, 0)
            idf = math.log(1 + (len(self.chunks) - document_frequency + 0.5) / (document_frequency + 0.5))
            numerator = frequency * (self.k1 + 1)
            denominator = frequency + self.k1 * (1 - self.b + self.b * (document_length / (self.average_document_length or 1.0)))
            score += idf * (numerator / denominator)
        return score

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9]+", text.lower())

    @staticmethod
    def _to_hit(chunk: ChunkDocument, score: float) -> RetrievedChunk:
        return RetrievedChunk(
            chunk_id=chunk.chunk_id,
            score=score,
            source=chunk.source,
            document_id=chunk.document_id,
            metadata=dict(chunk.metadata),
            text=chunk.original_text,
            contextual_text=chunk.contextual_text,
        )
