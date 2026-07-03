from __future__ import annotations

"""Stable ranking helpers for deterministic hybrid retrieval."""

from rag.models.document import RetrievedChunk


def score_chunk_id_key(score: float, chunk_id: str) -> tuple[float, str]:
    # Negated score enables descending sort; chunk_id breaks ties deterministically.
    return (-float(score), str(chunk_id))


def sort_by_score_chunk_id(items: list[RetrievedChunk]) -> list[RetrievedChunk]:
    return sorted(items, key=lambda item: score_chunk_id_key(item.score, item.chunk_id))


def sort_scored_pairs(pairs: list[tuple[float, RetrievedChunk]]) -> list[tuple[float, RetrievedChunk]]:
    return sorted(pairs, key=lambda pair: score_chunk_id_key(pair[0], pair[1].chunk_id))
