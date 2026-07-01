from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from rag.models.document import RetrievedChunk


def reciprocal_rank_fusion(ranked_lists: Sequence[Iterable[RetrievedChunk]], k: int = 60) -> list[RetrievedChunk]:
    fused_scores: dict[str, float] = defaultdict(float)
    best_item: dict[str, RetrievedChunk] = {}
    source_map: dict[str, set[str]] = defaultdict(set)

    for result_list in ranked_lists:
        for rank, item in enumerate(result_list, start=1):
            fused_scores[item.chunk_id] += 1.0 / (k + rank)
            best_item.setdefault(item.chunk_id, item)
            source_map[item.chunk_id].add(item.source)

    ranked = sorted(fused_scores.items(), key=lambda pair: pair[1], reverse=True)
    results: list[RetrievedChunk] = []
    for chunk_id, score in ranked:
        item = best_item[chunk_id]
        results.append(
            RetrievedChunk(
                chunk_id=chunk_id,
                score=score,
                source=", ".join(sorted(source_map[chunk_id])) or item.source,
                document_id=item.document_id,
                metadata=dict(item.metadata),
                text=item.text,
                contextual_text=item.contextual_text,
            )
        )
    return results
