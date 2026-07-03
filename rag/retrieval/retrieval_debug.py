from __future__ import annotations

import os
from typing import Iterable

from rag.models.document import RetrievedChunk


def is_retrieval_debug_enabled() -> bool:
    return os.getenv("RAG_DEBUG_RETRIEVAL", "").lower() in {"1", "true", "yes"} or os.getenv("DEBUG", "").lower() == "true"


def log_stage(title: str, **fields: object) -> None:
    if not is_retrieval_debug_enabled():
        return
    parts = [f"[RAG retrieval] {title}"]
    for key, value in fields.items():
        parts.append(f"  {key}: {value}")
    print("\n".join(parts), flush=True)


def log_ranked_chunks(title: str, results: Iterable[RetrievedChunk], limit: int = 5) -> None:
    if not is_retrieval_debug_enabled():
        return
    print(f"\n[RAG retrieval] {title}", flush=True)
    items = list(results)
    if not items:
        print("  (no results)", flush=True)
        return
    for index, item in enumerate(items[:limit], start=1):
        attack_id = item.metadata.get("attack_id") or item.metadata.get("meta_attack_id") or ""
        print(
            f"  rank={index} score={item.score:.4f} doc={item.document_id} "
            f"attack_id={attack_id or '-'} source={item.source}",
            flush=True,
        )
