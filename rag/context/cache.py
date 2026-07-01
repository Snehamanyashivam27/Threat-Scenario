from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CachedContextEntry:
    chunk_id: str
    content_hash: str
    contextual_text: str


class ContextCache:
    def __init__(self, cache_path: str | Path | None = None):
        self.cache_path = Path(cache_path) if cache_path else None
        self._entries: dict[str, CachedContextEntry] = {}
        if self.cache_path and self.cache_path.exists():
            self._load()

    def get(self, chunk_id: str, content_hash: str) -> str | None:
        entry = self._entries.get(chunk_id)
        if entry is None or entry.content_hash != content_hash:
            return None
        return entry.contextual_text

    def set(self, chunk_id: str, content_hash: str, contextual_text: str) -> None:
        self._entries[chunk_id] = CachedContextEntry(
            chunk_id=chunk_id,
            content_hash=content_hash,
            contextual_text=contextual_text,
        )
        self._persist()

    def _load(self) -> None:
        if self.cache_path is None or not self.cache_path.exists():
            return
        payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        for chunk_id, entry in payload.items():
            self._entries[chunk_id] = CachedContextEntry(
                chunk_id=str(entry.get("chunk_id") or chunk_id),
                content_hash=str(entry.get("content_hash") or ""),
                contextual_text=str(entry.get("contextual_text") or ""),
            )

    def _persist(self) -> None:
        if self.cache_path is None:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, dict[str, Any]] = {
            chunk_id: {
                "chunk_id": entry.chunk_id,
                "content_hash": entry.content_hash,
                "contextual_text": entry.contextual_text,
            }
            for chunk_id, entry in self._entries.items()
        }
        self.cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
