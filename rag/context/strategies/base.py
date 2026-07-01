from __future__ import annotations

from typing import Protocol

from rag.models.document import ChunkDocument


class ContextStrategy(Protocol):
    def supports(self, chunk: ChunkDocument) -> bool:
        ...

    def generate(self, chunk: ChunkDocument) -> str:
        ...
