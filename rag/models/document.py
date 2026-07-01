from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SourceDocument:
    document_id: str
    source: str
    title: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ChunkDocument:
    document_id: str
    chunk_id: str
    source: str
    title: str
    original_text: str
    contextual_text: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    attack_id: str | None = None
    tactic: list[str] = field(default_factory=list)
    technique: list[str] = field(default_factory=list)
    platform: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    hash: str = ""

    @property
    def text(self) -> str:
        """Backward-compatible alias; always returns original_text."""
        return self.original_text

    def embedding_text(self) -> str:
        if not self.contextual_text:
            return self.original_text
        return f"{self.contextual_text}\n\n{self.original_text}"


@dataclass(slots=True)
class RetrievedChunk:
    chunk_id: str
    score: float
    source: str
    document_id: str
    metadata: dict[str, Any]
    text: str
    contextual_text: str = ""
