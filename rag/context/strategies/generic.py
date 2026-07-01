from __future__ import annotations

from rag.context.strategies.base import ContextStrategy
from rag.models.document import ChunkDocument
from rag.utils.text import clean_text


class GenericContextStrategy:
    def supports(self, chunk: ChunkDocument) -> bool:
        return True

    def generate(self, chunk: ChunkDocument) -> str:
        title = clean_text(chunk.title) or clean_text(chunk.document_id)
        source = clean_text(chunk.source) or "a knowledge source"
        kind = clean_text(str(chunk.metadata.get("kind") or "document"))
        return (
            f"This chunk is from {source} and represents {kind} content about {title}. "
            f"It may be relevant when retrieving cybersecurity knowledge for threat scenario generation."
        )
