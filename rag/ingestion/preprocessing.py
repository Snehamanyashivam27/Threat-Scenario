from __future__ import annotations

from rag.models.document import SourceDocument
from rag.utils.text import clean_text, stable_hash


def normalize_source_document(document: SourceDocument) -> SourceDocument:
    document.title = clean_text(document.title)
    document.text = clean_text(document.text)
    document.metadata = dict(document.metadata)
    document.metadata["normalized_hash"] = stable_hash(document.text)
    return document
