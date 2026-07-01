from __future__ import annotations

from typing import Iterable

from rag.models.document import ChunkDocument, SourceDocument
from rag.utils.text import clean_text, stable_hash


class ContextualChunker:
    def chunk_documents(self, documents: Iterable[SourceDocument]) -> list[ChunkDocument]:
        chunks: list[ChunkDocument] = []
        for document in documents:
            chunks.extend(self.chunk_document(document))
        return chunks

    def chunk_document(self, document: SourceDocument) -> list[ChunkDocument]:
        kind = str(document.metadata.get("kind") or "")
        if kind == "attack-pattern":
            return [self._chunk_attack_pattern(document)]
        if kind == "cisa-ics-advisory":
            return [self._chunk_cisa_advisory(document)]
        return [self._chunk_generic(document)]

    def _chunk_attack_pattern(self, document: SourceDocument) -> ChunkDocument:
        sections = dict(document.metadata.get("sections") or {})
        ordered_sections = [
            ("Technique Name", document.title),
            ("ATT&CK ID", document.metadata.get("attack_id") or ""),
            ("Tactic", "; ".join(document.metadata.get("tactic") or [])),
            ("Platforms", "; ".join(document.metadata.get("platform") or [])),
            ("Description", sections.get("description") or document.text),
            ("Detection", sections.get("detection") or "Not available in source data"),
            ("Mitigations", sections.get("mitigations") or ""),
            ("Procedures", sections.get("procedures") or ""),
            ("Related Groups", sections.get("related_groups") or ""),
            ("Related Software", sections.get("related_software") or ""),
        ]
        text = self._format_sections(ordered_sections)
        references = [self._extract_reference_url(reference) for reference in document.metadata.get("external_references") or []]
        return ChunkDocument(
            document_id=document.document_id,
            chunk_id=f"{document.document_id}::chunk-1",
            source=document.source,
            title=document.title,
            original_text=text,
            metadata={"kind": "attack-pattern", **document.metadata},
            attack_id=document.metadata.get("attack_id"),
            tactic=list(document.metadata.get("tactic") or []),
            platform=list(document.metadata.get("platform") or []),
            references=[reference for reference in references if reference],
            hash=stable_hash(text),
        )

    def _chunk_cisa_advisory(self, document: SourceDocument) -> ChunkDocument:
        sections = dict(document.metadata.get("sections") or {})
        ordered_sections = [
            ("Advisory", document.title),
            ("Identifier", sections.get("advisory_id") or document.document_id),
            ("Vendor", sections.get("vendor") or ""),
            ("Product", sections.get("product") or ""),
            ("Affected Products", sections.get("products_affected") or ""),
            ("CVE", sections.get("cves") or ""),
            ("CWE", sections.get("cwes") or ""),
            ("Severity", sections.get("severity") or ""),
            ("Sector", sections.get("sector") or ""),
        ]
        text = self._format_sections(ordered_sections)
        return ChunkDocument(
            document_id=document.document_id,
            chunk_id=f"{document.document_id}::chunk-1",
            source=document.source,
            title=document.title,
            original_text=text,
            metadata={"kind": "cisa-ics-advisory", **document.metadata},
            hash=stable_hash(text),
        )

    def _chunk_generic(self, document: SourceDocument) -> ChunkDocument:
        text = clean_text(document.text)
        return ChunkDocument(
            document_id=document.document_id,
            chunk_id=f"{document.document_id}::chunk-1",
            source=document.source,
            title=document.title,
            original_text=text,
            metadata=dict(document.metadata),
            hash=stable_hash(text),
        )

    @staticmethod
    def _format_sections(sections: list[tuple[str, str]]) -> str:
        rendered = [f"{heading}: {clean_text(content)}" for heading, content in sections if clean_text(content)]
        return clean_text("\n".join(rendered))

    @staticmethod
    def _extract_reference_url(reference: dict[str, str]) -> str | None:
        return reference.get("url")
