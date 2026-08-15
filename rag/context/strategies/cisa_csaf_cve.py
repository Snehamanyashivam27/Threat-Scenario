from __future__ import annotations

from rag.context.strategies.base import ContextStrategy
from rag.models.document import ChunkDocument
from rag.utils.text import clean_text


class CisaCsafCveContextStrategy:
    def supports(self, chunk: ChunkDocument) -> bool:
        return str(chunk.metadata.get("kind") or "") == "cisa-csaf-cve"

    def generate(self, chunk: ChunkDocument) -> str:
        sections = dict(chunk.metadata.get("sections") or {})
        cve_id = clean_text(str(sections.get("cve_id") or chunk.metadata.get("cve_id") or ""))
        vendor = clean_text(str(sections.get("vendor") or chunk.metadata.get("vendor") or ""))
        product = clean_text(str(sections.get("product") or chunk.metadata.get("product") or ""))
        cwes = clean_text(str(sections.get("cwes") or ""))
        severity = clean_text(str(sections.get("severity") or ""))
        product_phrase = f"{vendor} {product}".strip() or "an industrial product"
        detail_parts = [part for part in [cve_id, cwes, severity] if part]
        detail = ", ".join(detail_parts) if detail_parts else "detailed vulnerability evidence"
        return (
            f"This chunk is a CISA CSAF per-CVE vulnerability record for {product_phrase}. "
            f"It provides {detail}, including affected versions, prerequisites, and technical effects when present. "
            f"It may support exact CVE lookup and attack-step enablement validation."
        )
