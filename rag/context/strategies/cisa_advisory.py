from __future__ import annotations

from rag.context.strategies.base import ContextStrategy
from rag.models.document import ChunkDocument
from rag.utils.text import clean_text


class CisaAdvisoryContextStrategy:
    def supports(self, chunk: ChunkDocument) -> bool:
        return str(chunk.metadata.get("kind") or "") == "cisa-ics-advisory"

    def generate(self, chunk: ChunkDocument) -> str:
        sections = dict(chunk.metadata.get("sections") or {})
        vendor = clean_text(str(sections.get("vendor") or ""))
        product = clean_text(str(sections.get("product") or ""))
        cves = clean_text(str(sections.get("cves") or ""))
        cwes = clean_text(str(sections.get("cwes") or ""))
        severity = clean_text(str(sections.get("severity") or ""))
        title = clean_text(chunk.title)

        product_phrase = self._product_phrase(vendor, product, title)
        vulnerability_phrase = self._vulnerability_phrase(cves, cwes, severity)

        return (
            f"This chunk is a CISA ICS Advisory describing vulnerabilities affecting {product_phrase}. "
            f"{vulnerability_phrase} "
            f"It may support threat scenario generation involving ICS product vulnerabilities, vendor advisories, "
            f"and operational technology security risk assessment."
        )

    @staticmethod
    def _product_phrase(vendor: str, product: str, title: str) -> str:
        if vendor and product:
            return f"{vendor} {product} products"
        if vendor:
            return f"{vendor} industrial products"
        if product:
            return f"{product} products"
        if title:
            return title
        return "industrial control system products"

    @staticmethod
    def _vulnerability_phrase(cves: str, cwes: str, severity: str) -> str:
        parts: list[str] = []
        if cves:
            parts.append("CVE identifiers")
        if cwes:
            parts.append("CWE classifications")
        if severity:
            parts.append("severity ratings")
        parts.extend(["affected versions", "mitigation information"])

        if len(parts) == 1:
            detail = parts[0]
        elif len(parts) == 2:
            detail = f"{parts[0]} and {parts[1]}"
        else:
            detail = ", ".join(parts[:-1]) + f", and {parts[-1]}"
        return f"It contains {detail} that may support threat scenario generation."
