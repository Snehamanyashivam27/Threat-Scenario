from __future__ import annotations

import re
import json
from typing import Iterable

from rag.models.answer import SourceReference
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ATTACK_INTENTS, QueryIntent, detect_query_intent, extract_attack_id, extract_fields, extract_title, source_group_for
from rag.utils.text import strip_markdown_links


class ContextBuilder:
    ADVISORY_INTENTS = {"cve_lookup", "vendor_lookup", "advisory_lookup", "threat_scenario_query"}
    ADVISORY_RENDER_FIELDS = (
        ("Advisory", "advisory"),
        ("Identifier", "identifier"),
        ("Vendor", "vendor"),
        ("Product", "product"),
        ("Product Family", "product_family"),
        ("Model", "model"),
        ("Part Number", "part_number"),
        ("Affected Versions", "affected_versions"),
        ("Severity", "severity"),
        ("CVE", "cve"),
        ("CWE", "cwe"),
        ("Affected Products", "affected_products"),
        ("Prerequisites", "prerequisites"),
        ("Effect", "effect"),
        ("Description", "advisory_description"),
        ("Sector", "sector"),
    )

    def build(self, chunks: Iterable[RetrievedChunk], query: str = "") -> str:
        grouped = self._group_selected_chunks(chunks)
        intent = detect_query_intent(query).value
        sections: list[str] = []

        enterprise = grouped.get("enterprise", [])
        ics = grouped.get("ics", [])
        advisories = grouped.get("cisa", [])

        if enterprise:
            sections.append(self._render_attack_framework("Enterprise ATT&CK", enterprise, query=query))
        if ics:
            sections.append(self._render_attack_framework("ICS ATT&CK", ics, query=query))

        include_advisories = intent in self.ADVISORY_INTENTS or (not enterprise and not ics and advisories)
        if include_advisories and advisories:
            sections.append(self._render_advisories(advisories))

        if grouped.get("other"):
            sections.append(self._render_other(grouped["other"]))

        return "\n\n".join(section for section in sections if section.strip())

    def build_sources(self, chunks: Iterable[RetrievedChunk]) -> list[SourceReference]:
        # Sources mirror the exact documents rendered into the LLM context, in the same order.
        grouped = self._group_selected_chunks(chunks)
        sources: list[SourceReference] = []
        seen: set[tuple[str, str]] = set()

        for group, label in (("enterprise", "Enterprise ATT&CK"), ("ics", "ICS ATT&CK")):
            for item in grouped.get(group, []):
                attack_id = item.get("attack_id", "")
                key = (label, attack_id)
                if key in seen:
                    continue
                seen.add(key)
                sources.append(SourceReference(attack_id=attack_id, document_source=label))

        for item in grouped.get("cisa", []):
            identifier = item.get("identifier") or item.get("advisory") or ""
            key = ("CISA ICS Advisory", identifier)
            if key in seen:
                continue
            seen.add(key)
            sources.append(SourceReference(attack_id=identifier, document_source="CISA ICS Advisory"))

        for item in grouped.get("other", []):
            label = item.get("framework") or item.get("source") or "Other"
            attack_id = item.get("attack_id", "")
            key = (label, attack_id)
            if key in seen:
                continue
            seen.add(key)
            sources.append(SourceReference(attack_id=attack_id, document_source=label))

        return sources

    def _group_selected_chunks(self, chunks: Iterable[RetrievedChunk]) -> dict[str, list[dict[str, str]]]:
        grouped: dict[str, list[dict[str, str]]] = {"enterprise": [], "ics": [], "cisa": [], "other": []}
        seen_titles: dict[str, set[str]] = {"enterprise": set(), "ics": set()}

        for chunk in chunks:
            item = self._compact_chunk(chunk)
            group = item["group"]
            if group in {"enterprise", "ics"}:
                title_key = normalize_key(item["title"])
                if title_key in seen_titles[group]:
                    for index, existing in enumerate(grouped[group]):
                        if normalize_key(existing["title"]) != title_key:
                            continue
                        if not existing.get("attack_id") and item.get("attack_id"):
                            grouped[group][index] = item
                        break
                    continue
                seen_titles[group].add(title_key)
            grouped[group].append(item)
        return grouped

    @classmethod
    def _compact_chunk(cls, chunk: RetrievedChunk) -> dict[str, str]:
        group = source_group_for(chunk)
        fields = extract_fields(chunk.text)
        attack_id = extract_attack_id(chunk)
        title = extract_title(chunk)
        item: dict[str, str] = {
            "group": group,
            "framework": cls._framework_label(chunk.source, group),
            "source": chunk.source,
            "attack_id": attack_id,
            "title": title,
            "tactic": cls._format_tactic_list(fields.get("Tactic") or ""),
            "platforms": cls._compact_list(fields.get("Platforms") or fields.get("Platform") or ""),
            "description": cls._clean_summary(fields.get("Description") or "", sentence_limit=2),
            "detection": cls._clean_summary(fields.get("Detection") or "", sentence_limit=1),
            "mitigations": cls._clean_summary(fields.get("Mitigations") or "", sentence_limit=1),
        }
        if group == "cisa":
            item.update(cls._compact_advisory_fields(chunk, fields, title))
        return item

    @classmethod
    def _compact_advisory_fields(cls, chunk: RetrievedChunk, fields: dict[str, str], title: str) -> dict[str, str]:
        sections = cls._advisory_sections(chunk)
        return {
            "advisory": cls._advisory_field(fields.get("Advisory") or title or sections.get("title") or ""),
            "identifier": cls._advisory_field(fields.get("Identifier") or sections.get("advisory_id") or chunk.document_id or ""),
            "vendor": cls._advisory_field(fields.get("Vendor") or sections.get("vendor") or ""),
            "product": cls._advisory_field(fields.get("Product") or sections.get("product") or ""),
            "product_family": cls._advisory_field(
                fields.get("Product Family") or sections.get("product_family") or ""
            ),
            "model": cls._advisory_field(fields.get("Model") or sections.get("model") or ""),
            "part_number": cls._advisory_field(
                fields.get("Part Number") or sections.get("part_number") or ""
            ),
            "affected_versions": cls._advisory_field(
                fields.get("Affected Versions") or sections.get("affected_versions") or "",
                max_chars=1200,
            ),
            "severity": cls._advisory_field(fields.get("Severity") or sections.get("severity") or ""),
            "cve": cls._advisory_field(fields.get("CVE") or sections.get("cves") or "", max_chars=2000),
            "cwe": cls._advisory_field(fields.get("CWE") or sections.get("cwes") or "", max_chars=2000),
            "affected_products": cls._advisory_field(
                fields.get("Affected Products")
                or sections.get("affected_products")
                or sections.get("products_affected")
                or "",
                max_chars=1200,
            ),
            "prerequisites": cls._advisory_field(
                fields.get("Prerequisites") or sections.get("prerequisites") or "",
                max_chars=1200,
            ),
            "effect": cls._advisory_field(
                fields.get("Effect") or sections.get("effects") or "",
                max_chars=1200,
            ),
            "advisory_description": cls._advisory_field(
                fields.get("Description") or sections.get("description") or "",
                max_chars=1600,
            ),
            "sector": cls._advisory_field(fields.get("Sector") or sections.get("sector") or ""),
        }

    @staticmethod
    def _advisory_sections(chunk: RetrievedChunk) -> dict[str, str]:
        sections = chunk.metadata.get("sections")
        if isinstance(sections, dict):
            return {str(key): str(value) for key, value in sections.items() if value}
        sections_json = chunk.metadata.get("sections_json") or chunk.metadata.get("meta_sections_json")
        if not sections_json:
            return {}
        try:
            parsed = json.loads(str(sections_json))
        except json.JSONDecodeError:
            return {}
        return {str(key): str(value) for key, value in parsed.items() if value} if isinstance(parsed, dict) else {}

    @classmethod
    def _render_attack_framework(cls, heading: str, items: list[dict[str, str]], query: str = "") -> str:
        include_operational_fields = detect_query_intent(query) in {
            QueryIntent.THREAT_SCENARIO_QUERY,
            QueryIntent.GENERAL_SECURITY_QUESTION,
        }
        lines = [heading]
        for item in items:
            technique = item["title"] or item["attack_id"] or "Unknown technique"
            if item["attack_id"]:
                technique = f"{technique} ({item['attack_id']})"
            lines.append(f"Technique: {technique}")
            if item["tactic"]:
                lines.append(f"Tactic: {item['tactic']}")
            if item["description"]:
                lines.append(f"Description: {item['description']}")
            if include_operational_fields and item["detection"] and item["detection"].lower() != "not available in source data":
                lines.append(f"Detection: {item['detection']}")
            if include_operational_fields and item["mitigations"]:
                lines.append(f"Mitigation: {item['mitigations']}")
            lines.append("")
        return "\n".join(line for line in lines if line is not None).strip()

    @classmethod
    def _render_advisories(cls, items: list[dict[str, str]]) -> str:
        lines = ["Supporting Advisories"]
        for item in items:
            for label, key in cls.ADVISORY_RENDER_FIELDS:
                cls._append_field(lines, label, item.get(key, ""))
            lines.append("")
        return "\n".join(line for line in lines if line is not None).strip()

    @staticmethod
    def _render_other(items: list[dict[str, str]]) -> str:
        lines = ["Other Sources"]
        for item in items:
            summary = item["description"] or item["title"] or item["source"]
            lines.append(f"Summary: {summary}")
        return "\n".join(lines)

    @staticmethod
    def _append_field(lines: list[str], label: str, value: str) -> None:
        if value:
            lines.append(f"{label}: {value}")

    @staticmethod
    def _framework_label(source: str, group: str) -> str:
        if group == "ics":
            return "ICS ATT&CK"
        if group == "enterprise":
            return "Enterprise ATT&CK"
        if group == "cisa":
            return "CISA ICS Advisory"
        return source

    @staticmethod
    def _advisory_field(value: str, max_chars: int = 500) -> str:
        value = strip_markdown_links(re.sub(r"\s+", " ", value).strip(" ;,."))
        if not value:
            return ""
        if len(value) > max_chars:
            value = value[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;") + "..."
        return value

    @staticmethod
    def _compact_list(value: str, max_items: int = 6, max_chars: int = 200) -> str:
        value = strip_markdown_links(re.sub(r"\s+", " ", value).strip(" ;,."))
        if not value:
            return ""
        parts = [part.strip() for part in re.split(r"[,;]", value) if part.strip()]
        if len(parts) > max_items:
            value = ", ".join(parts[:max_items]) + ", ..."
        else:
            value = ", ".join(parts)
        if len(value) > max_chars:
            value = value[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;") + "..."
        return value

    @staticmethod
    def _format_tactic_list(value: str) -> str:
        return ContextBuilder._compact_list(value, max_items=8, max_chars=240)

    @staticmethod
    def _short_value(value: str, max_items: int = 3, max_chars: int = 140) -> str:
        value = strip_markdown_links(re.sub(r"\s+", " ", value).strip(" ;,."))
        if not value:
            return ""
        parts = [part.strip() for part in re.split(r"[,;]", value) if part.strip()]
        if len(parts) > max_items:
            value = ", ".join(parts[:max_items]) + ", and related products"
        else:
            value = ", ".join(parts)
        if len(value) > max_chars:
            value = value[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;") + "..."
        return value

    @staticmethod
    def _sanitize_text(text: str) -> str:
        return strip_markdown_links(text)

    @staticmethod
    def _clean_summary(text: str, sentence_limit: int = 2) -> str:
        text = strip_markdown_links(re.sub(r"\s+", " ", text).strip())
        if not text:
            return ""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        summary = " ".join(sentence.strip() for sentence in sentences[:sentence_limit] if sentence.strip())
        if len(summary) > 450:
            summary = summary[:450].rsplit(" ", 1)[0].rstrip(" ,;") + "..."
        return summary


def normalize_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
