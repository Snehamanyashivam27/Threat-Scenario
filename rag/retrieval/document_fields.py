from __future__ import annotations

import re

from rag.models.document import RetrievedChunk
from rag.utils.text import strip_markdown_links


def extract_attack_ids(query: str) -> set[str]:
    return {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE)}


def extract_cves(query: str) -> set[str]:
    return {match.upper() for match in re.findall(r"\bCVE-\d{4}-\d+\b", query, flags=re.IGNORECASE)}


def extract_attack_id(chunk: RetrievedChunk) -> str:
    attack_id = chunk.metadata.get("attack_id") or chunk.metadata.get("meta_attack_id") or ""
    if attack_id:
        return str(attack_id).upper()
    fields = extract_fields(chunk.text)
    field_id = fields.get("ATT&CK ID", "")
    return field_id.upper() if field_id else ""


def extract_title(chunk: RetrievedChunk) -> str:
    title = str(chunk.metadata.get("title") or "")
    if title:
        return title
    fields = extract_fields(chunk.text)
    return fields.get("Technique Name") or fields.get("Technique") or fields.get("Advisory") or ""


def extract_fields(text: str) -> dict[str, str]:
    labels = [
        "Technique Name", "Technique", "ATT&CK ID", "Tactic", "Platforms", "Platform", "Description",
        "Detection", "Mitigations", "Advisory", "Identifier", "Vendor", "Product", "Affected Products",
        "CVE", "CWE", "Severity", "Sector",
    ]
    label_pattern = "|".join(re.escape(label) for label in labels)
    pattern = re.compile(rf"({label_pattern}):\s*(.*?)(?=\s+(?:{label_pattern}):|$)", flags=re.IGNORECASE | re.DOTALL)
    fields: dict[str, str] = {}
    canonical = {label.lower(): label for label in labels}
    for match in pattern.finditer(text):
        label = canonical.get(match.group(1).lower(), match.group(1))
        fields[label] = strip_markdown_links(re.sub(r"\s+", " ", match.group(2)).strip())
    return fields
