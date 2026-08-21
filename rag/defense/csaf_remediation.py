from __future__ import annotations

"""Extract CSAF remediations without using the threat-generation parser.

Reads source JSON directly. Does not rank, retrieve, or mutate scenario objects.
"""

import json
import re
from pathlib import Path
from typing import Any

from rag.defense.models import CveRemediationRecord, RemediationAction
from rag.defense.product_binding import classify_remediation_scope
from rag.ingestion.csaf.parser import index_product_tree
from rag.utils.text import clean_text, dedupe_preserve_order


def load_csaf_remediation_records(path: str | Path) -> list[CveRemediationRecord]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    return _records_from_document(data, source_path=str(source.resolve()))


def lookup_csaf_remediations(
    directory: str | Path,
    *,
    cve_id: str,
    advisory_id: str | None = None,
) -> list[CveRemediationRecord]:
    """Return every distinct CSAF source for an exact CVE ID.

    `advisory_id` is used only to order matching advisories first. It does not
    drop other exact CVE sources.
    """
    wanted_cve = (cve_id or "").upper()
    wanted_advisory = (advisory_id or "").upper()
    if not wanted_cve.startswith("CVE-"):
        return []
    root = Path(directory)
    if not root.exists():
        return []
    found: list[CveRemediationRecord] = []
    seen_provenance: set[str] = set()
    for path in sorted(root.glob("*.json"), key=lambda item: item.as_posix()):
        for record in load_csaf_remediation_records(path):
            if record.cve_id != wanted_cve:
                continue
            if record.provenance in seen_provenance:
                continue
            seen_provenance.add(record.provenance)
            found.append(record)
    found.sort(
        key=lambda item: (
            0 if wanted_advisory and item.advisory_id == wanted_advisory else 1,
            item.source_path,
            item.advisory_id,
        )
    )
    return found


def _records_from_document(data: dict[str, Any], source_path: str) -> list[CveRemediationRecord]:
    document = data.get("document") or {}
    if not isinstance(document, dict):
        return []
    advisory_id = _advisory_id(document)
    tree = data.get("product_tree") if isinstance(data.get("product_tree"), dict) else {}
    product_index = index_product_tree(tree)
    records: list[CveRemediationRecord] = []
    seen_cves: set[str] = set()
    for vulnerability in data.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = clean_text(str(vulnerability.get("cve") or "")).upper()
        if not cve_id.startswith("CVE-") or cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        remediations: list[RemediationAction] = []
        for item in vulnerability.get("remediations") or []:
            if not isinstance(item, dict):
                continue
            action = _remediation_action(item)
            if action is not None:
                remediations.append(action)
        remediations = _dedupe_actions(remediations)
        status = vulnerability.get("product_status") if isinstance(vulnerability.get("product_status"), dict) else {}
        fixed_raw = status.get("fixed") or []
        fixed_ids = dedupe_preserve_order(
            [clean_text(str(item)) for item in fixed_raw if item]
            if isinstance(fixed_raw, list)
            else []
        )
        records.append(
            CveRemediationRecord(
                cve_id=cve_id,
                advisory_id=advisory_id,
                source_path=source_path,
                provenance=f"{advisory_id}::{cve_id}::{source_path}",
                remediations=remediations,
                fixed_product_ids=fixed_ids,
                product_index=product_index,
            )
        )
    return records


def _advisory_id(document: dict[str, Any]) -> str:
    tracking = document.get("tracking") if isinstance(document.get("tracking"), dict) else {}
    tracking_id = clean_text(str(tracking.get("id") or "")).upper()
    if tracking_id:
        return tracking_id
    title = clean_text(str(document.get("title") or ""))
    match = re.search(r"\b(?:ICSA|ICSMA|ICSALERT)-[\dA-Z-]+\b", title, flags=re.IGNORECASE)
    return match.group(0).upper() if match else ""


def _remediation_action(item: dict[str, Any]) -> RemediationAction | None:
    details = _clean_remediation_details(item.get("details") or "")
    category = clean_text(str(item.get("category") or ""))
    urls = _extract_urls(item)
    product_ids = _id_list(item.get("product_ids"))
    group_ids = _id_list(item.get("group_ids"))
    if not details and not category and not urls and not product_ids and not group_ids:
        return None
    return RemediationAction(
        category=category,
        details=details,
        urls=urls,
        product_ids=product_ids,
        group_ids=group_ids,
        scope=classify_remediation_scope(product_ids),
    )


def _clean_remediation_details(raw: Any) -> str:
    """Keep source paragraphs as separate sentences after whitespace collapse.

    CSAF `details` often uses a blank line between the update instruction and a
    follow-on firmware/package note. Collapsing whitespace without punctuation
    would glue them into one clause.
    """
    text = str(raw or "").replace("\r\n", "\n").replace("\r", "\n")
    paragraphs = [clean_text(part) for part in re.split(r"\n\s*\n+", text)]
    paragraphs = [part for part in paragraphs if part]
    if len(paragraphs) <= 1:
        return paragraphs[0] if paragraphs else ""
    sentences: list[str] = []
    for part in paragraphs:
        if not re.search(r"[.!?]$", part):
            part = f"{part}."
        sentences.append(part)
    return " ".join(sentences)


def _extract_urls(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("url", "urls"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            values.append(clean_text(raw))
        elif isinstance(raw, list):
            values.extend(clean_text(str(entry)) for entry in raw if entry)
    return dedupe_preserve_order([item for item in values if item])


def _id_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return dedupe_preserve_order([clean_text(str(item)) for item in raw if item])


def _dedupe_actions(actions: list[RemediationAction]) -> list[RemediationAction]:
    seen: set[tuple] = set()
    unique: list[RemediationAction] = []
    for action in actions:
        key = action.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique
