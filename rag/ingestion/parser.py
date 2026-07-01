from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from rag.models.document import SourceDocument
from rag.utils.text import clean_text, dedupe_preserve_order


def _first_external_id(external_references: list[dict[str, Any]] | None) -> str | None:
    for reference in external_references or []:
        external_id = reference.get("external_id")
        if external_id:
            return str(external_id)
    return None


def _build_relationship_index(objects: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    by_object_id: dict[str, dict[str, Any]] = {}
    relationships_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obj in objects:
        obj_id = obj.get("id")
        if obj_id:
            by_object_id[str(obj_id)] = obj
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        source_ref = str(obj.get("source_ref") or "")
        target_ref = str(obj.get("target_ref") or "")
        if source_ref:
            relationships_by_object[source_ref].append(obj)
        if target_ref:
            relationships_by_object[target_ref].append(obj)
    return relationships_by_object, by_object_id


def parse_attack_bundle(bundle: dict[str, Any], source_name: str) -> list[SourceDocument]:
    objects = list(bundle.get("objects") or [])
    relationships_by_object, by_object_id = _build_relationship_index(objects)

    documents: list[SourceDocument] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        object_id = str(obj.get("id"))
        title = clean_text(str(obj.get("name") or "Untitled technique"))
        attack_id = _first_external_id(obj.get("external_references"))
        description = clean_text(str(obj.get("description") or ""))

        tactic = dedupe_preserve_order(
            [str(phase.get("phase_name")) for phase in obj.get("kill_chain_phases") or [] if phase.get("phase_name")]
        )
        platform = dedupe_preserve_order([str(item) for item in obj.get("x_mitre_platforms") or [] if item])

        relation_map: dict[str, list[str]] = defaultdict(list)
        for rel in relationships_by_object.get(object_id, []):
            relation_type = str(rel.get("relationship_type") or "")
            source_ref = str(rel.get("source_ref") or "")
            target_ref = str(rel.get("target_ref") or "")
            partner_id = target_ref if source_ref == object_id else source_ref
            partner = by_object_id.get(partner_id)
            if not partner:
                continue
            partner_name = clean_text(str(partner.get("name") or ""))
            partner_type = str(partner.get("type") or "")
            if not partner_name:
                continue
            if partner_type in {"intrusion-set", "malware", "tool"} and relation_type == "uses":
                relation_map["procedures"].append(partner_name)
            elif partner_type == "course-of-action" and relation_type == "mitigates":
                relation_map["mitigations"].append(partner_name)
            elif partner_type in {"x-mitre-detection-strategy", "x-mitre-analytic"}:
                relation_map["detection"].append(partner_name)
            elif partner_type == "intrusion-set":
                relation_map["related groups"].append(partner_name)
            elif partner_type in {"malware", "tool"}:
                relation_map["related software"].append(partner_name)

        sections = {
            "description": description,
            "detection": "; ".join(dedupe_preserve_order(relation_map.get("detection", []))),
            "mitigations": "; ".join(dedupe_preserve_order(relation_map.get("mitigations", []))),
            "procedures": "; ".join(dedupe_preserve_order(relation_map.get("procedures", []))),
            "related_groups": "; ".join(dedupe_preserve_order(relation_map.get("related groups", []))),
            "related_software": "; ".join(dedupe_preserve_order(relation_map.get("related software", []))),
        }

        documents.append(
            SourceDocument(
                document_id=object_id,
                source=source_name,
                title=title,
                text=description,
                metadata={
                    "kind": "attack-pattern",
                    "attack_id": attack_id,
                    "tactic": tactic,
                    "platform": platform,
                    "sections": sections,
                    "external_references": obj.get("external_references") or [],
                    "source_type": source_name,
                },
            )
        )

    return documents


def parse_cisa_advisories(rows: Iterable[dict[str, str]], source_name: str) -> list[SourceDocument]:
    documents: list[SourceDocument] = []
    for row in rows:
        advisory_id = clean_text(row.get("icsad_ID") or row.get("icsad_id") or row.get("ICSAD_ID") or "")
        title = clean_text(row.get("ICS-CERT_Advisory_Title") or row.get("Advisory_Title") or row.get("Title") or advisory_id or "CISA ICS Advisory")
        vendor = clean_text(row.get("Vendor") or "")
        product = clean_text(row.get("Product") or "")
        products_affected = clean_text(row.get("Products_Affected") or "")
        cves = clean_text(row.get("CVE_Number") or "")
        cwes = clean_text(row.get("CWE_Number") or "")
        severity = clean_text(row.get("CVSS_Severity") or "")
        sector = clean_text(row.get("Critical_Infrastructure_Sector") or "")
        original_release = clean_text(row.get("Original_Release_Date") or "")
        last_updated = clean_text(row.get("Last_Updated") or "")
        headline = clean_text(row.get("ICS-CERT_Number") or "")

        sections = {
            "advisory_id": advisory_id,
            "title": title,
            "vendor": vendor,
            "product": product,
            "products_affected": products_affected,
            "cves": cves,
            "cwes": cwes,
            "severity": severity,
            "sector": sector,
            "release_dates": "; ".join([value for value in [original_release, last_updated] if value]),
            "headline": headline,
        }

        text_parts = [
            f"Advisory: {title}",
            f"Identifier: {advisory_id}" if advisory_id else "",
            f"Vendor: {vendor}" if vendor else "",
            f"Product: {product}" if product else "",
            f"Affected Products: {products_affected}" if products_affected else "",
            f"CVE: {cves}" if cves else "",
            f"CWE: {cwes}" if cwes else "",
            f"Severity: {severity}" if severity else "",
            f"Sector: {sector}" if sector else "",
        ]

        documents.append(
            SourceDocument(
                document_id=advisory_id or title,
                source=source_name,
                title=title,
                text=clean_text("\n".join(part for part in text_parts if part)),
                metadata={
                    "kind": "cisa-ics-advisory",
                    "sections": sections,
                    "source_type": source_name,
                    "row": row,
                },
            )
        )

    return documents
