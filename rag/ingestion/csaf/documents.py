from __future__ import annotations

from pathlib import Path

from rag.ingestion.csaf.models import CveDetailRecord
from rag.ingestion.csaf.parser import CsafParseError, parse_csaf_directory, parse_csaf_file
from rag.models.document import SourceDocument
from rag.scenario.product_evidence import format_product_evidence_blocks
from rag.utils.progress import report_progress
from rag.utils.text import clean_text


def cve_detail_to_source_document(record: CveDetailRecord) -> SourceDocument:
    text = build_cve_retrieval_text(record)
    sections = {
        "advisory_id": record.advisory_id,
        "cve_id": record.cve_id,
        "vendor": record.vendor or "",
        "product": record.product or "",
        "product_family": record.product_family or "",
        "model": record.model or "",
        "part_number": record.part_number or "",
        "affected_versions": "; ".join(record.affected_versions),
        "affected_products": "; ".join(record.affected_products),
        "affected_product_constraints": " || ".join(
            f"{item.get('product', '')}@@{item.get('version', '')}@@{item.get('part_number', '')}"
            for item in record.affected_product_constraints
        ),
        "cves": record.cve_id,
        "cwes": ", ".join(record.cwe_ids),
        "cvss_score": "" if record.cvss_score is None else str(record.cvss_score),
        "severity": record.severity or "",
        "description": record.description or "",
        "effects": "; ".join(record.effects),
        "network_access": record.prerequisites.network_access or "",
        "authentication_required": (
            ""
            if record.prerequisites.authentication_required is None
            else str(record.prerequisites.authentication_required).lower()
        ),
        "privileges_required": record.prerequisites.privileges_required or "",
        "user_interaction": record.prerequisites.user_interaction or "",
        "physical_access": (
            ""
            if record.prerequisites.physical_access is None
            else str(record.prerequisites.physical_access).lower()
        ),
        "references": "; ".join(record.references),
    }
    document_id = f"{record.advisory_id}::{record.cve_id}" if record.advisory_id else record.cve_id
    return SourceDocument(
        document_id=document_id,
        source="cisa_csaf",
        title=record.title or record.cve_id,
        text=text,
        metadata={
            "kind": "cisa-csaf-cve",
            "document_type": record.document_type,
            "source_type": record.source_type,
            "advisory_id": record.advisory_id,
            "cve_id": record.cve_id,
            "vendor": record.vendor or "",
            "product": record.product or "",
            "product_family": record.product_family or "",
            "model": record.model or "",
            "part_number": record.part_number or "",
            "cves": record.cve_id,
            "cwes": ", ".join(record.cwe_ids),
            "sections": sections,
            "cve_detail": record.to_dict(),
        },
    )


def build_cve_retrieval_text(record: CveDetailRecord) -> str:
    lines = [
        f"CVE: {record.cve_id}",
        f"Advisory: {record.advisory_id}" if record.advisory_id else "",
        f"Vendor: {record.vendor}" if record.vendor else "",
        f"Product: {record.product}" if record.product else "",
        f"Product Family: {record.product_family}" if record.product_family else "",
        f"Model: {record.model}" if record.model else "",
        f"Part Number: {record.part_number}" if record.part_number else "",
        f"Affected Products: {'; '.join(record.affected_products)}" if record.affected_products else "",
        (
            "Affected Product Constraints: "
            + " || ".join(
                f"{item.get('product', '')}@@{item.get('version', '')}@@{item.get('part_number', '')}"
                for item in record.affected_product_constraints
            )
            if record.affected_product_constraints
            else ""
        ),
        f"Affected Versions: {'; '.join(record.affected_versions)}" if record.affected_versions else "",
        f"CWE: {', '.join(record.cwe_ids)}" if record.cwe_ids else "",
        f"CVSS: {record.cvss_score}" if record.cvss_score is not None else "",
        f"Severity: {record.severity}" if record.severity else "",
        f"Title: {record.title}" if record.title else "",
        f"Description: {record.description}" if record.description else "",
    ]

    prereq_parts: list[str] = []
    prereq = record.prerequisites
    if prereq.network_access:
        prereq_parts.append(f"network_access={prereq.network_access}")
    if prereq.authentication_required is not None:
        prereq_parts.append(f"authentication_required={str(prereq.authentication_required).lower()}")
    if prereq.privileges_required:
        prereq_parts.append(f"privileges_required={prereq.privileges_required}")
    if prereq.user_interaction:
        prereq_parts.append(f"user_interaction={prereq.user_interaction}")
    if prereq.physical_access is not None:
        prereq_parts.append(f"physical_access={str(prereq.physical_access).lower()}")
    if prereq_parts:
        lines.append(f"Prerequisites: {'; '.join(prereq_parts)}")
    if record.effects:
        lines.append(f"Effect: {'; '.join(record.effects)}")
    if record.references:
        lines.append(f"References: {'; '.join(record.references)}")
    evidence_text = format_product_evidence_blocks(record.product_evidence)
    if evidence_text:
        lines.append(evidence_text)

    return clean_text("\n".join(line for line in lines if line))


def load_csaf_source_documents(directory: str | Path) -> list[SourceDocument]:
    records = parse_csaf_directory(
        directory,
        on_progress=lambda current, total: report_progress("Loading CSAF advisories", current, total),
    )
    return [cve_detail_to_source_document(record) for record in records]


def load_csaf_source_documents_from_files(paths: list[str | Path]) -> list[SourceDocument]:
    documents: list[SourceDocument] = []
    for path in paths:
        try:
            for record in parse_csaf_file(path):
                documents.append(cve_detail_to_source_document(record))
        except CsafParseError:
            continue
    return documents
