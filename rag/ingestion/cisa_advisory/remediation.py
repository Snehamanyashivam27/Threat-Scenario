from __future__ import annotations

from rag.defense.models import CveRemediationRecord, RemediationAction
from rag.ingestion.cisa_advisory.parser import AdvisoryDetail
from rag.ingestion.cisa_advisory.store import AdvisoryDetailStore


def lookup_advisory_remediations(
    directory: str,
    *,
    cve_id: str,
    advisory_id: str | None,
) -> list[CveRemediationRecord]:
    """Return full-advisory remediations only for the exact selected advisory/CVE."""
    wanted_cve = (cve_id or "").upper()
    wanted_advisory = (advisory_id or "").upper()
    if not wanted_cve.startswith("CVE-") or not wanted_advisory:
        return []
    detail = AdvisoryDetailStore(directory).lookup(wanted_advisory)
    if detail is None:
        return []
    return advisory_detail_to_remediation_records(detail, cve_id=wanted_cve)


def advisory_detail_to_remediation_records(
    detail: AdvisoryDetail,
    *,
    cve_id: str,
) -> list[CveRemediationRecord]:
    wanted = cve_id.upper()
    if wanted not in {item.upper() for item in detail.cve_ids}:
        return []
    actions: list[RemediationAction] = []
    for item in detail.remediations:
        scoped = [str(value).upper() for value in item.get("cve_ids") or []]
        scope = str(item.get("scope") or "advisory_level")
        if scoped and wanted not in scoped:
            continue
        if scope == "cve_specific" and wanted not in scoped:
            continue
        details = str(item.get("details") or "").strip()
        category = str(item.get("category") or "mitigation")
        if not details:
            continue
        actions.append(
            RemediationAction(
                category=category,
                details=details,
                urls=list(item.get("urls") or []),
                product_ids=list(item.get("product_ids") or []),
                group_ids=[],
                scope=scope,
            )
        )
    if not actions:
        return []
    return [
        CveRemediationRecord(
            cve_id=wanted,
            advisory_id=detail.advisory_id,
            source_path=detail.source_url or detail.advisory_id,
            provenance=f"{detail.advisory_id}::{wanted}::cisa_ics_advisory_detail",
            remediations=actions,
            source_type="cisa_ics_advisory_detail",
        )
    ]
