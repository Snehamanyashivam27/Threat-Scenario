from __future__ import annotations

"""Bind a finished scenario result to CSAF remediations.

Read-only: does not mutate ScenarioNarrativeResult or CandidateEvidence.
"""

from pathlib import Path

from rag.defense.csaf_remediation import lookup_csaf_remediations
from rag.defense.models import StepRemediationInventory
from rag.scenario.evidence import CandidateEvidence, StepEvidence
from rag.scenario.models import ScenarioNarrativeResult


def inventory_scenario_result(
    result: ScenarioNarrativeResult,
    csaf_dir: str | Path,
) -> list[StepRemediationInventory]:
    return inventory_step_evidence(result.evidence, csaf_dir)


def inventory_step_evidence(
    evidence: list[StepEvidence],
    csaf_dir: str | Path,
) -> list[StepRemediationInventory]:
    rows: list[StepRemediationInventory] = []
    directory = Path(csaf_dir)
    for step in evidence:
        selected = _selected_cve(step)
        if not selected:
            rows.append(
                StepRemediationInventory(
                    step_id=step.step_id,
                    sequence=step.sequence,
                    selected_cve=None,
                    advisory_id=None,
                    records=[],
                    note="no_selected_cve",
                )
            )
            continue
        advisory_id = _advisory_id_for_cve(step.candidates, selected)
        records = lookup_csaf_remediations(directory, cve_id=selected, advisory_id=advisory_id)
        if not records:
            note = "csaf_not_found"
        elif not any(item.has_remediation_evidence() for item in records):
            note = "no_csaf_remediation_fields"
        else:
            note = ""
        rows.append(
            StepRemediationInventory(
                step_id=step.step_id,
                sequence=step.sequence,
                selected_cve=selected,
                advisory_id=advisory_id,
                records=records,
                note=note,
            )
        )
    return rows


def format_inventory_text(rows: list[StepRemediationInventory]) -> str:
    if not rows:
        return "(no steps)"
    lines: list[str] = []
    for row in rows:
        header = f"=== Step {row.sequence}: {row.step_id} ==="
        if not row.selected_cve:
            lines.extend([header, "Selected CVE: none", f"Note: {row.note}", ""])
            continue
        lines.append(header)
        lines.append(f"Selected CVE: {row.selected_cve}")
        lines.append(f"Advisory: {row.advisory_id or '-'}")
        if row.note:
            lines.append(f"Note: {row.note}")
        if not row.records:
            lines.append("")
            continue
        for record in row.records:
            lines.append(f"Source: {record.provenance}")
            if record.remediations:
                lines.append("Remediations:")
                for action in record.remediations:
                    products = ", ".join(action.product_ids) or "-"
                    lines.append(f"  - category={action.category or '-'} products={products}")
                    if action.details:
                        lines.append(f"    details: {action.details}")
                    for url in action.urls:
                        lines.append(f"    url: {url}")
            else:
                lines.append("Remediations: (none in CSAF record)")
            if record.fixed_product_ids:
                lines.append("product_status.fixed: " + "; ".join(record.fixed_product_ids))
            else:
                lines.append("product_status.fixed: (none)")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _selected_cve(step: StepEvidence) -> str | None:
    raw = step.selected_cve or (step.selected_cves[0] if step.selected_cves else None)
    if not raw:
        return None
    return str(raw).upper()


def _advisory_id_for_cve(candidates: list[CandidateEvidence], cve_id: str) -> str | None:
    for candidate in candidates:
        if candidate.cve_id.upper() == cve_id and candidate.advisory_id:
            return str(candidate.advisory_id).upper()
    return None
