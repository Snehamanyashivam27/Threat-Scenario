from __future__ import annotations

from rag.scenario.applicability import FinalStatus, format_gate_summary
from rag.scenario.evidence import StepEvidence
from rag.scenario.product_evidence import ProductEvidenceTrace, format_product_evidence_debug


def format_evidence_trace(evidence: list[StepEvidence]) -> str:
    sections: list[str] = []
    for step in evidence:
        sections.append(f"=== Step {step.sequence}: {step.step_id} ===")
        if step.vulnerable_component_id or step.action_target_id or step.downstream_affected_id:
            sections.append(
                "Targets: "
                f"vulnerable={step.vulnerable_component_id or '-'} "
                f"action={step.action_target_id or '-'} "
                f"downstream={step.downstream_affected_id or '-'}"
            )
        if step.selected_cve:
            sections.append(f"Selected: {step.selected_cve}")
        elif step.selected_cves:
            sections.append(f"Selected: {', '.join(step.selected_cves)}")
        if step.selection_reason:
            sections.append(f"Selection reason: {step.selection_reason}")
        if step.admission_trace:
            sections.append("Admission:")
            for row in step.admission_trace:
                admitted = "admitted" if row.get("admitted") else f"dropped:{row.get('drop_reason') or 'unknown'}"
                rank = row.get("best_rrf_rank")
                rank_text = "-" if rank is None else str(rank)
                validation = row.get("final_validation_state") or "not_evaluated"
                sections.append(
                    "  "
                    f"{row.get('cve_id')}  {row.get('kind') or 'aggregate'}  "
                    f"identity={row.get('identity_score', 0)}  "
                    f"objective={row.get('objective_score', 1)}  "
                    f"rrf={rank_text}  "
                    f"src={row.get('source_document') or '-'}  "
                    f"{admitted}  "
                    f"validation={validation}"
                )
        if not step.candidates:
            sections.append("(no candidates evaluated)")
            sections.append("")
            continue
        for candidate in step.candidates:
            try:
                final_status = FinalStatus(candidate.final_status)
            except ValueError:
                final_status = FinalStatus.INSUFFICIENT_CONTEXT
            sections.append(format_gate_summary(candidate.cve_id, final_status, candidate.checks))
            if candidate.lifecycle:
                sections.append(f"  Lifecycle: {' → '.join(candidate.lifecycle)}")
            if candidate.lifecycle_reason:
                sections.append(f"  Lifecycle reason: {candidate.lifecycle_reason}")
            if candidate.rejection_reasons:
                sections.append(f"  Rejection: {'; '.join(candidate.rejection_reasons)}")
            provenance = [
                f"  {check.name}: {check.provenance}"
                for check in candidate.checks
                if check.provenance
            ]
            if provenance:
                sections.extend(provenance[:6])
            if candidate.product_evidence_trace:
                traces = [
                    ProductEvidenceTrace(**item) if isinstance(item, dict) else item
                    for item in candidate.product_evidence_trace
                ]
                sections.append(format_product_evidence_debug(traces))
            sections.append("")
    return "\n".join(sections).rstrip() + "\n"
