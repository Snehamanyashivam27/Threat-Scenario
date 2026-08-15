from __future__ import annotations

import re

from rag.retrieval.document_fields import extract_cves
from rag.scenario.evidence import StepEvidence


def narrative_uses_only_validated_cves(
    narrative: str,
    evidence: list[StepEvidence],
) -> bool:
    """Post-generation gate: every CVE mentioned must be selected for narration."""
    allowed = _selected_cves(evidence)
    claimed = {cve_id.upper() for cve_id in extract_cves(narrative)}
    if not claimed <= allowed:
        return False
    return narrative_claims_are_grounded(narrative, evidence)


def narrative_claims_are_grounded(
    narrative: str,
    evidence: list[StepEvidence],
) -> bool:
    """Validate type/product/version/effect claims against narrator evidence when present."""
    by_cve = _narrator_by_cve(evidence)
    if not by_cve:
        # Selection IDs alone are enough when narrator payloads were not attached.
        return True
    for cve_id in extract_cves(narrative):
        item = by_cve.get(cve_id.upper())
        if item is None:
            return False
        window = _cve_window(narrative, cve_id)
        phrase = str(item.get("vulnerability_phrase") or item.get("technical_effect") or "").lower()
        typed = _specific_type_token(phrase)
        invented = _specific_type_token(window)
        if invented and typed and invented != typed and invented not in phrase:
            return False
        if "serial number" in window and "firmware version" in window:
            applicability = " ".join(item.get("unresolved_conditions") or []).lower()
            applicability += " " + " ".join(item.get("confirmed_conditions") or []).lower()
            if "serial" in applicability and "firmware" not in applicability:
                return False
    return True


def mark_removed_by_validator(evidence: list[StepEvidence], narrative: str) -> None:
    """Record auditable removal when a selected CVE no longer appears in the narrative."""
    narrated = {cve_id.upper() for cve_id in extract_cves(narrative)}
    for step in evidence:
        for candidate in step.candidates:
            if candidate.cve_id.upper() in narrated:
                if "NARRATED" not in candidate.lifecycle:
                    candidate.record_lifecycle("NARRATED")
                continue
            if candidate.cve_id == step.selected_cve or candidate.cve_id in step.selected_cves:
                if "NARRATED" not in candidate.lifecycle:
                    candidate.record_lifecycle(
                        "REMOVED_BY_VALIDATOR",
                        reason="selected CVE absent from validated narrative output",
                    )


def _selected_cves(evidence: list[StepEvidence]) -> set[str]:
    return {
        cve_id.upper()
        for step in evidence
        for cve_id in ([step.selected_cve] if step.selected_cve else step.selected_cves)
        if cve_id
    }


def _narrator_by_cve(evidence: list[StepEvidence]) -> dict[str, dict]:
    by_cve: dict[str, dict] = {}
    for step in evidence:
        for item in step.narrator_evidence:
            cve_id = str(item.get("cve_id") or "").upper()
            if cve_id:
                by_cve[cve_id] = item
    return by_cve


def _cve_window(narrative: str, cve_id: str) -> str:
    upper = narrative.upper()
    idx = upper.find(cve_id.upper())
    if idx < 0:
        return ""
    return narrative[max(0, idx - 100) : idx + 260].lower()


def _specific_type_token(text: str) -> str:
    lowered = text.lower()
    for token in (
        "command-injection",
        "authentication-bypass",
        "stack-based buffer-overflow",
        "buffer-overflow",
        "improper privilege-management",
        "privilege-management",
        "path-traversal",
        "denial-of-service",
    ):
        if token in lowered:
            return token
    return ""
