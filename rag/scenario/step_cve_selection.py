from __future__ import annotations

# RETRIEVAL FINDS CANDIDATES.
# CANONICAL EVIDENCE DEFINES FACTS.
# VALIDATION DETERMINES APPLICABILITY.
# EFFECT COMPATIBILITY DETERMINES WHETHER A CVE EXPLAINS A STEP.
# STEP SELECTION CHOOSES THE BEST CANDIDATE.
# THE LLM ONLY NARRATES THE RESULT.
#
# PRODUCT MATCH != STEP APPLICABILITY.
# UNKNOWN != FALSE.
# UNKNOWN EFFECT != PROOF OF A SPECIFIC ATTACK CAPABILITY.
#
# CVE METADATA MUST NEVER LEAK BETWEEN CVES.
# A SELECTED CVE MUST NEVER DISAPPEAR WITHOUT AN AUDITABLE REASON.

import re
from dataclasses import dataclass, field

from rag.scenario.applicability import PREREQUISITE_GATE_NAMES, StepObjective, classify_step_objective
from rag.scenario.evidence import CandidateEvidence, TruthValue
from rag.scenario.models import AttackStep, ComponentModel


HARD_SELECTION_GATES = frozenset(
    {
        "product",
        "version",
        "software_version",
        "technical_effect",
        *PREREQUISITE_GATE_NAMES,
    }
)

IDENTITY_GATE_WEIGHTS = {
    "part_number": 4,
    "model": 3,
    "product_name": 2,
    "relationship": 1,
    "product": 1,
}


@dataclass(frozen=True, slots=True)
class StepCveSelection:
    step_id: str
    selected: CandidateEvidence | None
    ranked_survivors: tuple[CandidateEvidence, ...] = ()
    reason: str = ""
    alternatives: tuple[CandidateEvidence, ...] = ()


def select_best_step_candidate(
    step_id: str,
    candidates: list[CandidateEvidence],
    *,
    step: AttackStep | None = None,
    component: ComponentModel | None = None,
    used_cves: set[str] | None = None,
) -> StepCveSelection:
    if step is not None and not step_supports_cve_selection(step):
        for candidate in candidates:
            candidate.record_lifecycle("NOT_SELECTED", reason="step_not_vulnerability_relevant")
        return StepCveSelection(
            step_id=step_id,
            selected=None,
            reason="step_not_vulnerability_relevant",
        )
    blocked = used_cves or set()
    survivors = []
    for candidate in candidates:
        if candidate.cve_id in blocked:
            candidate.record_lifecycle("NOT_SELECTED", reason="cve_already_used_on_prior_step")
            continue
        if _is_narration_eligible(candidate, component):
            candidate.record_lifecycle("NARRATOR_ELIGIBLE")
            survivors.append(candidate)
        else:
            candidate.record_lifecycle("NOT_SELECTED", reason=_candidate_not_selected_reason(candidate))
    survivors.sort(key=lambda item: _selection_rank_key(item, component))
    selected = survivors[0] if survivors else None
    if selected is not None:
        selected.record_lifecycle("SELECTED")
        for alt in survivors[1:]:
            alt.record_lifecycle("NOT_SELECTED", reason="ranked_below_primary")
        reason = (
            f"selected:{selected.cve_id};disposition={selected.disposition};"
            f"final_status={selected.final_status}"
        )
    else:
        reason = _no_selection_reason(candidates)
    return StepCveSelection(
        step_id=step_id,
        selected=selected,
        ranked_survivors=tuple(survivors),
        reason=reason,
        alternatives=tuple(survivors[1:3]),
    )


def _effect_true(candidate: CandidateEvidence) -> bool:
    checks = {check.name: check.status for check in candidate.checks}
    return checks.get("technical_effect") == TruthValue.TRUE


def _candidate_not_selected_reason(candidate: CandidateEvidence) -> str:
    if candidate.disposition == "rejected":
        return "rejected"
    if candidate.disposition == "insufficient":
        return "insufficient"
    if not _effect_true(candidate):
        return "effect_not_confirmed"
    return "hard_gate_failed"


def _no_selection_reason(candidates: list[CandidateEvidence]) -> str:
    """ABSTAIN is empty discovery. REJECTED/INSUFFICIENT are evaluated outcomes."""
    if not candidates:
        return "abstain"
    dispositions = {candidate.disposition for candidate in candidates}
    if dispositions <= {"rejected"}:
        return "rejected"
    return "insufficient"


def _is_narration_eligible(
    candidate: CandidateEvidence,
    component: ComponentModel | None = None,
) -> bool:
    """Eligible only when product/version/prereqs are not FALSE and effect is TRUE.

    Unknown deployment details (e.g. version) may remain conditional.
    Unknown effect-to-step compatibility must NOT authorize a specific exploit claim.
    Advisory-reference mismatch is ranking-only, never a hard reject.
    """
    del component  # ranking-only; kept for call-site compatibility
    if not candidate.is_usable:
        return False
    checks = {check.name: check.status for check in candidate.checks}
    for gate in HARD_SELECTION_GATES:
        if gate == "technical_effect":
            continue
        if checks.get(gate) == TruthValue.FALSE:
            return False
    # Effect must be confirmed compatible with the step — UNKNOWN is not enough.
    if checks.get("technical_effect") != TruthValue.TRUE:
        return False
    return True


def step_supports_cve_selection(step: AttackStep) -> bool:
    from rag.scenario.step_targets import is_downstream_consequence_step

    if is_downstream_consequence_step(step):
        return False
    lowered_name = step.name.lower()
    if lowered_name.startswith("effect") or "impact" in lowered_name:
        return False
    objective = classify_step_objective(step)
    if objective in {StepObjective.INITIAL_ACCESS, StepObjective.LATERAL_MOVEMENT, StepObjective.CREDENTIAL_ACCESS}:
        return False
    if objective in {
        StepObjective.DEVICE_COMPROMISE,
        StepObjective.CONTROL_MODIFICATION,
        StepObjective.PRIVILEGE_ESCALATION,
        StepObjective.NETWORK_CONTROL_BYPASS,
        StepObjective.AVAILABILITY_IMPACT,
        StepObjective.CONFIDENTIALITY_IMPACT,
    }:
        return True
    if objective == StepObjective.SESSION_COMPROMISE:
        blob = f"{step.name} {step.description}".lower()
        return any(
            token in blob
            for token in (
                "replay",
                "hijack",
                "mitm",
                "man-in-the-middle",
                "man in the middle",
                "intercept and modify",
                "session integrity",
            )
        )
    blob = f"{step.name} {step.description}".lower()
    return bool(
        re.search(
            r"\b(?:exploit|crafted|compromise|vulnerabilit\w*|bypass(?:es|ing)?)\b",
            blob,
            flags=re.IGNORECASE,
        )
    )


def _selection_rank_key(
    candidate: CandidateEvidence,
    component: ComponentModel | None,
) -> tuple:
    checks = {check.name: check.status for check in candidate.checks}
    return (
        0 if candidate.disposition == "applicable" else 1,
        -_identity_strength(checks),
        -_gate_confirmed_score(checks.get("version")),
        -_prerequisite_confirmed_count(checks),
        -_gate_confirmed_score(checks.get("technical_effect")),
        -_source_specificity(candidate, component),
        -candidate.rank_score,
        candidate.cve_id,
    )


def _identity_strength(checks: dict[str, TruthValue]) -> int:
    score = 0
    for gate, weight in IDENTITY_GATE_WEIGHTS.items():
        status = checks.get(gate)
        if status == TruthValue.TRUE:
            score += weight
        elif status == TruthValue.UNKNOWN and gate == "product":
            score += 1
    return score


def _gate_confirmed_score(status: TruthValue | None) -> int:
    if status == TruthValue.TRUE:
        return 2
    if status == TruthValue.UNKNOWN:
        return 1
    return 0


def _prerequisite_confirmed_count(checks: dict[str, TruthValue]) -> int:
    return sum(1 for gate in PREREQUISITE_GATE_NAMES if checks.get(gate) == TruthValue.TRUE)


def _source_specificity(candidate: CandidateEvidence, component: ComponentModel | None) -> int:
    score = 0
    if candidate.advisory_id and str(candidate.advisory_id).upper().startswith("ICSA-"):
        score += 1
    reference = component.advisory_reference() if component else None
    if reference and candidate.advisory_id:
        if reference.upper() == str(candidate.advisory_id).upper():
            score += 4
    return score
