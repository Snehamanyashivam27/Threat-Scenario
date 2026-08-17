from __future__ import annotations

"""Deterministic recommendation eligibility policy.

Consumes Stage 4 unified evidence and emits recommendation candidates.
Does not generate prose, rank by risk, merge CSAF with ATT&CK, or mutate inputs.
"""

import json

from rag.defense.models import (
    AttackMitigationEvidence,
    DefenseSupportState,
    RecommendationCandidate,
    RecommendationCondition,
    RecommendationPolicyState,
    StepRecommendationCandidates,
    UnifiedStepDefenseEvidence,
    ValidatedRemediation,
)
from rag.scenario.evidence import TruthValue
from rag.utils.text import stable_hash

SOURCE_CSAF = "csaf_remediation"
SOURCE_ATTACK = "attack_mitigation"
ACTIONABLE_STATES = frozenset(
    {
        RecommendationPolicyState.ELIGIBLE,
        RecommendationPolicyState.CONDITIONAL,
    }
)
_CSAF_CATEGORY_RANK = {
    "vendor_fix": 0,
    "mitigation": 1,
    "workaround": 2,
}
_SUPPORT_TO_POLICY = {
    DefenseSupportState.SUPPORTED: RecommendationPolicyState.ELIGIBLE,
    DefenseSupportState.CONDITIONAL: RecommendationPolicyState.CONDITIONAL,
    DefenseSupportState.INSUFFICIENT_EVIDENCE: RecommendationPolicyState.SUPPRESSED,
    DefenseSupportState.REJECTED: RecommendationPolicyState.SUPPRESSED,
    DefenseSupportState.NOT_APPLICABLE: RecommendationPolicyState.SUPPRESSED,
}
_CONDITIONAL_CHECK_NAMES = (
    "version",
    "remediation_scope",
    "fixed_scope",
    "advisory_match",
    "unresolved_conditions",
)
_AMBIGUOUS_CSAF = "ambiguous_csaf_step_id"
_AMBIGUOUS_ATTACK = "ambiguous_attack_step_id"


def apply_recommendation_policy(
    rows: list[UnifiedStepDefenseEvidence],
) -> list[StepRecommendationCandidates]:
    results: list[StepRecommendationCandidates] = []
    for index, row in enumerate(rows):
        candidates = _candidates_for_step(row)
        candidates = _dedupe_candidates(candidates)
        candidates.sort(key=lambda item: _sort_key(item, index))
        results.append(
            StepRecommendationCandidates(
                step_id=row.step_id,
                sequence=row.sequence,
                notes=list(row.notes),
                candidates=candidates,
            )
        )
    return results


def actionable_recommendation_candidates(
    rows: list[StepRecommendationCandidates],
) -> list[RecommendationCandidate]:
    selected: list[RecommendationCandidate] = []
    for row in rows:
        for item in row.candidates:
            if item.policy_state in ACTIONABLE_STATES:
                selected.append(item)
    return selected


def serialize_step_recommendation_candidates(rows: list[StepRecommendationCandidates]) -> str:
    return json.dumps(
        [row.to_dict() for row in rows],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _candidates_for_step(row: UnifiedStepDefenseEvidence) -> list[RecommendationCandidate]:
    candidates: list[RecommendationCandidate] = []
    if _AMBIGUOUS_CSAF not in row.notes and row.csaf is not None:
        for remediation in row.csaf.remediations:
            candidates.append(_csaf_candidate(row, remediation))
    if (
        _AMBIGUOUS_ATTACK not in row.notes
        and row.attack is not None
        and row.attack.records
        and row.attack_relationship_supported == TruthValue.TRUE
    ):
        for record in row.attack.records:
            candidates.append(_attack_candidate(row, record))
    return candidates


def _csaf_candidate(
    row: UnifiedStepDefenseEvidence,
    remediation: ValidatedRemediation,
) -> RecommendationCandidate:
    category = remediation.category
    if category == "none_available":
        policy = RecommendationPolicyState.INFORMATIONAL
        reason = "source reports that no remediation is available"
    else:
        policy = _SUPPORT_TO_POLICY.get(remediation.support_state, RecommendationPolicyState.SUPPRESSED)
        reason = _csaf_reason(policy, remediation.support_state, category)
    conditions = _conditions_from_checks(remediation) if policy == RecommendationPolicyState.CONDITIONAL else []
    recommendation_id = _recommendation_id(
        SOURCE_CSAF,
        row.step_id,
        category,
        remediation.cve_id,
        remediation.advisory_id,
        "",
        "",
        remediation.provenance,
        remediation.details,
    )
    return RecommendationCandidate(
        step_id=row.step_id,
        sequence=row.sequence,
        recommendation_id=recommendation_id,
        source_type=SOURCE_CSAF,
        policy_state=policy,
        category=category,
        name="",
        content=remediation.details,
        cve_id=remediation.cve_id,
        advisory_id=remediation.advisory_id,
        support_state=remediation.support_state.value,
        conditions=conditions,
        policy_reason=reason,
        provenance=remediation.provenance,
        urls=list(remediation.urls),
    )


def _attack_candidate(
    row: UnifiedStepDefenseEvidence,
    record: AttackMitigationEvidence,
) -> RecommendationCandidate:
    technique_id = record.technique_external_id or record.technique_stix_id
    mitigation_id = record.mitigation_external_id or record.mitigation_stix_id
    recommendation_id = _recommendation_id(
        SOURCE_ATTACK,
        row.step_id,
        "attack_mitigation",
        "",
        "",
        technique_id,
        mitigation_id,
        record.provenance,
        record.description,
    )
    return RecommendationCandidate(
        step_id=row.step_id,
        sequence=row.sequence,
        recommendation_id=recommendation_id,
        source_type=SOURCE_ATTACK,
        policy_state=RecommendationPolicyState.ELIGIBLE,
        category="attack_mitigation",
        name=record.mitigation_name,
        content=record.description,
        technique_id=technique_id,
        mitigation_id=mitigation_id,
        relationship_supported=row.attack_relationship_supported.value,
        deployment_applicability=row.attack_deployment_applicability.value,
        policy_reason="exact ATT&CK mitigates relationship; deployment applicability is unknown",
        provenance=record.provenance,
        urls=list(record.urls),
    )


def _csaf_reason(
    policy: RecommendationPolicyState,
    support_state: DefenseSupportState,
    category: str,
) -> str:
    if policy == RecommendationPolicyState.ELIGIBLE:
        return f"csaf {category} is supported"
    if policy == RecommendationPolicyState.CONDITIONAL:
        return f"csaf {category} is conditional"
    return f"csaf {category} is {support_state.value}"


def _conditions_from_checks(remediation: ValidatedRemediation) -> list[RecommendationCondition]:
    conditions: list[RecommendationCondition] = []
    for check in remediation.checks:
        if check.name not in _CONDITIONAL_CHECK_NAMES:
            continue
        if check.status not in {TruthValue.UNKNOWN, TruthValue.FALSE}:
            continue
        conditions.append(
            RecommendationCondition(
                name=check.name,
                status=check.status,
                reason=check.reason,
            )
        )
    return conditions


def _recommendation_id(
    source_type: str,
    step_id: str,
    category: str,
    cve_id: str,
    advisory_id: str,
    technique_id: str,
    mitigation_id: str,
    provenance: str,
    content: str,
) -> str:
    key = "|".join(
        [
            source_type,
            step_id,
            category,
            cve_id,
            advisory_id,
            technique_id,
            mitigation_id,
            provenance,
            content,
        ]
    )
    prefix = "csaf" if source_type == SOURCE_CSAF else "attack"
    return f"{prefix}:{stable_hash(key)}"


def _dedupe_candidates(candidates: list[RecommendationCandidate]) -> list[RecommendationCandidate]:
    seen: set[str] = set()
    unique: list[RecommendationCandidate] = []
    for item in candidates:
        if item.recommendation_id in seen:
            continue
        seen.add(item.recommendation_id)
        unique.append(item)
    return unique


def _sort_key(item: RecommendationCandidate, step_index: int) -> tuple:
    return (
        _class_rank(item),
        step_index,
        item.source_type,
        item.category,
        item.advisory_id,
        item.cve_id,
        item.technique_id,
        item.mitigation_id,
        item.provenance,
        item.recommendation_id,
    )


def _class_rank(item: RecommendationCandidate) -> int:
    if item.source_type == SOURCE_CSAF:
        category_rank = _CSAF_CATEGORY_RANK.get(item.category, 3)
        if item.policy_state == RecommendationPolicyState.ELIGIBLE:
            return category_rank
        if item.policy_state == RecommendationPolicyState.CONDITIONAL:
            return 4 + category_rank
        if item.policy_state == RecommendationPolicyState.INFORMATIONAL:
            return 10
        return 11
    if item.policy_state == RecommendationPolicyState.ELIGIBLE:
        return 8
    if item.policy_state == RecommendationPolicyState.CONDITIONAL:
        return 9
    if item.policy_state == RecommendationPolicyState.INFORMATIONAL:
        return 10
    return 11
