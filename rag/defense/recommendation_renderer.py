from __future__ import annotations

"""Deterministic template rendering for Stage 5 recommendation candidates.

Presentation only. Does not change eligibility, invent advice, merge sources,
or use an LLM.
"""

import json

from rag.defense.models import (
    DefenseRecommendationReport,
    RecommendationCandidate,
    RecommendationCondition,
    RecommendationPolicyState,
    RenderedRecommendation,
    RenderedStepRecommendations,
    StepRecommendationCandidates,
)
from rag.defense.recommendation_policy import ACTIONABLE_STATES, SOURCE_ATTACK, SOURCE_CSAF

_ELIGIBLE_PREFIX = {
    "vendor_fix": "Vendor remediation",
    "mitigation": "Mitigation",
    "workaround": "Workaround",
}
_CONDITIONAL_PREFIX = {
    "vendor_fix": "Conditional vendor remediation",
    "mitigation": "Conditional mitigation",
    "workaround": "Conditional workaround",
}
_UNKNOWN_DEPLOYMENT = "unknown"
_INTERNAL_REASON_MARKERS = (
    "product_ids",
    "fixed_product_ids",
    "matched_dimension",
    "source_conflict",
    "known_true",
    "known_false",
    "selected cve has unresolved conditions",
)
_GENERIC_UNRESOLVED_NAME = "unresolved_conditions"
_DISPLAYABLE_CONDITION_NAMES = {
    "version": "the deployed version is unknown",
    "remediation_scope": "remediation applicability to the selected deployment is not fully confirmed",
    "advisory_match": "source applicability to the selected deployment is unresolved",
}


def render_actionable_recommendations(
    rows: list[StepRecommendationCandidates],
) -> DefenseRecommendationReport:
    return _render_report(rows, include_actionable=True, include_informational=False)


def render_informational_recommendations(
    rows: list[StepRecommendationCandidates],
) -> DefenseRecommendationReport:
    return _render_report(rows, include_actionable=False, include_informational=True)


def render_defense_recommendations(
    rows: list[StepRecommendationCandidates],
    *,
    include_informational: bool = False,
) -> DefenseRecommendationReport:
    return _render_report(
        rows,
        include_actionable=True,
        include_informational=include_informational,
    )


def serialize_defense_recommendation_report(report: DefenseRecommendationReport) -> str:
    return json.dumps(
        report.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _render_report(
    rows: list[StepRecommendationCandidates],
    *,
    include_actionable: bool,
    include_informational: bool,
) -> DefenseRecommendationReport:
    steps: list[RenderedStepRecommendations] = []
    informational: list[RenderedRecommendation] = []
    for row in rows:
        rendered: list[RenderedRecommendation] = []
        for candidate in row.candidates:
            if candidate.policy_state is RecommendationPolicyState.SUPPRESSED:
                continue
            if candidate.policy_state is RecommendationPolicyState.INFORMATIONAL:
                if include_informational:
                    informational.append(_render_candidate(candidate))
                continue
            if include_actionable and candidate.policy_state in ACTIONABLE_STATES:
                rendered.append(_render_candidate(candidate))
        if rendered:
            steps.append(
                RenderedStepRecommendations(
                    step_id=row.step_id,
                    sequence=row.sequence,
                    recommendations=rendered,
                )
            )
    return DefenseRecommendationReport(steps=steps, informational=informational)


def _render_candidate(candidate: RecommendationCandidate) -> RenderedRecommendation:
    return RenderedRecommendation(
        step_id=candidate.step_id,
        sequence=candidate.sequence,
        recommendation_id=candidate.recommendation_id,
        source_type=candidate.source_type,
        policy_state=candidate.policy_state,
        category=candidate.category,
        rendered_text=_rendered_text(candidate),
        source_content=candidate.content,
        name=candidate.name,
        conditions=[
            RecommendationCondition(name=item.name, status=item.status, reason=item.reason)
            for item in candidate.conditions
        ],
        citation=_citation(candidate),
        provenance=candidate.provenance,
        urls=list(candidate.urls),
        cve_id=candidate.cve_id,
        advisory_id=candidate.advisory_id,
        technique_id=candidate.technique_id,
        mitigation_id=candidate.mitigation_id,
        deployment_applicability=candidate.deployment_applicability,
    )


def _rendered_text(candidate: RecommendationCandidate) -> str:
    if candidate.policy_state is RecommendationPolicyState.INFORMATIONAL:
        if candidate.category == "none_available":
            return "Source information: no remediation is available."
        return f"Source information: {candidate.content}" if candidate.content else "Source information: no remediation is available."
    if candidate.source_type == SOURCE_ATTACK:
        return _render_attack(candidate)
    return _render_csaf(candidate)


def _render_csaf(candidate: RecommendationCandidate) -> str:
    content = candidate.content
    if candidate.policy_state is RecommendationPolicyState.CONDITIONAL:
        prefix = _conditional_prefix(candidate)
        return (
            f"{prefix}: {_ensure_sentence(content)} "
            f"This recommendation is conditional because {render_condition_clause(candidate.conditions)}."
        )
    prefix = _eligible_prefix(candidate)
    if content:
        return f"{prefix}: {content}"
    return f"{prefix}:"


def _eligible_prefix(candidate: RecommendationCandidate) -> str:
    if candidate.scope == "advisory_level":
        if candidate.category == "vendor_fix":
            return "Advisory-level vendor remediation"
        if candidate.category == "workaround":
            return "Advisory-level workaround"
        return "Advisory-level mitigation"
    return _ELIGIBLE_PREFIX.get(candidate.category) or candidate.category


def _conditional_prefix(candidate: RecommendationCandidate) -> str:
    if candidate.scope == "advisory_level":
        return f"Conditional {_eligible_prefix(candidate).lower()}"
    return _CONDITIONAL_PREFIX.get(candidate.category) or f"Conditional {candidate.category}"


def _render_attack(candidate: RecommendationCandidate) -> str:
    name = candidate.name
    content = candidate.content
    if name and content:
        text = f"ATT&CK technique-level mitigation: {name}. {content}"
    elif name:
        text = f"ATT&CK technique-level mitigation: {name}."
    elif content:
        text = f"ATT&CK technique-level mitigation: {content}"
    else:
        text = "ATT&CK technique-level mitigation:"
    if candidate.deployment_applicability in {"", _UNKNOWN_DEPLOYMENT}:
        text = f"{_ensure_sentence(text)} Deployment-specific applicability is not confirmed."
    if candidate.cve_id:
        text = f"{_ensure_sentence(text)} CVE: {candidate.cve_id}."
    return text


def render_condition_explanations(conditions: list[RecommendationCondition]) -> list[str]:
    """Map Stage 5 conditions to concise user-facing phrases. Does not mutate inputs."""
    phrases: list[str] = []
    seen: set[str] = set()
    for item in conditions:
        if item.name == _GENERIC_UNRESOLVED_NAME:
            continue
        phrase = _user_facing_reason(item)
        if not phrase:
            continue
        key = phrase.casefold()
        if key in seen:
            continue
        seen.add(key)
        phrases.append(phrase)
    return phrases


def render_condition_clause(conditions: list[RecommendationCondition]) -> str:
    phrases = render_condition_explanations(conditions)
    if not phrases:
        return "applicability is unknown"
    if len(phrases) == 1:
        return phrases[0]
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}"
    return f"{', '.join(phrases[:-1])}, and {phrases[-1]}"


def _user_facing_reason(condition: RecommendationCondition) -> str:
    mapped = _DISPLAYABLE_CONDITION_NAMES.get(condition.name)
    if mapped:
        return mapped
    if condition.name == _GENERIC_UNRESOLVED_NAME:
        return ""
    phrase = _normalize_phrase(condition.reason)
    if not phrase:
        return ""
    lowered = phrase.casefold()
    if any(marker in lowered for marker in _INTERNAL_REASON_MARKERS):
        return ""
    if "trace" in lowered.split():
        return ""
    return phrase


def _normalize_phrase(text: str) -> str:
    phrase = " ".join(str(text or "").split()).strip()
    phrase = phrase.rstrip(".;:")
    if not phrase:
        return ""
    return phrase[:1].lower() + phrase[1:]


def _ensure_sentence(text: str) -> str:
    if not text:
        return ""
    if text.endswith((".", "!", "?")):
        return text
    return f"{text}."


def _citation(candidate: RecommendationCandidate) -> str:
    parts: list[str] = []
    if candidate.source_type == SOURCE_CSAF:
        if candidate.cve_id:
            parts.append(f"CVE: {candidate.cve_id}")
        if candidate.advisory_id:
            parts.append(f"Advisory: {candidate.advisory_id}")
    elif candidate.source_type == SOURCE_ATTACK:
        if candidate.technique_id:
            parts.append(f"Technique: {candidate.technique_id}")
        if candidate.mitigation_id:
            parts.append(f"ATT&CK mitigation: {candidate.mitigation_id}")
        if candidate.cve_id:
            parts.append(f"CVE: {candidate.cve_id}")
    if not parts:
        return ""
    return ". ".join(parts) + "."
