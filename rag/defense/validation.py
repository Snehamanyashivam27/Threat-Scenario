from __future__ import annotations

"""Deterministic defense-support validation.

Compares Stage 1 CSAF remediation evidence against already-validated scenario
and CVE applicability facts. Does not generate recommendation prose, rank
sources, mutate inputs, or participate in threat generation.
"""

import json

from rag.defense.models import (
    CveRemediationRecord,
    DefenseApplicabilityCheck,
    DefenseSupportState,
    RemediationAction,
    StepDefenseEvidence,
    StepRemediationInventory,
    ValidatedRemediation,
)
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.models import ScenarioNarrativeResult
from rag.utils.text import dedupe_preserve_order

_EXACT_MATCH_DIMENSIONS = frozenset({"model", "part_number", "product_name", "relationship"})
_CHECK_ORDER = (
    "cve_match",
    "advisory_match",
    "product",
    "version",
    "remediation_scope",
    "fixed_scope",
    "source_conflict",
    "unresolved_conditions",
)
_POSITIVE_STATES = frozenset(
    {
        DefenseSupportState.SUPPORTED,
        DefenseSupportState.CONDITIONAL,
    }
)
_SCOPE_CONDITIONAL_CATEGORIES = frozenset({"vendor_fix", "mitigation", "workaround"})


def validate_scenario_result(
    result: ScenarioNarrativeResult,
    inventory: list[StepRemediationInventory],
) -> list[StepDefenseEvidence]:
    return validate_step_evidence(result.evidence, inventory)


def validate_step_evidence(
    evidence: list[StepEvidence],
    inventory: list[StepRemediationInventory],
) -> list[StepDefenseEvidence]:
    inventory_by_key = {(row.step_id, row.sequence): row for row in inventory}
    rows: list[StepDefenseEvidence] = []
    for step in evidence:
        row = inventory_by_key.get((step.step_id, step.sequence))
        rows.append(_validate_step(step, row))
    return rows


def serialize_step_defense_evidence(rows: list[StepDefenseEvidence]) -> str:
    return json.dumps(
        [row.to_dict() for row in rows],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _validate_step(
    step: StepEvidence,
    inventory: StepRemediationInventory | None,
) -> StepDefenseEvidence:
    selected = _selected_cve(step)
    if inventory is None:
        return StepDefenseEvidence(
            step_id=step.step_id,
            sequence=step.sequence,
            selected_cve=selected,
            advisory_id=None,
            note="no_selected_cve" if not selected else "",
            remediations=[],
            source_conflict=False,
        )
    if not selected or not inventory.selected_cve:
        return StepDefenseEvidence(
            step_id=step.step_id,
            sequence=step.sequence,
            selected_cve=None,
            advisory_id=None,
            note=inventory.note or "no_selected_cve",
            remediations=[],
            source_conflict=False,
        )
    candidate = _selected_candidate(step, selected)
    validated: list[ValidatedRemediation] = []
    for record in inventory.records:
        if record.remediations:
            for action in record.remediations:
                validated.append(_validate_action(selected, candidate, record, action))
            continue
        if record.fixed_product_ids:
            validated.append(
                _validate_action(
                    selected,
                    candidate,
                    record,
                    RemediationAction(category="", details=""),
                )
            )
    return StepDefenseEvidence(
        step_id=step.step_id,
        sequence=step.sequence,
        selected_cve=selected,
        advisory_id=inventory.advisory_id,
        note=inventory.note,
        remediations=validated,
        source_conflict=_cross_source_conflict(validated),
    )


def _validate_action(
    selected_cve: str,
    candidate: CandidateEvidence | None,
    record: CveRemediationRecord,
    action: RemediationAction,
) -> ValidatedRemediation:
    selected_ids = _selected_matching_product_ids(candidate)
    by_name = {
        "cve_match": _cve_match_check(selected_cve, record.cve_id),
        "advisory_match": _advisory_match_check(candidate, record.advisory_id),
        "product": _copy_candidate_check(candidate, "product"),
        "version": _copy_candidate_check(candidate, "version"),
        "remediation_scope": _scope_check(
            name="remediation_scope",
            scope_ids=list(action.product_ids),
            selected_ids=selected_ids,
            empty_reason="remediation is not product-scoped",
            overlap_reason="remediation product_ids overlap selected product evidence",
            conflict_reason="remediation product_ids conflict with selected product evidence",
            unresolved_reason="remediation product_ids cannot be related to selected product evidence",
        ),
        "fixed_scope": _scope_check(
            name="fixed_scope",
            scope_ids=list(record.fixed_product_ids),
            selected_ids=selected_ids,
            empty_reason="no fixed product_ids in source record",
            overlap_reason="fixed_product_ids overlap selected product evidence",
            conflict_reason="fixed_product_ids do not include the selected product",
            unresolved_reason="fixed_product_ids cannot be related to selected product evidence",
            disjoint_is_unknown=True,
        ),
        "source_conflict": _source_conflict_check(candidate, action, selected_ids, record),
        "unresolved_conditions": _unresolved_check(candidate),
    }
    checks = [by_name[name] for name in _CHECK_ORDER]
    state = _roll_up(action.category, checks)
    return ValidatedRemediation(
        cve_id=record.cve_id,
        advisory_id=record.advisory_id,
        source_path=record.source_path,
        provenance=record.provenance,
        category=action.category,
        details=action.details,
        urls=list(action.urls),
        product_ids=list(action.product_ids),
        group_ids=list(action.group_ids),
        fixed_product_ids=list(record.fixed_product_ids),
        support_state=state,
        checks=checks,
    )


def _cve_match_check(selected_cve: str, record_cve: str) -> DefenseApplicabilityCheck:
    selected = (selected_cve or "").upper()
    observed = (record_cve or "").upper()
    if not selected:
        status = TruthValue.UNKNOWN
        reason = "no selected CVE"
    elif observed == selected:
        status = TruthValue.TRUE
        reason = "exact selected CVE match"
    else:
        status = TruthValue.FALSE
        reason = "remediation CVE does not match selected CVE"
    return DefenseApplicabilityCheck(
        name="cve_match",
        status=status,
        required=selected,
        observed=observed,
        reason=reason,
    )


def _advisory_match_check(
    candidate: CandidateEvidence | None,
    record_advisory: str,
) -> DefenseApplicabilityCheck:
    required = ((candidate.advisory_id if candidate else None) or "").upper()
    observed = (record_advisory or "").upper()
    if not required or not observed:
        status = TruthValue.UNKNOWN
        reason = "advisory identity is not available on both sides"
    elif required == observed:
        status = TruthValue.TRUE
        reason = "exact advisory identity match"
    else:
        status = TruthValue.FALSE
        reason = "source advisory differs from selected CVE advisory"
    return DefenseApplicabilityCheck(
        name="advisory_match",
        status=status,
        required=required,
        observed=observed,
        reason=reason,
    )


def _copy_candidate_check(
    candidate: CandidateEvidence | None,
    name: str,
) -> DefenseApplicabilityCheck:
    match = _candidate_check(candidate, name)
    if match is None:
        return DefenseApplicabilityCheck(
            name=name,
            status=TruthValue.UNKNOWN,
            reason="candidate check not present",
        )
    return DefenseApplicabilityCheck(
        name=name,
        status=match.status,
        required=match.required,
        observed=match.observed,
        reason=match.reason,
    )


def _scope_check(
    *,
    name: str,
    scope_ids: list[str],
    selected_ids: list[str],
    empty_reason: str,
    overlap_reason: str,
    conflict_reason: str,
    unresolved_reason: str,
    disjoint_is_unknown: bool = False,
) -> DefenseApplicabilityCheck:
    scoped = dedupe_preserve_order([item for item in scope_ids if item])
    selected = dedupe_preserve_order([item for item in selected_ids if item])
    observed = ";".join(scoped)
    required = ";".join(selected)
    if not scoped:
        return DefenseApplicabilityCheck(
            name=name,
            status=TruthValue.TRUE if name == "remediation_scope" else TruthValue.UNKNOWN,
            required=required,
            observed=observed,
            reason=empty_reason,
        )
    if not selected:
        return DefenseApplicabilityCheck(
            name=name,
            status=TruthValue.UNKNOWN,
            required=required,
            observed=observed,
            reason=unresolved_reason,
        )
    if _ids_overlap(scoped, selected):
        return DefenseApplicabilityCheck(
            name=name,
            status=TruthValue.TRUE,
            required=required,
            observed=observed,
            reason=overlap_reason,
        )
    if disjoint_is_unknown:
        return DefenseApplicabilityCheck(
            name=name,
            status=TruthValue.UNKNOWN,
            required=required,
            observed=observed,
            reason=conflict_reason + "; disjoint fixed ids are not treated as a contradiction",
        )
    return DefenseApplicabilityCheck(
        name=name,
        status=TruthValue.FALSE,
        required=required,
        observed=observed,
        reason=conflict_reason,
    )


def _source_conflict_check(
    candidate: CandidateEvidence | None,
    action: RemediationAction,
    selected_ids: list[str],
    record: CveRemediationRecord,
) -> DefenseApplicabilityCheck:
    if candidate is None:
        return DefenseApplicabilityCheck(
            name="source_conflict",
            status=TruthValue.UNKNOWN,
            reason="selected candidate is not available",
        )
    if candidate.final_status == "conflicting_evidence":
        return DefenseApplicabilityCheck(
            name="source_conflict",
            status=TruthValue.FALSE,
            observed=candidate.final_status,
            reason="selected candidate has conflicting_evidence",
        )
    product = _candidate_check(candidate, "product")
    if product is not None and product.status == TruthValue.CONFLICT:
        return DefenseApplicabilityCheck(
            name="source_conflict",
            status=TruthValue.FALSE,
            observed=product.status.value,
            reason="selected product applicability is conflicting",
        )
    action_ids = {item for item in action.product_ids if item}
    del selected_ids
    for trace in candidate.product_evidence_trace:
        if not isinstance(trace, dict):
            continue
        if not _trace_is_in_record_context(trace, record):
            continue
        if not _trace_is_relevant_conflict(trace, action_ids):
            continue
        conflict = str(trace.get("conflicting_evidence") or "")
        product_id = str(trace.get("product_id") or "")
        observed = conflict or str(trace.get("polarity") or "")
        return DefenseApplicabilityCheck(
            name="source_conflict",
            status=TruthValue.FALSE,
            observed=observed,
            required=product_id,
            reason="selected product evidence records a contradiction",
        )
    return DefenseApplicabilityCheck(
        name="source_conflict",
        status=TruthValue.TRUE,
        reason="no source contradiction in selected evidence",
    )


def _trace_is_in_record_context(trace: dict, record: CveRemediationRecord) -> bool:
    trace_cve = str(trace.get("cve_id") or "").strip().upper()
    record_cve = (record.cve_id or "").strip().upper()
    if trace_cve and record_cve and trace_cve != record_cve:
        return False
    trace_advisory = _trace_advisory_id(trace)
    record_advisory = (record.advisory_id or "").strip().upper()
    if trace_advisory and record_advisory:
        return trace_advisory == record_advisory
    if trace_advisory and not record_advisory:
        return False
    return True


def _trace_advisory_id(trace: dict) -> str:
    explicit = str(trace.get("advisory_id") or "").strip().upper()
    if explicit:
        return explicit
    provenance = str(trace.get("provenance") or "").strip()
    if not provenance:
        return ""
    prefix = provenance.split("::", 1)[0].strip().upper()
    if _looks_like_advisory_id(prefix):
        return prefix
    return ""


def _looks_like_advisory_id(value: str) -> bool:
    return value.startswith(("ICSA-", "ICSMA-", "ICSALERT-", "SSA-"))


def _trace_is_relevant_conflict(trace: dict, action_ids: set[str]) -> bool:
    conflict = str(trace.get("conflicting_evidence") or "").strip()
    polarity = str(trace.get("polarity") or "POSITIVE").upper()
    strength = str(trace.get("evidence_strength") or "").upper()
    matched = str(trace.get("matched_dimension") or "")
    product_id = str(trace.get("product_id") or "").strip()
    final_state = str(trace.get("final_product_state") or "").upper()
    if action_ids and product_id and product_id not in action_ids:
        return False
    if polarity == "NEGATIVE" or strength == "NEGATIVE":
        return True
    if final_state in {"FALSE", "CONFLICTING_EVIDENCE", "CONFLICT"}:
        return True
    if not conflict:
        return False
    if conflict == "sibling_or_identity_mismatch" and matched not in _EXACT_MATCH_DIMENSIONS:
        return False
    return True


def _unresolved_check(candidate: CandidateEvidence | None) -> DefenseApplicabilityCheck:
    if candidate is None:
        return DefenseApplicabilityCheck(
            name="unresolved_conditions",
            status=TruthValue.UNKNOWN,
            reason="selected candidate is not available",
        )
    conditions = list(candidate.unresolved_conditions)
    if conditions:
        return DefenseApplicabilityCheck(
            name="unresolved_conditions",
            status=TruthValue.UNKNOWN,
            observed="; ".join(conditions),
            reason="selected CVE has unresolved conditions",
        )
    return DefenseApplicabilityCheck(
        name="unresolved_conditions",
        status=TruthValue.TRUE,
        reason="no unresolved conditions on selected CVE",
    )


def _roll_up(category: str, checks: list[DefenseApplicabilityCheck]) -> DefenseSupportState:
    status = {item.name: item.status for item in checks}
    cve_match = status["cve_match"]
    product = status["product"]
    version = status["version"]
    remediation_scope = status["remediation_scope"]
    fixed_scope = status["fixed_scope"]
    source_conflict = status["source_conflict"]
    unresolved = status["unresolved_conditions"]
    advisory_match = status["advisory_match"]

    if _false_or_conflict(cve_match):
        return DefenseSupportState.REJECTED
    if _false_or_conflict(product) or _false_or_conflict(remediation_scope):
        return DefenseSupportState.REJECTED
    if _false_or_conflict(source_conflict):
        return DefenseSupportState.REJECTED
    if _false_or_conflict(version):
        return DefenseSupportState.REJECTED
    if category == "none_available":
        return DefenseSupportState.NOT_APPLICABLE
    if product == TruthValue.UNKNOWN:
        return DefenseSupportState.INSUFFICIENT_EVIDENCE
    if (
        category in _SCOPE_CONDITIONAL_CATEGORIES
        and cve_match == TruthValue.TRUE
        and product == TruthValue.TRUE
        and remediation_scope == TruthValue.UNKNOWN
        and fixed_scope in {TruthValue.TRUE, TruthValue.UNKNOWN}
    ):
        return DefenseSupportState.CONDITIONAL
    if remediation_scope == TruthValue.UNKNOWN and fixed_scope != TruthValue.TRUE:
        return DefenseSupportState.INSUFFICIENT_EVIDENCE
    if version == TruthValue.UNKNOWN or unresolved == TruthValue.UNKNOWN:
        return DefenseSupportState.CONDITIONAL
    if advisory_match == TruthValue.FALSE:
        return DefenseSupportState.CONDITIONAL
    if remediation_scope == TruthValue.TRUE or fixed_scope == TruthValue.TRUE:
        return DefenseSupportState.SUPPORTED
    return DefenseSupportState.INSUFFICIENT_EVIDENCE


def _selected_matching_product_ids(candidate: CandidateEvidence | None) -> list[str]:
    if candidate is None:
        return []
    ids: list[str] = []
    for trace in candidate.product_evidence_trace:
        if not isinstance(trace, dict):
            continue
        product_id = str(trace.get("product_id") or "").strip()
        if not product_id:
            continue
        polarity = str(trace.get("polarity") or "POSITIVE")
        strength = str(trace.get("evidence_strength") or "")
        if polarity == "NEGATIVE" or strength == "NEGATIVE":
            continue
        if str(trace.get("conflicting_evidence") or ""):
            continue
        matched = str(trace.get("matched_dimension") or "")
        if matched not in _EXACT_MATCH_DIMENSIONS:
            continue
        ids.append(product_id)
    return dedupe_preserve_order(ids)


def _selected_cve(step: StepEvidence) -> str | None:
    raw = step.selected_cve or (step.selected_cves[0] if step.selected_cves else None)
    if not raw:
        return None
    return str(raw).upper()


def _selected_candidate(step: StepEvidence, cve_id: str) -> CandidateEvidence | None:
    for candidate in step.candidates:
        if candidate.cve_id.upper() == cve_id:
            return candidate
    return None


def _candidate_check(candidate: CandidateEvidence | None, name: str) -> ApplicabilityCheck | None:
    if candidate is None:
        return None
    return next((item for item in candidate.checks if item.name == name), None)


def _ids_overlap(left: list[str], right: list[str]) -> bool:
    right_set = set(right)
    return any(item in right_set for item in left)


def _false_or_conflict(status: TruthValue) -> bool:
    return status in {TruthValue.FALSE, TruthValue.CONFLICT}


def _cross_source_conflict(items: list[ValidatedRemediation]) -> bool:
    if any(item.support_state == DefenseSupportState.REJECTED and _check_status(item, "source_conflict") == TruthValue.FALSE for item in items):
        return True
    categories_by_provenance: dict[str, list[str]] = {}
    for item in items:
        categories_by_provenance.setdefault(item.provenance, [])
        if item.category and item.category not in categories_by_provenance[item.provenance]:
            categories_by_provenance[item.provenance].append(item.category)
    if len(categories_by_provenance) < 2:
        return False
    all_categories: list[str] = []
    for provenance in sorted(categories_by_provenance):
        for category in categories_by_provenance[provenance]:
            if category not in all_categories:
                all_categories.append(category)
    return "none_available" in all_categories and any(item != "none_available" for item in all_categories)


def _check_status(item: ValidatedRemediation, name: str) -> TruthValue | None:
    match = next((check for check in item.checks if check.name == name), None)
    return match.status if match else None


def is_positive_support(state: DefenseSupportState) -> bool:
    return state in _POSITIVE_STATES
