from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from rag.defense.inventory import inventory_step_evidence
from rag.defense.models import (
    CveRemediationRecord,
    DefenseSupportState,
    RemediationAction,
    StepRemediationInventory,
)
from rag.defense.validation import (
    is_positive_support,
    serialize_step_defense_evidence,
    validate_scenario_result,
    validate_step_evidence,
)
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.models import ScenarioNarrativeResult

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cisa_csaf"


def _check(name: str, status: TruthValue, reason: str = "") -> ApplicabilityCheck:
    return ApplicabilityCheck(name=name, status=status, reason=reason)


def _trace(
    product_id: str,
    *,
    matched: str = "model",
    conflict: str = "",
    polarity: str = "POSITIVE",
    provenance: str = "product_status.known_affected",
    source: str = "cisa_csaf",
    cve_id: str = "",
    final_product_state: str = "TRUE",
) -> dict:
    return {
        "source": source,
        "provenance": provenance,
        "scope": "cve_specific",
        "identity_origin": "product_tree_resolved",
        "evidence_strength": "SOURCE_MEMBERSHIP",
        "polarity": polarity,
        "matched_dimension": matched,
        "corroborating_evidence": "",
        "conflicting_evidence": conflict,
        "final_product_state": final_product_state,
        "product_id": product_id,
        "relationship_type": "",
        "version_constraint": "",
        "specificity_notes": [],
        "cve_id": cve_id,
    }


def _candidate(
    cve: str = "CVE-2030-80001",
    *,
    advisory: str | None = "ICSA-30-001-01",
    product: TruthValue = TruthValue.TRUE,
    version: TruthValue = TruthValue.TRUE,
    traces: list[dict] | None = None,
    unresolved: list[str] | None = None,
    final_status: str | None = None,
    disposition: str | None = None,
) -> CandidateEvidence:
    if version == TruthValue.TRUE and product == TruthValue.TRUE:
        status = final_status or "verified_applicable"
        disp = disposition or "applicable"
    elif product == TruthValue.FALSE:
        status = final_status or "rejected_product_mismatch"
        disp = disposition or "rejected"
    else:
        status = final_status or "conditional_version_unknown"
        disp = disposition or "conditional"
    return CandidateEvidence(
        cve_id=cve,
        advisory_id=advisory,
        disposition=disp,
        final_status=status,
        checks=[
            _check("product", product),
            _check("version", version),
            _check("technical_effect", TruthValue.TRUE),
        ],
        unresolved_conditions=list(unresolved or []),
        product_evidence_trace=list(traces if traces is not None else [_trace("CSAFPID-0001")]),
        lifecycle=["SELECTED"],
    )


def _step(
    *,
    step_id: str = "step-compromise",
    sequence: int = 5,
    selected: str | None = "CVE-2030-80001",
    candidates: list[CandidateEvidence] | None = None,
) -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        sequence=sequence,
        candidates=candidates if candidates is not None else [_candidate()],
        selected_cve=selected,
        selected_cves=[selected] if selected else [],
    )


def _record(
    *,
    cve: str = "CVE-2030-80001",
    advisory: str = "ICSA-30-001-01",
    source_path: str = "/tmp/remediation-inventory.json",
    actions: list[RemediationAction] | None = None,
    fixed: list[str] | None = None,
) -> CveRemediationRecord:
    return CveRemediationRecord(
        cve_id=cve,
        advisory_id=advisory,
        source_path=source_path,
        provenance=f"{advisory}::{cve}::{source_path}",
        remediations=list(actions or []),
        fixed_product_ids=list(fixed or []),
    )


def _inventory(
    step: StepEvidence,
    records: list[CveRemediationRecord],
    note: str = "",
) -> StepRemediationInventory:
    return StepRemediationInventory(
        step_id=step.step_id,
        sequence=step.sequence,
        selected_cve=step.selected_cve,
        advisory_id=step.candidates[0].advisory_id if step.candidates else None,
        records=records,
        note=note,
    )


def _validate(step: StepEvidence, records: list[CveRemediationRecord], note: str = ""):
    return validate_step_evidence([step], [_inventory(step, records, note=note)])[0]


def _status(row, category: str | None = None) -> DefenseSupportState:
    items = row.remediations
    if category is not None:
        items = [item for item in items if item.category == category]
    assert items
    return items[0].support_state


def _check_named(item, name: str) -> TruthValue:
    match = next(check for check in item.checks if check.name == name)
    return match.status


def _reason(item, name: str) -> str:
    return next(check for check in item.checks if check.name == name).reason


def test_supported_exact_cve_and_applicable_product():
    action = RemediationAction(
        category="vendor_fix",
        details="Update to V2.0.",
        product_ids=["CSAFPID-0001"],
        urls=["https://example.invalid/update"],
    )
    row = _validate(_step(), [_record(actions=[action])])
    item = row.remediations[0]
    assert item.support_state == DefenseSupportState.SUPPORTED
    assert item.category == "vendor_fix"
    assert _check_named(item, "cve_match") == TruthValue.TRUE
    assert _check_named(item, "product") == TruthValue.TRUE
    assert _check_named(item, "version") == TruthValue.TRUE
    assert _check_named(item, "remediation_scope") == TruthValue.TRUE
    assert _check_named(item, "source_conflict") == TruthValue.TRUE


def test_conditional_when_deployed_version_unknown():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(version=TruthValue.UNKNOWN)])
    row = _validate(step, [_record(actions=[action])])
    assert _status(row, "vendor_fix") == DefenseSupportState.CONDITIONAL
    assert _check_named(row.remediations[0], "version") == TruthValue.UNKNOWN


def test_rejected_when_remediation_product_conflicts():
    action = RemediationAction(category="vendor_fix", details="Update other product.", product_ids=["CSAFPID-9999"])
    row = _validate(_step(), [_record(actions=[action])])
    assert _status(row) == DefenseSupportState.REJECTED
    assert _check_named(row.remediations[0], "remediation_scope") == TruthValue.FALSE


def test_unresolved_remediation_scope_is_conditional_when_product_is_true():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(traces=[])])
    row = _validate(step, [_record(actions=[action])])
    item = row.remediations[0]
    assert _check_named(item, "cve_match") == TruthValue.TRUE
    assert _check_named(item, "product") == TruthValue.TRUE
    assert _check_named(item, "remediation_scope") == TruthValue.UNKNOWN
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state == DefenseSupportState.CONDITIONAL
    assert _reason(item, "remediation_scope") == "remediation product_ids cannot be related to selected product evidence"


def test_unresolved_scope_and_unknown_version_remain_conditional():
    candidate = _candidate(version=TruthValue.UNKNOWN, traces=[])
    candidate.checks = [
        _check("product", TruthValue.TRUE),
        _check("version", TruthValue.UNKNOWN, "The deployed version is unknown."),
        _check("technical_effect", TruthValue.TRUE),
    ]
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    item = _validate(_step(candidates=[candidate]), [_record(actions=[action])]).remediations[0]
    assert item.support_state == DefenseSupportState.CONDITIONAL
    assert _check_named(item, "version") == TruthValue.UNKNOWN
    assert _check_named(item, "remediation_scope") == TruthValue.UNKNOWN
    assert _reason(item, "version") == "The deployed version is unknown."
    assert _reason(item, "remediation_scope") == "remediation product_ids cannot be related to selected product evidence"


def test_unknown_product_and_unresolved_scope_remain_insufficient():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(product=TruthValue.UNKNOWN, traces=[])])
    item = _validate(step, [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "product") == TruthValue.UNKNOWN
    assert _check_named(item, "remediation_scope") == TruthValue.UNKNOWN
    assert item.support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE


def test_false_product_is_rejected():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(product=TruthValue.FALSE, traces=[])])
    item = _validate(step, [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "product") == TruthValue.FALSE
    assert item.support_state == DefenseSupportState.REJECTED


def test_conflicting_source_evidence_is_rejected():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(
        candidates=[
            _candidate(
                traces=[
                    _trace(
                        "CSAFPID-0001",
                        conflict="sibling_or_identity_mismatch",
                        provenance="ICSA-30-001-01::product_status.known_affected",
                    )
                ]
            )
        ]
    )
    item = _validate(step, [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.FALSE
    assert item.support_state == DefenseSupportState.REJECTED


def test_same_source_without_contradiction_keeps_source_conflict_true():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    item = _validate(_step(), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state == DefenseSupportState.SUPPORTED
    assert item.provenance == "ICSA-30-001-01::CVE-2030-80001::/tmp/remediation-inventory.json"


def test_unrelated_advisory_contradiction_does_not_reject():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-001-01::product_status.known_affected"),
        _trace(
            "CSAFPID-0001",
            conflict="contradictory_negative",
            polarity="NEGATIVE",
            provenance="ICSA-30-001-99::product_status.known_not_affected",
        ),
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state == DefenseSupportState.SUPPORTED


def test_unrelated_source_sibling_mismatch_does_not_reject():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-001-01::product_status.known_affected"),
        _trace(
            "CSAFPID-0001",
            matched="",
            conflict="sibling_or_identity_mismatch",
            provenance="ICSA-30-009-09::product_status.known_affected",
        ),
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state != DefenseSupportState.REJECTED


def test_same_source_unmatched_sibling_does_not_reject():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-001-01::product_status.known_affected"),
        _trace(
            "CSAFPID-0002",
            matched="",
            conflict="sibling_or_identity_mismatch",
            provenance="ICSA-30-001-01::product_status.known_affected",
        ),
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state == DefenseSupportState.SUPPORTED


def test_same_source_unmatched_identity_on_scoped_product_does_not_reject():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-009-09::product_status.known_affected"),
        _trace(
            "CSAFPID-0001",
            matched="",
            conflict="sibling_or_identity_mismatch",
            provenance="ICSA-30-001-01::product_status.known_affected",
        ),
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.TRUE
    assert item.support_state != DefenseSupportState.REJECTED


def test_same_source_known_not_affected_is_rejected():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-001-01::product_status.known_affected"),
        _trace(
            "CSAFPID-0001",
            polarity="NEGATIVE",
            conflict="contradictory_negative",
            provenance="ICSA-30-001-01::product_status.known_not_affected",
        ),
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.FALSE
    assert item.support_state == DefenseSupportState.REJECTED


def test_same_source_conflicting_exact_product_is_rejected():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    traces = [
        _trace(
            "CSAFPID-0001",
            conflict="contradictory_negative",
            provenance="ICSA-30-001-01::product_status.known_affected",
        )
    ]
    item = _validate(_step(candidates=[_candidate(traces=traces)]), [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "source_conflict") == TruthValue.FALSE
    assert item.support_state == DefenseSupportState.REJECTED


def test_multiple_sources_validate_conflicts_independently():
    traces = [
        _trace("CSAFPID-0001", provenance="ICSA-30-001-01::product_status.known_affected"),
        _trace(
            "CSAFPID-0001",
            conflict="sibling_or_identity_mismatch",
            provenance="ICSA-30-001-02::product_status.known_affected",
        ),
    ]
    step = _step(candidates=[_candidate(traces=traces)])
    primary = _record(advisory="ICSA-30-001-01", source_path="/tmp/a.json", actions=[
        RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    ])
    alternate = _record(advisory="ICSA-30-001-02", source_path="/tmp/b.json", actions=[
        RemediationAction(category="vendor_fix", details="Apply vendor package 2.0.1.", product_ids=["CSAFPID-0001"])
    ])
    row = _validate(step, [primary, alternate])
    by_advisory = {item.advisory_id: item for item in row.remediations}
    assert by_advisory["ICSA-30-001-01"].support_state == DefenseSupportState.SUPPORTED
    assert _check_named(by_advisory["ICSA-30-001-01"], "source_conflict") == TruthValue.TRUE
    assert by_advisory["ICSA-30-001-02"].support_state == DefenseSupportState.REJECTED
    assert _check_named(by_advisory["ICSA-30-001-02"], "source_conflict") == TruthValue.FALSE
    assert by_advisory["ICSA-30-001-01"].provenance != by_advisory["ICSA-30-001-02"].provenance
    assert by_advisory["ICSA-30-001-01"].provenance.endswith("/tmp/a.json")
    assert by_advisory["ICSA-30-001-02"].provenance.endswith("/tmp/b.json")


def test_unknown_fixed_scope_does_not_suppress_conditional_remediation():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(version=TruthValue.UNKNOWN)])
    item = _validate(step, [_record(actions=[action], fixed=[])]).remediations[0]
    assert _check_named(item, "remediation_scope") == TruthValue.TRUE
    assert _check_named(item, "fixed_scope") == TruthValue.UNKNOWN
    assert item.support_state == DefenseSupportState.CONDITIONAL
    assert item.support_state != DefenseSupportState.INSUFFICIENT_EVIDENCE


def test_mitigation_and_workaround_unresolved_scope_are_conditional():
    for category, details in (
        ("mitigation", "Restrict management-plane access."),
        ("workaround", "Disable unused services."),
    ):
        action = RemediationAction(category=category, details=details, product_ids=["CSAFPID-0001"])
        item = _validate(_step(candidates=[_candidate(traces=[])]), [_record(actions=[action])]).remediations[0]
        assert item.category == category
        assert _check_named(item, "remediation_scope") == TruthValue.UNKNOWN
        assert item.support_state == DefenseSupportState.CONDITIONAL


def test_vendor_fix_unknown_version_is_not_automatically_supported():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(version=TruthValue.UNKNOWN)])
    row = _validate(step, [_record(actions=[action])])
    assert row.remediations[0].support_state != DefenseSupportState.SUPPORTED
    assert row.remediations[0].support_state == DefenseSupportState.CONDITIONAL
    assert row.remediations[0].category == "vendor_fix"


def test_mitigation_preserves_category_and_validates_independently():
    action = RemediationAction(
        category="mitigation",
        details="Restrict management-plane access to authorized operators.",
        product_ids=["CSAFPID-0001"],
    )
    row = _validate(_step(), [_record(actions=[action])])
    item = row.remediations[0]
    assert item.category == "mitigation"
    assert item.support_state == DefenseSupportState.SUPPORTED
    assert item.category != "vendor_fix"


def test_workaround_preserves_workaround_semantics():
    action = RemediationAction(
        category="workaround",
        details="Disable unused services until the update is applied.",
        product_ids=["CSAFPID-0001"],
    )
    row = _validate(_step(), [_record(actions=[action])])
    item = row.remediations[0]
    assert item.category == "workaround"
    assert item.support_state == DefenseSupportState.SUPPORTED


def test_none_available_is_never_positive_support():
    action = RemediationAction(category="none_available", details="Currently no fix is available")
    row = _validate(_step(), [_record(actions=[action])])
    item = row.remediations[0]
    assert item.category == "none_available"
    assert item.support_state == DefenseSupportState.NOT_APPLICABLE
    assert not is_positive_support(item.support_state)
    assert item.support_state != DefenseSupportState.SUPPORTED


def test_fixed_product_ids_matching_selected_deployment():
    action = RemediationAction(category="vendor_fix", details="Install the fixed build.", product_ids=["CSAFPID-0002"])
    step = _step(candidates=[_candidate(traces=[_trace("CSAFPID-0002")])])
    row = _validate(step, [_record(actions=[action], fixed=["CSAFPID-0002"])])
    item = row.remediations[0]
    assert _check_named(item, "fixed_scope") == TruthValue.TRUE
    assert _check_named(item, "remediation_scope") == TruthValue.TRUE
    assert item.support_state == DefenseSupportState.SUPPORTED


def test_fixed_product_ids_conflicting_deployment():
    action = RemediationAction(category="vendor_fix", details="Install the fixed build.", product_ids=["CSAFPID-0002"])
    step = _step(candidates=[_candidate(traces=[_trace("CSAFPID-0001")])])
    row = _validate(step, [_record(actions=[action], fixed=["CSAFPID-0002"])])
    item = row.remediations[0]
    assert _check_named(item, "remediation_scope") == TruthValue.FALSE
    assert _check_named(item, "fixed_scope") != TruthValue.TRUE
    assert item.support_state == DefenseSupportState.REJECTED


def test_multiple_csaf_sources_remain_independent():
    step = _step(candidates=[_candidate(version=TruthValue.UNKNOWN)])
    inventory = inventory_step_evidence([step], FIXTURES)
    assert len(inventory) == 1
    records = inventory[0].records
    assert len(records) >= 2

    source_paths = [item.source_path for item in records]
    provenances = [item.provenance for item in records]
    assert len(source_paths) == len(set(source_paths))
    assert len(provenances) == len(set(provenances))
    primary_record = next(item for item in records if item.advisory_id == "ICSA-30-001-01")
    alternate_record = next(item for item in records if item.advisory_id == "ICSA-30-001-02")
    assert Path(primary_record.source_path).name == "remediation-inventory.json"
    assert Path(alternate_record.source_path).name == "remediation-inventory-alt.json"
    assert primary_record.source_path != alternate_record.source_path
    assert primary_record.provenance != alternate_record.provenance
    assert primary_record.provenance == (
        f"{primary_record.advisory_id}::{primary_record.cve_id}::{primary_record.source_path}"
    )
    assert alternate_record.provenance == (
        f"{alternate_record.advisory_id}::{alternate_record.cve_id}::{alternate_record.source_path}"
    )
    assert [item.category for item in primary_record.remediations if item.category == "vendor_fix"] == ["vendor_fix"]

    row = validate_step_evidence([step], inventory)[0]
    again = validate_step_evidence([step], inventory)[0]
    assert row.remediations
    for item in row.remediations:
        assert item.source_path
        assert item.provenance
        assert item.provenance == f"{item.advisory_id}::{item.cve_id}::{item.source_path}"

    by_source: dict[str, list] = {}
    for item in row.remediations:
        by_source.setdefault(item.source_path, []).append(item)
    assert set(by_source) == {primary_record.source_path, alternate_record.source_path}

    primary_items = by_source[primary_record.source_path]
    alternate_items = by_source[alternate_record.source_path]
    assert [(item.category, item.details) for item in primary_items] == [
        ("vendor_fix", "Update to V2.0."),
        ("mitigation", "Restrict management-plane access to authorized operators."),
        ("workaround", "Disable unused services until the update is applied."),
    ]
    assert [(item.category, item.details) for item in alternate_items] == [
        ("vendor_fix", "Apply vendor package 2.0.1."),
    ]
    assert primary_items[0].details != alternate_items[0].details
    assert {item.provenance for item in primary_items} == {primary_record.provenance}
    assert {item.provenance for item in alternate_items} == {alternate_record.provenance}

    identity_keys = [(item.source_path, item.category, item.details) for item in row.remediations]
    assert len(identity_keys) == len(set(identity_keys))

    first_order = [(item.source_path, item.provenance, item.category, item.details) for item in row.remediations]
    second_order = [(item.source_path, item.provenance, item.category, item.details) for item in again.remediations]
    assert first_order == second_order
    assert first_order == [
        (primary_record.source_path, primary_record.provenance, "vendor_fix", "Update to V2.0."),
        (
            primary_record.source_path,
            primary_record.provenance,
            "mitigation",
            "Restrict management-plane access to authorized operators.",
        ),
        (
            primary_record.source_path,
            primary_record.provenance,
            "workaround",
            "Disable unused services until the update is applied.",
        ),
        (alternate_record.source_path, alternate_record.provenance, "vendor_fix", "Apply vendor package 2.0.1."),
    ]
    assert primary_items[0].support_state == DefenseSupportState.CONDITIONAL
    assert alternate_items[0].support_state == DefenseSupportState.CONDITIONAL


def test_malformed_optional_fields_do_not_crash():
    step = _step(
        candidates=[
            CandidateEvidence(
                cve_id="CVE-2030-80001",
                advisory_id=None,
                disposition="conditional",
                checks=[],
                product_evidence_trace=["not-a-dict", None, {"product_id": None}],
            )
        ]
    )
    records = [
        _record(
            actions=[
                RemediationAction(category="", details="", product_ids=[], urls=[], group_ids=[]),
            ],
            fixed=[],
        )
    ]
    row = _validate(step, records)
    assert row.remediations
    assert row.remediations[0].support_state in {
        DefenseSupportState.INSUFFICIENT_EVIDENCE,
        DefenseSupportState.CONDITIONAL,
        DefenseSupportState.REJECTED,
        DefenseSupportState.NOT_APPLICABLE,
        DefenseSupportState.SUPPORTED,
    }


def test_no_selected_cve_yields_empty_validated_remediations():
    step = _step(selected=None, candidates=[])
    row = _validate(step, [], note="no_selected_cve")
    assert row.selected_cve is None
    assert row.remediations == []
    assert row.note == "no_selected_cve"


def test_no_stage1_remediation_evidence_yields_empty_result():
    row = _validate(_step(), [], note="csaf_not_found")
    assert row.remediations == []
    assert row.note == "csaf_not_found"


def test_deterministic_ordering():
    actions = [
        RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"]),
        RemediationAction(category="mitigation", details="Restrict access.", product_ids=["CSAFPID-0001"]),
        RemediationAction(category="workaround", details="Disable unused services.", product_ids=["CSAFPID-0001"]),
    ]
    record_b = _record(advisory="ICSA-30-001-02", source_path="/tmp/b.json", actions=[actions[0]])
    record_a = _record(advisory="ICSA-30-001-01", source_path="/tmp/a.json", actions=actions)
    first = _validate(_step(), [record_a, record_b])
    second = _validate(_step(), [record_a, record_b])
    assert [item.provenance for item in first.remediations] == [item.provenance for item in second.remediations]
    assert [item.category for item in first.remediations] == [
        "vendor_fix",
        "mitigation",
        "workaround",
        "vendor_fix",
    ]
    assert [item.category for item in first.remediations] == [item.category for item in second.remediations]


def test_deterministic_serialization():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step()
    first = validate_step_evidence([step], [_inventory(step, [_record(actions=[action])])])
    second = validate_step_evidence([step], [_inventory(step, [_record(actions=[action])])])
    assert serialize_step_defense_evidence(first) == serialize_step_defense_evidence(second)
    encoded = serialize_step_defense_evidence(first)
    assert "supported" in encoded
    assert "recommend" not in encoded.lower()
    assert "You should" not in encoded


def test_validation_does_not_mutate_inputs():
    candidate = _candidate(version=TruthValue.UNKNOWN)
    step = _step(candidates=[candidate])
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    record = _record(actions=[action], fixed=["CSAFPID-0002"])
    inventory = _inventory(step, [record])
    result = ScenarioNarrativeResult(
        scenario_id="DEF-2",
        title="Defense validation",
        narrative="placeholder",
        evidence=[step],
    )
    result_evidence_id = id(result.evidence)
    step_id = id(step)
    candidate_id = id(candidate)
    record_id = id(record)
    action_id = id(action)
    lifecycle_before = list(candidate.lifecycle)
    traces_before = deepcopy(candidate.product_evidence_trace)
    checks_before = [(item.name, item.status) for item in candidate.checks]
    record_before = record.to_dict()
    inventory_before = inventory.to_dict()
    rows = validate_scenario_result(result, [inventory])
    assert result.narrative == "placeholder"
    assert id(result.evidence) == result_evidence_id
    assert id(result.evidence[0]) == step_id
    assert id(result.evidence[0].candidates[0]) == candidate_id
    assert id(inventory.records[0]) == record_id
    assert id(inventory.records[0].remediations[0]) == action_id
    assert candidate.lifecycle == lifecycle_before
    assert candidate.product_evidence_trace == traces_before
    assert [(item.name, item.status) for item in candidate.checks] == checks_before
    assert record.to_dict() == record_before
    assert inventory.to_dict() == inventory_before
    assert rows[0].remediations
    assert rows[0].remediations[0] is not action
    assert rows[0].remediations[0] is not record


def test_unknown_is_not_collapsed_to_true_or_false():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(version=TruthValue.UNKNOWN)])
    item = _validate(step, [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "version") == TruthValue.UNKNOWN
    assert item.support_state == DefenseSupportState.CONDITIONAL
    assert _check_named(item, "version") != TruthValue.TRUE
    assert _check_named(item, "version") != TruthValue.FALSE


def test_family_only_trace_does_not_create_positive_scope():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    step = _step(candidates=[_candidate(traces=[_trace("CSAFPID-0001", matched="family")])])
    item = _validate(step, [_record(actions=[action])]).remediations[0]
    assert _check_named(item, "remediation_scope") == TruthValue.UNKNOWN
    assert item.support_state == DefenseSupportState.CONDITIONAL
    assert item.support_state != DefenseSupportState.SUPPORTED


def test_textual_product_fields_do_not_masquerade_as_csaf_product_ids():
    action = RemediationAction(category="vendor_fix", details="Update to V2.0.", product_ids=["CSAFPID-0001"])
    masquerade = _trace("", matched="product_name")
    masquerade["product_name"] = "CSAFPID-0001"
    masquerade["model"] = "CSAFPID-0001"
    masquerade["part_number"] = "CSAFPID-0001"
    unresolved = _validate(_step(candidates=[_candidate(traces=[masquerade])]), [_record(actions=[action])])
    assert _check_named(unresolved.remediations[0], "remediation_scope") == TruthValue.UNKNOWN
    assert unresolved.remediations[0].support_state == DefenseSupportState.CONDITIONAL
    assert unresolved.remediations[0].support_state != DefenseSupportState.SUPPORTED

    mapped = _trace("CSAFPID-0001", matched="model")
    mapped["product_name"] = "FlowMaster X100"
    mapped["model"] = "X100"
    mapped["part_number"] = "PN-1"
    joined = _validate(_step(candidates=[_candidate(traces=[mapped])]), [_record(actions=[action])])
    assert _check_named(joined.remediations[0], "remediation_scope") == TruthValue.TRUE
    assert joined.remediations[0].support_state == DefenseSupportState.SUPPORTED
