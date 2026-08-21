from __future__ import annotations

from pathlib import Path

from rag.defense.csaf_remediation import load_csaf_remediation_records
from rag.defense.models import (
    CveRemediationRecord,
    DefenseSupportState,
    RemediationAction,
    StepRemediationInventory,
)
from rag.defense.product_binding import (
    SCOPE_ADVISORY_LEVEL,
    SCOPE_PRODUCT_SPECIFIC,
    classify_actionability,
    classify_remediation_scope,
)
from rag.defense.recommendation_policy import apply_recommendation_policy
from rag.defense.recommendation_renderer import render_actionable_recommendations
from rag.defense.report_pipeline import format_defense_recommendations
from rag.defense.unified_evidence import unify_step_defense_evidence
from rag.defense.validation import validate_step_evidence
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue

ROOT = Path(__file__).resolve().parents[1]
CSAF_DIR = ROOT / "data" / "cisa_csaf"


def _check(name: str, status: TruthValue, observed: str = "", required: str = "", reason: str = "") -> ApplicabilityCheck:
    return ApplicabilityCheck(name=name, status=status, required=required, observed=observed, reason=reason)


def _trace(product_id: str, *, matched: str = "model", product_name: str = "", model: str = "") -> dict:
    return {
        "source": "cisa_csaf",
        "provenance": "product_status.known_affected",
        "scope": "cve_specific",
        "identity_origin": "product_tree_resolved",
        "evidence_strength": "SOURCE_MEMBERSHIP",
        "polarity": "POSITIVE",
        "matched_dimension": matched,
        "corroborating_evidence": "",
        "conflicting_evidence": "",
        "final_product_state": "TRUE",
        "product_id": product_id,
        "product_name": product_name,
        "model": model,
        "part_number": "",
        "relationship_type": "",
        "version_constraint": "",
        "specificity_notes": [],
    }


def _candidate(
    *,
    name: str = "FlowMaster X100",
    model: str = "FlowMaster X100",
    family: str = "FlowMaster",
    product: TruthValue = TruthValue.TRUE,
    version: TruthValue = TruthValue.TRUE,
    traces: list[dict] | None = None,
    cve: str = "CVE-2030-80001",
    advisory: str = "ICSA-30-001-01",
) -> CandidateEvidence:
    observed = " | ".join(dict.fromkeys(part for part in (model, name, family) if part))
    return CandidateEvidence(
        cve_id=cve,
        advisory_id=advisory,
        disposition="applicable" if version == TruthValue.TRUE else "conditional",
        final_status="verified_applicable" if version == TruthValue.TRUE else "conditional_version_unknown",
        checks=[
            _check("product", product, observed=observed),
            _check("model", TruthValue.TRUE if model else TruthValue.UNKNOWN, observed=observed, required=model),
            _check("version", version),
            _check("technical_effect", TruthValue.TRUE),
        ],
        product_evidence_trace=list(
            traces if traces is not None else [_trace("CSAFPID-0001", product_name=name, model=model)]
        ),
        lifecycle=["SELECTED"],
    )


def _step(candidate: CandidateEvidence, *, step_id: str = "step-compromise", sequence: int = 5) -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        sequence=sequence,
        candidates=[candidate],
        selected_cve=candidate.cve_id,
        selected_cves=[candidate.cve_id],
    )


def _record(
    actions: list[RemediationAction],
    *,
    cve: str = "CVE-2030-80001",
    advisory: str = "ICSA-30-001-01",
    source_path: str = "/tmp/remediation-inventory.json",
    product_index: dict | None = None,
) -> CveRemediationRecord:
    return CveRemediationRecord(
        cve_id=cve,
        advisory_id=advisory,
        source_path=source_path,
        provenance=f"{advisory}::{cve}::{source_path}",
        remediations=actions,
        product_index=dict(product_index or {}),
    )


def _validate(candidate: CandidateEvidence, actions: list[RemediationAction], **kwargs):
    step = _step(candidate)
    record = _record(actions, cve=candidate.cve_id, advisory=candidate.advisory_id or "ICSA-30-001-01", **kwargs)
    inventory = StepRemediationInventory(
        step_id=step.step_id,
        sequence=step.sequence,
        selected_cve=step.selected_cve,
        advisory_id=candidate.advisory_id,
        records=[record],
    )
    return validate_step_evidence([step], [inventory])[0]


def _render(candidate: CandidateEvidence, actions: list[RemediationAction], **kwargs) -> str:
    row = _validate(candidate, actions, **kwargs)
    report = render_actionable_recommendations(
        apply_recommendation_policy(unify_step_defense_evidence([row], [], evidence=[_step(candidate)]))
    )
    return format_defense_recommendations(report)


def _action(details: str, product_ids: list[str], *, category: str = "vendor_fix") -> RemediationAction:
    return RemediationAction(
        category=category,
        details=details,
        product_ids=product_ids,
        scope=classify_remediation_scope(product_ids),
    )


def _tree_index(*pairs: tuple[str, str]) -> dict[str, dict[str, str]]:
    return {
        product_id: {
            "product_id": product_id,
            "name": name,
            "product": name,
            "model": name,
            "part_number": "",
        }
        for product_id, name in pairs
    }


def test_matching_product_scoped_remediation_renders():
    row = _validate(_candidate(), [_action("Update to V2.0.", ["CSAFPID-0001"])])
    assert row.remediations[0].support_state == DefenseSupportState.SUPPORTED
    text = _render(_candidate(), [_action("Update to V2.0.", ["CSAFPID-0001"])])
    assert "Update to V2.0." in text


def test_sibling_product_scoped_remediation_is_rejected():
    row = _validate(_candidate(), [_action("Update other product.", ["CSAFPID-9999"])])
    assert row.remediations[0].support_state == DefenseSupportState.REJECTED
    text = _render(_candidate(), [_action("Update other product.", ["CSAFPID-9999"])])
    assert "Update other product." not in text


def test_unknown_product_binding_is_suppressed_not_conditional():
    row = _validate(_candidate(traces=[]), [_action("Update to V2.0.", ["CSAFPID-0001"])])
    item = row.remediations[0]
    assert item.support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE
    assert item.support_state != DefenseSupportState.CONDITIONAL
    text = _render(_candidate(traces=[]), [_action("Update to V2.0.", ["CSAFPID-0001"])])
    assert "Update to V2.0." not in text


def test_unknown_version_with_product_match_is_conditional():
    row = _validate(
        _candidate(version=TruthValue.UNKNOWN),
        [_action("Update to V2.0.", ["CSAFPID-0001"])],
    )
    assert row.remediations[0].support_state == DefenseSupportState.CONDITIONAL
    text = _render(_candidate(version=TruthValue.UNKNOWN), [_action("Update to V2.0.", ["CSAFPID-0001"])])
    assert "Conditional vendor remediation" in text
    assert "Update to V2.0." in text


def test_advisory_level_mitigation_may_render():
    action = RemediationAction(
        category="mitigation",
        details="Restrict management-plane access to authorized operators.",
        product_ids=[],
        scope=SCOPE_ADVISORY_LEVEL,
    )
    row = _validate(_candidate(traces=[]), [action])
    assert row.remediations[0].scope == SCOPE_ADVISORY_LEVEL
    assert row.remediations[0].support_state == DefenseSupportState.SUPPORTED
    text = _render(_candidate(traces=[]), [action])
    assert "Restrict management-plane access" in text


def test_sibling_product_ids_in_same_advisory_only_matching_row_renders():
    index = _tree_index(("CSAFPID-0001", "FlowMaster X100"), ("CSAFPID-0002", "FlowMaster X200"))
    actions = [
        _action("Update FlowMaster X100 to V2.0.", ["CSAFPID-0001"]),
        _action("Update FlowMaster X200 to V3.0.", ["CSAFPID-0002"]),
    ]
    candidate = _candidate(traces=[_trace("CSAFPID-0001"), _trace("CSAFPID-0002")])
    row = _validate(candidate, actions, product_index=index)
    by_details = {item.details: item.support_state for item in row.remediations}
    assert by_details["Update FlowMaster X100 to V2.0."] == DefenseSupportState.SUPPORTED
    assert by_details["Update FlowMaster X200 to V3.0."] == DefenseSupportState.REJECTED
    text = _render(candidate, actions, product_index=index)
    assert "FlowMaster X100" in text
    assert "FlowMaster X200" not in text


def test_wrong_series_is_suppressed():
    index = _tree_index(
        ("CSAFPID-0001", "Catalog-100 Series A"),
        ("CSAFPID-0003", "Catalog-100 Series B"),
    )
    actions = [
        _action("Update Catalog-100 Series A.", ["CSAFPID-0001"]),
        _action("Update Catalog-100 Series B.", ["CSAFPID-0003"]),
    ]
    candidate = _candidate(
        name="Catalog-100 Series A",
        model="Catalog-100 Series A",
        family="Catalog-100",
        traces=[_trace("CSAFPID-0001"), _trace("CSAFPID-0003")],
    )
    text = _render(candidate, actions, product_index=index)
    assert "Series A" in text
    assert "Series B" not in text


def test_product_tree_resolves_exact_catalog_identity_without_trace_ids():
    index = _tree_index(("CSAFPID-0001", "FlowMaster X100"), ("CSAFPID-0002", "FlowMaster X200"))
    candidate = _candidate(traces=[])
    row = _validate(candidate, [_action("Update to V2.0.", ["CSAFPID-0001"])], product_index=index)
    assert row.remediations[0].support_state == DefenseSupportState.SUPPORTED
    sibling = _validate(candidate, [_action("Update sibling.", ["CSAFPID-0002"])], product_index=index)
    assert sibling.remediations[0].support_state == DefenseSupportState.REJECTED


def test_family_or_vendor_similarity_cannot_authorize_product_specific_remediation():
    index = _tree_index(("CSAFPID-0001", "FlowMaster X100"))
    candidate = _candidate(name="FlowMaster", model="", family="FlowMaster", traces=[])
    row = _validate(candidate, [_action("Update to V2.0.", ["CSAFPID-0001"])], product_index=index)
    assert row.remediations[0].support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE
    assert row.remediations[0].support_state != DefenseSupportState.CONDITIONAL
    family_trace = _candidate(
        name="FlowMaster",
        model="",
        family="FlowMaster",
        traces=[_trace("CSAFPID-0001", matched="family")],
    )
    family_row = _validate(family_trace, [_action("Update to V2.0.", ["CSAFPID-0001"])], product_index=index)
    assert family_row.remediations[0].support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE


def test_heading_lead_in_text_is_informational():
    assert (
        classify_actionability(
            details="The vendor has released the following for users to apply:",
            category="mitigation",
            scope=SCOPE_PRODUCT_SPECIFIC,
            product_ids=["CSAFPID-0001"],
        )
        == "informational"
    )
    action = _action(
        "The vendor has released the following for users to apply:",
        ["CSAFPID-0001"],
        category="mitigation",
    )
    text = _render(_candidate(), [action])
    assert "has released the following" not in text


def test_generic_boilerplate_is_not_actionable():
    details = (
        "Customers using the affected software are encouraged to apply the risk mitigations, "
        "if possible. Additionally, implement suggested security best practices."
    )
    assert (
        classify_actionability(
            details=details,
            category="mitigation",
            scope=SCOPE_PRODUCT_SPECIFIC,
            product_ids=["CSAFPID-0001"],
        )
        == "informational"
    )
    text = _render(_candidate(), [_action(details, ["CSAFPID-0001"], category="mitigation")])
    assert "risk mitigations" not in text
    assert "best practices" not in text


def test_feature_or_port_mitigation_without_deployment_binding_is_suppressed():
    details = "Restrict traffic to the mail port (25), if not needed."
    row = _validate(_candidate(), [_action(details, ["CSAFPID-0001"], category="mitigation")])
    assert row.remediations[0].support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE
    text = _render(_candidate(), [_action(details, ["CSAFPID-0001"], category="mitigation")])
    assert "port (25)" not in text
    object_details = "Customers can disable the mail object, if not needed."
    object_row = _validate(_candidate(), [_action(object_details, ["CSAFPID-0001"], category="mitigation")])
    assert object_row.remediations[0].support_state == DefenseSupportState.INSUFFICIENT_EVIDENCE


def test_exact_duplicate_remediation_renders_once():
    actions = [
        _action("Update to V2.0.", ["CSAFPID-0001"]),
        _action("Update to V2.0.", ["CSAFPID-0001"]),
    ]
    report = render_actionable_recommendations(
        apply_recommendation_policy(
            unify_step_defense_evidence(
                [_validate(_candidate(), actions)],
                [],
                evidence=[_step(_candidate())],
            )
        )
    )
    rendered = [item.rendered_text for step in report.steps for item in step.recommendations]
    assert len(rendered) == 1
    assert "Update to V2.0." in rendered[0]


def test_distinct_valid_remediations_are_both_retained():
    actions = [
        _action("Update to V2.0.", ["CSAFPID-0001"]),
        _action(
            "Restrict management-plane access to authorized operators.",
            ["CSAFPID-0001"],
            category="mitigation",
        ),
    ]
    text = _render(_candidate(), actions)
    assert "Update to V2.0." in text
    assert "Restrict management-plane access" in text


def _example_row(
    path: Path,
    cve: str,
    *,
    name: str,
    model: str,
    family: str,
    traces: list[dict] | None = None,
):
    records = [item for item in load_csaf_remediation_records(path) if item.cve_id == cve]
    assert records
    candidate = _candidate(
        name=name,
        model=model,
        family=family,
        version=TruthValue.UNKNOWN,
        traces=traces,
        cve=cve,
        advisory=records[0].advisory_id,
    )
    step = _step(candidate)
    inventory = StepRemediationInventory(
        step_id=step.step_id,
        sequence=step.sequence,
        selected_cve=cve,
        advisory_id=records[0].advisory_id,
        records=records,
    )
    row = validate_step_evidence([step], [inventory])[0]
    report = render_actionable_recommendations(
        apply_recommendation_policy(unify_step_defense_evidence([row], [], evidence=[step]))
    )
    return row, format_defense_recommendations(report)


def test_test_001_defense_keeps_matching_firmware_update():
    _row, text = _example_row(
        CSAF_DIR / "ICSA-24-137-02.json",
        "CVE-2024-31485",
        name="SICAM 8 CPCI85",
        model="CPCI85 Central Processing/Communication",
        family="SICAM 8",
    )
    assert "Update to V5.30" in text
    assert "CPC80" not in text
    assert "SICORE" not in text


def test_test_003_valid_mitigations_remain():
    _row, text = _example_row(
        CSAF_DIR / "ICSA-24-030-03.json",
        "CVE-2023-6374",
        name="MELSEC WS0-GETH00200",
        model="WS0-GETH00200",
        family="MELSEC WS Series",
    )
    lowered = text.lower()
    assert "virtual private network" in lowered or "vpn" in lowered
    assert "firewall" in lowered
    assert "take the following mitigation measures" not in lowered
    assert "for more information" not in lowered


def test_test_004_only_matching_catalog_remediation_renders():
    path = CSAF_DIR / "ICSA-23-264-04.json"
    records = [item for item in load_csaf_remediation_records(path) if item.cve_id == "CVE-2023-2262"]
    assert records
    assert records[0].product_index
    overbound = [_trace(f"CSAFPID-{index:04d}") for index in range(1, 56)]
    for traces in ([], overbound):
        _row, text = _example_row(
            path,
            "CVE-2023-2262",
            name="1756-EN2T Series A",
            model="1756-EN2T Series A",
            family="1756 Logix Communication Modules",
            traces=traces,
        )
        lowered = text.lower()
        assert "1756-en2t series a" in lowered
        assert "update to 5.009" in lowered
        assert "1756-en2t series b" not in lowered
        assert "1756-en2f" not in lowered
        assert "1756-en3tr" not in lowered
        assert "1756-en2tpk" not in lowered
        assert "1756-en2trk" not in lowered
        assert "smtp" not in lowered
        assert "mail object" not in lowered
        assert "email object" not in lowered
        assert "has released the following" not in lowered
        assert "best practices" not in lowered
    production = ROOT / "rag"
    for py_path in production.rglob("*.py"):
        body = py_path.read_text(encoding="utf-8")
        assert "1756-EN2T" not in body
        assert "CVE-2023-2262" not in body
        assert "Rockwell" not in body


def test_csaf_rows_with_product_ids_are_product_specific():
    action = _action("Update to V2.0.", ["CSAFPID-0001"])
    assert action.scope == SCOPE_PRODUCT_SPECIFIC
    empty = RemediationAction(category="mitigation", details="Restrict access.", product_ids=[])
    assert classify_remediation_scope(empty.product_ids, empty.scope) == SCOPE_ADVISORY_LEVEL
