from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from rag.defense.attack_mitigation import (
    inventory_scenario_attack_mitigations,
    inventory_step_attack_mitigations,
    lookup_attack_mitigations,
    serialize_attack_mitigation_inventory,
    serialize_attack_mitigations,
)
from rag.defense.inventory import inventory_step_evidence
from rag.defense.models import DefenseSupportState, RemediationAction
from rag.defense.validation import validate_step_evidence
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.models import ScenarioNarrativeResult

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "attack"
ENTERPRISE = FIXTURES / "enterprise-mitigations.json"
ICS = FIXTURES / "ics-mitigations.json"
CSAF = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cisa_csaf"

ALPHA_STIX = "attack-pattern--aaaa0001-0001-0001-0001-000000000001"
M9991_STIX = "course-of-action--bbbb0001-0001-0001-0001-000000000001"


def _step(
    *,
    step_id: str = "step-compromise",
    sequence: int = 5,
    context: dict | None = None,
    selected: str | None = None,
    candidates: list[CandidateEvidence] | None = None,
) -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        sequence=sequence,
        context=context or {},
        selected_cve=selected,
        selected_cves=[selected] if selected else [],
        candidates=candidates or [],
    )


def _ids(records) -> list[str]:
    return [item.mitigation_external_id or item.mitigation_stix_id for item in records]


def test_exact_technique_returns_linked_course_of_action():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert any(item.mitigation_external_id == "M9991" for item in records)
    isolation = next(item for item in records if item.mitigation_external_id == "M9991")
    assert isolation.mitigation_name == "Network Isolation"
    assert isolation.mitigation_stix_id == M9991_STIX
    assert isolation.relationship_type == "mitigates"
    assert isolation.source_ref == M9991_STIX
    assert isolation.target_ref == ALPHA_STIX
    assert isolation.description == "Isolate the affected host from untrusted networks.\nKeep this paragraph intact."


def test_one_technique_keeps_all_linked_mitigations():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert _ids(records) == ["M9991", "M9992"]


def test_shared_mitigation_is_returned_only_for_requested_technique():
    alpha = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    beta = lookup_attack_mitigations(ENTERPRISE, technique_id="T9991")
    assert {item.mitigation_external_id for item in alpha} == {"M9991", "M9992"}
    assert _ids(beta) == ["M9991"]
    assert all(item.technique_external_id == "T9991" for item in beta)
    assert all(item.target_ref.endswith("0002") for item in beta)


def test_unrelated_course_of_action_is_not_returned():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert "M9993" not in _ids(records)
    assert all(item.mitigation_name != "Unrelated Mitigation" for item in records)


def test_wrong_relationship_type_is_not_treated_as_mitigation():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert all(item.relationship_type == "mitigates" for item in records)
    assert all("malware--" not in item.source_ref for item in records)


def test_reversed_relationship_direction_is_rejected():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert all(item.source_ref.startswith("course-of-action--") for item in records)
    assert all(item.target_ref.startswith("attack-pattern--") for item in records)
    assert all(item.source_ref != ALPHA_STIX for item in records)


def test_exact_external_technique_id_resolution():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="t9990")
    assert records
    assert all(item.technique_external_id == "T9990" for item in records)
    assert lookup_attack_mitigations(ENTERPRISE, technique_id="T9990.001") == []


def test_exact_stix_attack_pattern_id_resolution():
    records = lookup_attack_mitigations(FIXTURES, technique_id=ALPHA_STIX)
    assert records
    assert all(item.technique_stix_id == ALPHA_STIX for item in records)
    assert {item.mitigation_external_id for item in records} == {"M9991", "M9992"}
    ics_only = lookup_attack_mitigations(
        FIXTURES,
        technique_id="attack-pattern--eeee0001-0001-0001-0001-000000000001",
    )
    assert _ids(ics_only) == ["M8881"]


def test_missing_technique_returns_empty():
    assert lookup_attack_mitigations(ENTERPRISE, technique_id="T0000") == []
    assert lookup_attack_mitigations(ENTERPRISE, technique_id="") == []
    row = inventory_step_attack_mitigations([_step()], FIXTURES)[0]
    assert row.note == "no_technique_id"
    assert row.records == []


def test_missing_mitigation_external_id_is_still_valid():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9995")
    assert len(records) == 1
    item = records[0]
    assert item.mitigation_external_id == ""
    assert item.mitigation_stix_id == "course-of-action--bbbb0001-0001-0001-0001-000000000005"
    assert item.mitigation_name == "Sparse Mitigation"


def test_missing_description_and_url_do_not_crash():
    item = lookup_attack_mitigations(ENTERPRISE, technique_id="T9995")[0]
    assert item.description == ""
    assert item.urls == []


def test_revoked_technique_is_excluded():
    assert lookup_attack_mitigations(ENTERPRISE, technique_id="T9993") == []
    row = inventory_step_attack_mitigations(
        [_step(context={"attack_id": "T9993"})],
        ENTERPRISE,
    )[0]
    assert row.records == []
    assert row.note == "technique_inactive"


def test_deprecated_mitigation_and_technique_are_excluded():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    assert "M9994" not in _ids(records)
    assert lookup_attack_mitigations(ENTERPRISE, technique_id="T9996") == []
    row = inventory_step_attack_mitigations(
        [_step(context={"technique_id": "T9996"})],
        ENTERPRISE,
    )[0]
    assert row.note == "technique_inactive"


def test_duplicate_relationship_is_deduped_deterministically():
    records = lookup_attack_mitigations(ENTERPRISE, technique_id="T9990")
    m9991 = [item for item in records if item.mitigation_external_id == "M9991"]
    assert len(m9991) == 1
    assert m9991[0].relationship_stix_id == "relationship--dddd0001-0001-0001-0001-000000000001"


def test_multi_source_same_technique_preserves_provenance():
    records = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    domains = [item.technique_domain for item in records]
    assert "enterprise-attack" in domains
    assert "ics-attack" in domains
    source_paths = {item.source_path for item in records}
    assert any(Path(path).name == "enterprise-mitigations.json" for path in source_paths)
    assert any(Path(path).name == "ics-mitigations.json" for path in source_paths)
    provenances = [item.provenance for item in records]
    assert len(provenances) == len(set(provenances))
    ics = next(item for item in records if item.mitigation_external_id == "M8881")
    enterprise = next(item for item in records if item.mitigation_external_id == "M9991")
    assert ics.technique_stix_id != enterprise.technique_stix_id
    assert ics.domain == "ics-attack"
    assert enterprise.domain == "enterprise-attack"


def test_deterministic_ordering():
    first = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    second = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    keys = [(item.source_path, item.mitigation_external_id, item.relationship_stix_id) for item in first]
    assert keys == [(item.source_path, item.mitigation_external_id, item.relationship_stix_id) for item in second]
    assert [item.mitigation_external_id for item in first] == ["M9991", "M9992", "M8881"]


def test_deterministic_serialization():
    first = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    second = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    encoded = serialize_attack_mitigations(first)
    assert encoded == serialize_attack_mitigations(second)
    assert "created" not in encoded
    assert "modified" not in encoded
    assert "recommend" not in encoded.lower()
    rows = inventory_step_attack_mitigations([_step(context={"attack_id": "T9990"})], FIXTURES)
    assert serialize_attack_mitigation_inventory(rows) == serialize_attack_mitigation_inventory(
        inventory_step_attack_mitigations([_step(context={"attack_id": "T9990"})], FIXTURES)
    )


def test_malformed_unrelated_stix_objects_do_not_crash():
    records = lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    assert records
    empty = lookup_attack_mitigations(FIXTURES / "malformed.json", technique_id="T9990")
    assert empty == []
    invalid = lookup_attack_mitigations(FIXTURES / "not-json.json", technique_id="T9990")
    assert invalid == []
    missing = lookup_attack_mitigations("/no/such/attack/dir", technique_id="T9990")
    assert missing == []


def test_inventory_does_not_mutate_scenario_or_prior_defense_records():
    candidate = CandidateEvidence(
        cve_id="CVE-2030-80001",
        advisory_id="ICSA-30-001-01",
        disposition="conditional",
        final_status="conditional_version_unknown",
        checks=[ApplicabilityCheck(name="product", status=TruthValue.TRUE)],
        lifecycle=["SELECTED"],
        product_evidence_trace=[{"product_id": "CSAFPID-0001", "matched_dimension": "model", "polarity": "POSITIVE"}],
    )
    step = _step(
        selected="CVE-2030-80001",
        context={"attack_id": "T9990", "step_description": "Mentions T9990 in prose should not matter."},
        candidates=[candidate],
    )
    result = ScenarioNarrativeResult(
        scenario_id="DEF-3",
        title="Attack mitigations",
        narrative="placeholder",
        evidence=[step],
    )
    csaf_rows = inventory_step_evidence([step], CSAF)
    stage2 = validate_step_evidence([step], csaf_rows)
    evidence_id = id(result.evidence)
    step_id = id(step)
    candidate_id = id(candidate)
    lifecycle_before = list(candidate.lifecycle)
    traces_before = deepcopy(candidate.product_evidence_trace)
    csaf_before = csaf_rows[0].to_dict()
    stage2_before = stage2[0].to_dict()
    rows = inventory_scenario_attack_mitigations(result, FIXTURES)
    assert result.narrative == "placeholder"
    assert id(result.evidence) == evidence_id
    assert id(result.evidence[0]) == step_id
    assert id(result.evidence[0].candidates[0]) == candidate_id
    assert candidate.lifecycle == lifecycle_before
    assert candidate.product_evidence_trace == traces_before
    assert csaf_rows[0].to_dict() == csaf_before
    assert stage2[0].to_dict() == stage2_before
    assert rows[0].records
    assert rows[0].records[0] is not candidate


def test_step_prose_and_retrieval_hits_are_not_used_as_technique_ids():
    step = _step(
        context={"step_description": "Adversary uses T9990 against the RTU."},
        candidates=[],
    )
    step.queries = ["Explain T9990"]
    step.retrieval = []
    row = inventory_step_attack_mitigations([step], FIXTURES)[0]
    assert row.note == "no_technique_id"
    assert row.records == []


def test_structured_context_technique_id_is_used():
    row = inventory_step_attack_mitigations(
        [_step(context={"attack_ids": ["T9991", "T9991"]})],
        ENTERPRISE,
    )[0]
    assert row.technique_ids == ["T9991"]
    assert _ids(row.records) == ["M9991"]
    assert row.note == ""


def test_stage1_and_stage2_behavior_unchanged_by_attack_lookup():
    from rag.defense.csaf_remediation import load_csaf_remediation_records

    actions = load_csaf_remediation_records(CSAF / "remediation-inventory.json")
    vendor = next(
        item
        for record in actions
        if record.cve_id == "CVE-2030-80001"
        for item in record.remediations
        if item.category == "vendor_fix"
    )
    assert vendor.details == "Update to V2.0."
    step = _step(
        selected="CVE-2030-80001",
        context={"attack_id": "T9990"},
        candidates=[
            CandidateEvidence(
                cve_id="CVE-2030-80001",
                advisory_id="ICSA-30-001-01",
                disposition="applicable",
                final_status="verified_applicable",
                checks=[
                    ApplicabilityCheck(name="product", status=TruthValue.TRUE),
                    ApplicabilityCheck(name="version", status=TruthValue.TRUE),
                ],
                product_evidence_trace=[
                    {
                        "product_id": "CSAFPID-0001",
                        "matched_dimension": "model",
                        "polarity": "POSITIVE",
                        "conflicting_evidence": "",
                    }
                ],
            )
        ],
    )
    lookup_attack_mitigations(FIXTURES, technique_id="T9990")
    csaf_rows = inventory_step_evidence([step], CSAF)
    stage2 = validate_step_evidence([step], csaf_rows)
    assert csaf_rows[0].selected_cve == "CVE-2030-80001"
    assert any(item.category == "vendor_fix" for record in csaf_rows[0].records for item in record.remediations)
    assert isinstance(vendor, RemediationAction)
    assert stage2[0].remediations
    assert stage2[0].remediations[0].support_state in {
        DefenseSupportState.SUPPORTED,
        DefenseSupportState.CONDITIONAL,
        DefenseSupportState.REJECTED,
        DefenseSupportState.INSUFFICIENT_EVIDENCE,
        DefenseSupportState.NOT_APPLICABLE,
    }
