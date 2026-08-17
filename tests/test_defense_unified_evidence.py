from __future__ import annotations

from pathlib import Path

from rag.defense.attack_mitigation import lookup_attack_mitigations
from rag.defense.models import (
    AttackMitigationEvidence,
    DefenseSupportState,
    StepAttackMitigationInventory,
    StepDefenseEvidence,
    ValidatedRemediation,
)
from rag.defense.scenario_context import (
    inventory_attack_mitigations_from_contexts,
    load_defense_step_contexts,
)
from rag.defense.unified_evidence import serialize_unified_step_defense_evidence, unify_step_defense_evidence
from rag.scenario.evidence import StepEvidence, TruthValue
from rag.scenario.models import ScenarioNarrativeResult

ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "tests" / "fixtures" / "attack"
CONSTRAINED = ROOT / "tests" / "fixtures" / "defense_scenarios" / "constrained"
EXAMPLES_CONSTRAINED = ROOT / "examples" / "TS-OT-CONSTRAINED-001"


def _csaf(
    *,
    step_id: str = "step-compromise",
    sequence: int = 5,
    selected_cve: str | None = "CVE-2030-80001",
    advisory_id: str | None = "ICSA-30-001-01",
    note: str = "",
    remediations: list[ValidatedRemediation] | None = None,
) -> StepDefenseEvidence:
    return StepDefenseEvidence(
        step_id=step_id,
        sequence=sequence,
        selected_cve=selected_cve,
        advisory_id=advisory_id,
        note=note,
        remediations=list(remediations or []),
    )


def _remediation(
    *,
    category: str = "vendor_fix",
    details: str = "Update to V2.0.",
    support_state: DefenseSupportState = DefenseSupportState.SUPPORTED,
    provenance: str = "ICSA-30-001-01::CVE-2030-80001::/tmp/a.json",
    advisory_id: str = "ICSA-30-001-01",
    source_path: str = "/tmp/a.json",
) -> ValidatedRemediation:
    return ValidatedRemediation(
        cve_id="CVE-2030-80001",
        advisory_id=advisory_id,
        source_path=source_path,
        provenance=provenance,
        category=category,
        details=details,
        support_state=support_state,
    )


def _attack(
    *,
    step_id: str = "step-compromise",
    sequence: int = 5,
    technique_ids: list[str] | None = None,
    records: list[AttackMitigationEvidence] | None = None,
    note: str = "",
) -> StepAttackMitigationInventory:
    return StepAttackMitigationInventory(
        step_id=step_id,
        sequence=sequence,
        technique_ids=list(technique_ids or []),
        records=list(records or []),
        note=note,
    )


def _attack_record(**overrides) -> AttackMitigationEvidence:
    data = dict(
        technique_stix_id="attack-pattern--aaaa0001-0001-0001-0001-000000000001",
        technique_external_id="T9990",
        technique_name="Fixture Technique Alpha",
        technique_domain="enterprise-attack",
        mitigation_stix_id="course-of-action--bbbb0001-0001-0001-0001-000000000001",
        mitigation_external_id="M9991",
        mitigation_name="Network Isolation",
        description="Isolate the affected host from untrusted networks.",
        domain="enterprise-attack",
        relationship_stix_id="relationship--dddd0001-0001-0001-0001-000000000001",
        relationship_type="mitigates",
        source_ref="course-of-action--bbbb0001-0001-0001-0001-000000000001",
        target_ref="attack-pattern--aaaa0001-0001-0001-0001-000000000001",
        source_path="/tmp/enterprise-mitigations.json",
        provenance="enterprise-attack::T9990::coa::rel::/tmp/enterprise-mitigations.json",
    )
    data.update(overrides)
    return AttackMitigationEvidence(**data)


def test_csaf_only_leaves_attack_empty():
    csaf = _csaf(remediations=[_remediation()])
    row = unify_step_defense_evidence([csaf], [])[0]
    assert row.csaf is csaf
    assert row.attack is None
    assert row.csaf.remediations[0].support_state == DefenseSupportState.SUPPORTED
    assert "no_attack_technique_id" in row.notes
    assert "no_attack_mitigation" in row.notes
    assert "no_csaf_remediation" not in row.notes


def test_attack_only_leaves_csaf_empty():
    attack = _attack(technique_ids=["T9990"], records=[_attack_record()])
    row = unify_step_defense_evidence([], [attack])[0]
    assert row.attack is attack
    assert row.csaf is None
    assert "no_selected_cve" in row.notes
    assert "no_csaf_remediation" in row.notes
    assert "no_attack_mitigation" not in row.notes


def test_both_branches_retained_independently():
    csaf = _csaf(remediations=[_remediation(details="Update to V2.0.")])
    attack = _attack(technique_ids=["T9990"], records=[_attack_record(mitigation_name="Network Isolation")])
    row = unify_step_defense_evidence([csaf], [attack])[0]
    assert row.csaf.remediations[0].details == "Update to V2.0."
    assert row.attack.records[0].mitigation_name == "Network Isolation"
    assert row.csaf.remediations[0].details != row.attack.records[0].mitigation_name


def test_neither_branch_present_is_valid_empty_result():
    rows = unify_step_defense_evidence([], [])
    assert rows == []
    evidence = [StepEvidence(step_id="step-empty", sequence=1)]
    row = unify_step_defense_evidence([], [], evidence=evidence)[0]
    assert row.step_id == "step-empty"
    assert row.csaf is None
    assert row.attack is None
    assert "no_csaf_remediation" in row.notes
    assert "no_attack_technique_id" in row.notes


def test_exact_step_id_matching():
    csaf = _csaf(step_id="step-compromise", remediations=[_remediation()])
    attack = _attack(step_id="step-initial-access", technique_ids=["T9990"], records=[_attack_record()])
    rows = unify_step_defense_evidence([csaf], [attack])
    assert [item.step_id for item in rows] == ["step-compromise", "step-initial-access"]
    assert rows[0].csaf is csaf and rows[0].attack is None
    assert rows[1].attack is attack and rows[1].csaf is None


def test_unknown_step_id_is_empty_not_guessed():
    csaf = _csaf(step_id="step-compromise", remediations=[_remediation()])
    evidence = [StepEvidence(step_id="step-unknown", sequence=9)]
    row = unify_step_defense_evidence([csaf], [], evidence=evidence)[0]
    assert row.step_id == "step-unknown"
    assert row.csaf is None
    assert row.attack is None
    assert row.sequence == 9


def test_duplicate_step_id_is_not_merged():
    first = _csaf(remediations=[_remediation(details="Update to V2.0.")])
    second = _csaf(remediations=[_remediation(details="Apply vendor package 2.0.1.", provenance="other")])
    row = unify_step_defense_evidence([first, second], [])[0]
    assert row.csaf is None
    assert "ambiguous_csaf_step_id" in row.notes
    attack_a = _attack(technique_ids=["T9990"], records=[_attack_record()])
    attack_b = _attack(technique_ids=["T9991"], records=[_attack_record(mitigation_external_id="M9992")])
    attack_row = unify_step_defense_evidence([], [attack_a, attack_b])[0]
    assert attack_row.attack is None
    assert "ambiguous_attack_step_id" in attack_row.notes


def test_supported_state_preserved_unchanged():
    csaf = _csaf(remediations=[_remediation(support_state=DefenseSupportState.SUPPORTED)])
    row = unify_step_defense_evidence([csaf], [])[0]
    assert row.csaf.remediations[0].support_state is DefenseSupportState.SUPPORTED
    assert row.csaf.remediations[0] is csaf.remediations[0]


def test_conditional_state_preserved_unchanged():
    csaf = _csaf(remediations=[_remediation(support_state=DefenseSupportState.CONDITIONAL)])
    row = unify_step_defense_evidence([csaf], [])[0]
    assert row.csaf.remediations[0].support_state is DefenseSupportState.CONDITIONAL


def test_rejected_state_preserved_unchanged():
    csaf = _csaf(remediations=[_remediation(support_state=DefenseSupportState.REJECTED)])
    row = unify_step_defense_evidence([csaf], [])[0]
    assert row.csaf.remediations[0].support_state is DefenseSupportState.REJECTED


def test_none_available_semantics_preserved_unchanged():
    csaf = _csaf(
        remediations=[
            _remediation(
                category="none_available",
                details="Currently no fix is available",
                support_state=DefenseSupportState.NOT_APPLICABLE,
            )
        ]
    )
    row = unify_step_defense_evidence([csaf], [])[0]
    item = row.csaf.remediations[0]
    assert item.category == "none_available"
    assert item.support_state is DefenseSupportState.NOT_APPLICABLE
    assert item.details == "Currently no fix is available"


def test_attack_relationship_fields_preserved_unchanged():
    record = _attack_record()
    attack = _attack(technique_ids=["T9990"], records=[record])
    row = unify_step_defense_evidence([], [attack])[0]
    kept = row.attack.records[0]
    assert kept is record
    assert kept.relationship_type == "mitigates"
    assert kept.source_ref == record.source_ref
    assert kept.target_ref == record.target_ref
    assert kept.mitigation_external_id == "M9991"


def test_attack_deployment_applicability_remains_unknown():
    attack = _attack(technique_ids=["T9990"], records=[_attack_record()])
    row = unify_step_defense_evidence([], [attack])[0]
    assert row.attack_relationship_supported is TruthValue.TRUE
    assert row.attack_deployment_applicability is TruthValue.UNKNOWN
    payload = row.to_dict()["attack"]["records"][0]
    assert payload["relationship_supported"] == "known_true"
    assert payload["deployment_applicability"] == "unknown"
    assert "deployment_applicability" not in row.attack.records[0].to_dict()


def test_no_exact_technique_id_leaves_attack_empty():
    csaf = _csaf(remediations=[_remediation()])
    attack = _attack(technique_ids=[], records=[], note="no_technique_id")
    row = unify_step_defense_evidence([csaf], [attack])[0]
    assert row.attack.records == []
    assert "no_attack_technique_id" in row.notes
    assert row.csaf.remediations


def test_missing_attack_evidence_does_not_affect_csaf():
    csaf = _csaf(remediations=[_remediation(details="Update to V2.0.")])
    before = csaf.to_dict()
    row = unify_step_defense_evidence([csaf], [])[0]
    assert row.csaf.to_dict() == before
    assert row.csaf.remediations[0].details == "Update to V2.0."
    assert row.csaf.remediations[0].support_state is DefenseSupportState.SUPPORTED


def test_multiple_csaf_sources_remain_independent():
    csaf = _csaf(
        remediations=[
            _remediation(details="Update to V2.0.", provenance="ICSA-30-001-01::a"),
            _remediation(
                details="Apply vendor package 2.0.1.",
                provenance="ICSA-30-001-02::b",
                advisory_id="ICSA-30-001-02",
            ),
        ]
    )
    row = unify_step_defense_evidence([csaf], [])[0]
    assert [item.details for item in row.csaf.remediations] == [
        "Update to V2.0.",
        "Apply vendor package 2.0.1.",
    ]
    assert row.csaf.remediations[0].provenance != row.csaf.remediations[1].provenance


def test_multiple_attack_domains_remain_independent():
    records = lookup_attack_mitigations(ATTACK, technique_id="T9990")
    attack = _attack(technique_ids=["T9990"], records=records)
    row = unify_step_defense_evidence([], [attack])[0]
    domains = [item.technique_domain for item in row.attack.records]
    assert "enterprise-attack" in domains
    assert "ics-attack" in domains
    provenances = [item.provenance for item in row.attack.records]
    assert len(provenances) == len(set(provenances))


def test_no_cross_source_semantic_deduplication():
    csaf = _csaf(remediations=[_remediation(details="Update to V2.0.")])
    attack = _attack(technique_ids=["T9990"], records=[_attack_record(description="Update to V2.0.")])
    row = unify_step_defense_evidence([csaf], [attack])[0]
    assert len(row.csaf.remediations) == 1
    assert len(row.attack.records) == 1
    assert row.csaf.remediations[0].details == row.attack.records[0].description
    assert row.csaf.remediations[0] is not row.attack.records[0]


def test_deterministic_step_ordering():
    csaf = [
        _csaf(step_id="step-b", sequence=2, remediations=[_remediation()]),
        _csaf(step_id="step-a", sequence=1, remediations=[_remediation()]),
    ]
    attack = [_attack(step_id="step-c", sequence=3, technique_ids=["T9990"], records=[_attack_record()])]
    first = unify_step_defense_evidence(csaf, attack)
    second = unify_step_defense_evidence(csaf, attack)
    assert [item.step_id for item in first] == ["step-b", "step-a", "step-c"]
    assert [item.step_id for item in first] == [item.step_id for item in second]
    evidence = [
        StepEvidence(step_id="step-c", sequence=3),
        StepEvidence(step_id="step-a", sequence=1),
        StepEvidence(step_id="step-b", sequence=2),
    ]
    ordered = unify_step_defense_evidence(csaf, attack, evidence=evidence)
    assert [item.step_id for item in ordered] == ["step-c", "step-a", "step-b"]


def test_deterministic_serialization():
    csaf = _csaf(remediations=[_remediation()])
    attack = _attack(technique_ids=["T9990"], records=[_attack_record()])
    first = unify_step_defense_evidence([csaf], [attack])
    second = unify_step_defense_evidence([csaf], [attack])
    encoded = serialize_unified_step_defense_evidence(first)
    assert encoded == serialize_unified_step_defense_evidence(second)
    assert "created" not in encoded
    assert "recommend" not in encoded.lower()
    assert "Update to V2.0." in encoded
    assert "Network Isolation" in encoded


def test_no_mutation_of_prior_stage_inputs():
    remediation = _remediation()
    csaf = _csaf(remediations=[remediation])
    record = _attack_record()
    attack = _attack(technique_ids=["T9990"], records=[record])
    step = StepEvidence(step_id="step-compromise", sequence=5, context={"step_description": "Uses T9990 in prose."})
    result = ScenarioNarrativeResult(
        scenario_id="UNI-4",
        title="Unified",
        narrative="placeholder",
        evidence=[step],
    )
    csaf_before = csaf.to_dict()
    attack_before = attack.to_dict()
    record_before = record.to_dict()
    remediation_id = id(remediation)
    record_id = id(record)
    evidence_id = id(result.evidence)
    unify_step_defense_evidence([csaf], [attack], evidence=result.evidence)
    assert result.narrative == "placeholder"
    assert id(result.evidence) == evidence_id
    assert csaf.to_dict() == csaf_before
    assert attack.to_dict() == attack_before
    assert record.to_dict() == record_before
    assert id(csaf.remediations[0]) == remediation_id
    assert id(attack.records[0]) == record_id
    assert "deployment_applicability" not in record.to_dict()


def test_constrained_input_without_attack_id_has_no_attack_evidence():
    contexts = load_defense_step_contexts(CONSTRAINED)
    attack_rows = inventory_attack_mitigations_from_contexts(contexts, ATTACK)
    csaf = [
        _csaf(step_id=item.step_id, sequence=item.sequence, remediations=[_remediation()])
        for item in attack_rows
    ]
    rows = unify_step_defense_evidence(csaf, attack_rows)
    assert rows
    assert all(not item.attack.records for item in rows)
    assert all("no_attack_technique_id" in item.notes for item in rows)
    assert all(item.csaf.remediations for item in rows)
    example = load_defense_step_contexts(EXAMPLES_CONSTRAINED)
    example_attack = inventory_attack_mitigations_from_contexts(example, ATTACK)
    example_unified = unify_step_defense_evidence([], example_attack)
    assert example_unified
    assert all(not item.attack.records for item in example_unified)
    assert all("no_attack_technique_id" in item.notes for item in example_unified)
