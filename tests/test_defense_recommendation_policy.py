from __future__ import annotations

from pathlib import Path

from rag.defense.models import (
    AttackMitigationEvidence,
    DefenseApplicabilityCheck,
    DefenseSupportState,
    RecommendationPolicyState,
    StepAttackMitigationInventory,
    StepDefenseEvidence,
    UnifiedStepDefenseEvidence,
    ValidatedRemediation,
)
from rag.defense.recommendation_policy import (
    SOURCE_ATTACK,
    SOURCE_CSAF,
    actionable_recommendation_candidates,
    apply_recommendation_policy,
    serialize_step_recommendation_candidates,
)
from rag.defense.scenario_context import (
    inventory_attack_mitigations_from_contexts,
    load_defense_step_contexts,
)
from rag.defense.unified_evidence import unify_step_defense_evidence
from rag.scenario.evidence import StepEvidence, TruthValue

ROOT = Path(__file__).resolve().parents[1]
CONSTRAINED = ROOT / "tests" / "fixtures" / "defense_scenarios" / "constrained"
ATTACK = ROOT / "tests" / "fixtures" / "attack"
EXAMPLES_CONSTRAINED = ROOT / "examples" / "TS-OT-CONSTRAINED-001"


def _check(name: str, status: TruthValue, reason: str = "") -> DefenseApplicabilityCheck:
    return DefenseApplicabilityCheck(name=name, status=status, reason=reason)


def _remediation(
    *,
    category: str = "vendor_fix",
    details: str = "Update to V2.0.",
    support_state: DefenseSupportState = DefenseSupportState.SUPPORTED,
    provenance: str = "ICSA-30-001-01::CVE-2030-80001::/tmp/a.json",
    advisory_id: str = "ICSA-30-001-01",
    cve_id: str = "CVE-2030-80001",
    urls: list[str] | None = None,
    checks: list[DefenseApplicabilityCheck] | None = None,
) -> ValidatedRemediation:
    return ValidatedRemediation(
        cve_id=cve_id,
        advisory_id=advisory_id,
        source_path="/tmp/a.json",
        provenance=provenance,
        category=category,
        details=details,
        urls=list(urls or []),
        support_state=support_state,
        checks=list(checks or []),
    )


def _csaf(
    *,
    step_id: str = "step-compromise",
    sequence: int = 5,
    remediations: list[ValidatedRemediation] | None = None,
    selected_cve: str | None = "CVE-2030-80001",
    note: str = "",
) -> StepDefenseEvidence:
    return StepDefenseEvidence(
        step_id=step_id,
        sequence=sequence,
        selected_cve=selected_cve,
        advisory_id="ICSA-30-001-01",
        note=note,
        remediations=list(remediations or []),
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
        urls=["https://attack.mitre.org/mitigations/M9991"],
    )
    data.update(overrides)
    return AttackMitigationEvidence(**data)


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


def _unify(csaf=None, attack=None, evidence=None) -> list[UnifiedStepDefenseEvidence]:
    return unify_step_defense_evidence(csaf or [], attack or [], evidence=evidence)


def _candidates(csaf=None, attack=None, evidence=None):
    return apply_recommendation_policy(_unify(csaf, attack, evidence))


def _flat(rows):
    return [item for row in rows for item in row.candidates]


def test_supported_vendor_fix_is_eligible():
    rows = _candidates(csaf=[_csaf(remediations=[_remediation()])])
    item = _flat(rows)[0]
    assert item.policy_state is RecommendationPolicyState.ELIGIBLE
    assert item.category == "vendor_fix"
    assert item.content == "Update to V2.0."
    assert item.source_type == SOURCE_CSAF


def test_conditional_vendor_fix_is_conditional():
    checks = [_check("version", TruthValue.UNKNOWN, "deployed version unknown")]
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(support_state=DefenseSupportState.CONDITIONAL, checks=checks)
                ]
            )
        ]
    )
    item = _flat(rows)[0]
    assert item.policy_state is RecommendationPolicyState.CONDITIONAL
    assert item.category == "vendor_fix"
    assert item.conditions[0].name == "version"
    assert item.conditions[0].reason == "deployed version unknown"


def test_rejected_is_suppressed():
    item = _flat(
        _candidates(csaf=[_csaf(remediations=[_remediation(support_state=DefenseSupportState.REJECTED)])])
    )[0]
    assert item.policy_state is RecommendationPolicyState.SUPPRESSED
    assert "rejected" in item.policy_reason


def test_insufficient_evidence_is_suppressed():
    item = _flat(
        _candidates(
            csaf=[_csaf(remediations=[_remediation(support_state=DefenseSupportState.INSUFFICIENT_EVIDENCE)])]
        )
    )[0]
    assert item.policy_state is RecommendationPolicyState.SUPPRESSED


def test_not_applicable_is_suppressed():
    item = _flat(
        _candidates(
            csaf=[_csaf(remediations=[_remediation(support_state=DefenseSupportState.NOT_APPLICABLE)])]
        )
    )[0]
    assert item.policy_state is RecommendationPolicyState.SUPPRESSED


def test_none_available_is_informational_never_eligible():
    item = _flat(
        _candidates(
            csaf=[
                _csaf(
                    remediations=[
                        _remediation(
                            category="none_available",
                            details="Currently no fix is available",
                            support_state=DefenseSupportState.NOT_APPLICABLE,
                        )
                    ]
                )
            ]
        )
    )[0]
    assert item.policy_state is RecommendationPolicyState.INFORMATIONAL
    assert item.policy_state is not RecommendationPolicyState.ELIGIBLE
    assert item.category == "none_available"
    assert item.content == "Currently no fix is available"


def test_workaround_preserves_category():
    item = _flat(
        _candidates(
            csaf=[_csaf(remediations=[_remediation(category="workaround", details="Disable unused services.")])]
        )
    )[0]
    assert item.category == "workaround"
    assert item.policy_state is RecommendationPolicyState.ELIGIBLE
    assert item.content == "Disable unused services."


def test_mitigation_preserves_category():
    item = _flat(
        _candidates(
            csaf=[
                _csaf(
                    remediations=[
                        _remediation(category="mitigation", details="Restrict management-plane access.")
                    ]
                )
            ]
        )
    )[0]
    assert item.category == "mitigation"
    assert item.content == "Restrict management-plane access."


def test_attack_relationship_is_eligible_technique_level():
    rows = _candidates(attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])])
    item = _flat(rows)[0]
    assert item.source_type == SOURCE_ATTACK
    assert item.policy_state is RecommendationPolicyState.ELIGIBLE
    assert item.technique_id == "T9990"
    assert item.mitigation_id == "M9991"
    assert item.name == "Network Isolation"
    assert item.content == "Isolate the affected host from untrusted networks."


def test_attack_candidate_keeps_deployment_applicability_unknown():
    item = _flat(_candidates(attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])]))[0]
    assert item.relationship_supported == "known_true"
    assert item.deployment_applicability == "unknown"


def test_no_attack_technique_id_yields_no_attack_candidate():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation()])],
        attack=[_attack(technique_ids=[], records=[], note="no_technique_id")],
    )
    assert all(item.source_type != SOURCE_ATTACK for item in _flat(rows))
    assert any(item.source_type == SOURCE_CSAF for item in _flat(rows))


def test_no_attack_mitigation_yields_no_attack_candidate():
    rows = _candidates(attack=[_attack(technique_ids=["T9990"], records=[], note="technique_not_found")])
    assert _flat(rows) == []


def test_missing_attack_does_not_alter_csaf_candidates():
    csaf = [_csaf(remediations=[_remediation(details="Update to V2.0.")])]
    with_attack_missing = _flat(_candidates(csaf=csaf, attack=[]))
    without = _flat(_candidates(csaf=csaf))
    assert [item.content for item in with_attack_missing] == [item.content for item in without]
    assert with_attack_missing[0].policy_state is RecommendationPolicyState.ELIGIBLE


def test_csaf_and_attack_are_independent_candidates():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation(details="Update to V2.0.")])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    kinds = [(item.source_type, item.category) for item in _flat(rows)]
    assert (SOURCE_CSAF, "vendor_fix") in kinds
    assert (SOURCE_ATTACK, "attack_mitigation") in kinds
    assert len(_flat(rows)) == 2


def test_no_cross_source_semantic_merging():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation(details="Update to V2.0.")])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record(description="Update to V2.0.")])],
    )
    items = _flat(rows)
    assert len(items) == 2
    assert {item.source_type for item in items} == {SOURCE_CSAF, SOURCE_ATTACK}


def test_unresolved_conditions_are_preserved_exactly():
    checks = [
        _check("unresolved_conditions", TruthValue.UNKNOWN, "selected CVE has unresolved conditions"),
        _check("version", TruthValue.TRUE, "version known"),
    ]
    item = _flat(
        _candidates(
            csaf=[
                _csaf(
                    remediations=[
                        _remediation(support_state=DefenseSupportState.CONDITIONAL, checks=checks)
                    ]
                )
            ]
        )
    )[0]
    names = [condition.name for condition in item.conditions]
    assert names == ["unresolved_conditions"]
    assert item.conditions[0].reason == "selected CVE has unresolved conditions"
    assert "if applicable" not in item.policy_reason


def test_no_unsupported_new_condition_is_introduced():
    item = _flat(_candidates(csaf=[_csaf(remediations=[_remediation()])]))[0]
    assert item.conditions == []
    assert item.policy_state is RecommendationPolicyState.ELIGIBLE


def test_ambiguous_step_id_does_not_guess_recommendations():
    first = _csaf(remediations=[_remediation(details="Update to V2.0.")])
    second = _csaf(remediations=[_remediation(details="Apply vendor package 2.0.1.", provenance="other")])
    rows = apply_recommendation_policy(unify_step_defense_evidence([first, second], []))
    assert "ambiguous_csaf_step_id" in rows[0].notes
    assert all(item.source_type != SOURCE_CSAF for item in _flat(rows))


def test_exact_duplicate_same_source_is_deduped():
    duplicate = _remediation()
    rows = _candidates(csaf=[_csaf(remediations=[duplicate, duplicate])])
    items = [item for item in _flat(rows) if item.source_type == SOURCE_CSAF]
    assert len(items) == 1


def test_distinct_provenance_remains_distinct():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(details="Update to V2.0.", provenance="ICSA-30-001-01::a"),
                    _remediation(details="Update to V2.0.", provenance="ICSA-30-001-02::b", advisory_id="ICSA-30-001-02"),
                ]
            )
        ]
    )
    items = _flat(rows)
    assert len(items) == 2
    assert items[0].recommendation_id != items[1].recommendation_id
    assert items[0].provenance != items[1].provenance


def test_deterministic_ordering_across_classes():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(category="workaround", details="Disable unused services."),
                    _remediation(category="none_available", details="Currently no fix is available"),
                    _remediation(
                        category="vendor_fix",
                        details="Update later.",
                        support_state=DefenseSupportState.CONDITIONAL,
                        checks=[_check("version", TruthValue.UNKNOWN, "deployed version unknown")],
                    ),
                    _remediation(category="mitigation", details="Restrict access."),
                    _remediation(category="vendor_fix", details="Update to V2.0."),
                    _remediation(category="vendor_fix", details="Rejected fix.", support_state=DefenseSupportState.REJECTED),
                ]
            )
        ],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    ordered = [(item.policy_state, item.source_type, item.category) for item in _flat(rows)]
    assert ordered == [
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "vendor_fix"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "mitigation"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "workaround"),
        (RecommendationPolicyState.CONDITIONAL, SOURCE_CSAF, "vendor_fix"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_ATTACK, "attack_mitigation"),
        (RecommendationPolicyState.INFORMATIONAL, SOURCE_CSAF, "none_available"),
        (RecommendationPolicyState.SUPPRESSED, SOURCE_CSAF, "vendor_fix"),
    ]


def test_deterministic_ordering_within_same_class():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(details="B fix", provenance="ICSA-30-001-02::b", advisory_id="ICSA-30-001-02"),
                    _remediation(details="A fix", provenance="ICSA-30-001-01::a", advisory_id="ICSA-30-001-01"),
                ]
            )
        ]
    )
    assert [item.advisory_id for item in _flat(rows)] == ["ICSA-30-001-01", "ICSA-30-001-02"]


def test_stable_recommendation_ids_across_repeated_calls():
    unified = _unify(csaf=[_csaf(remediations=[_remediation()])], attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])])
    first = [item.recommendation_id for item in _flat(apply_recommendation_policy(unified))]
    second = [item.recommendation_id for item in _flat(apply_recommendation_policy(unified))]
    assert first == second
    assert all(item.startswith("csaf:") or item.startswith("attack:") for item in first)


def test_deterministic_serialization():
    unified = _unify(csaf=[_csaf(remediations=[_remediation()])], attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])])
    first = apply_recommendation_policy(unified)
    second = apply_recommendation_policy(unified)
    encoded = serialize_step_recommendation_candidates(first)
    assert encoded == serialize_step_recommendation_candidates(second)
    assert "created" not in encoded
    assert "You should" not in encoded
    assert "Update to V2.0." in encoded
    assert "Network Isolation" in encoded


def test_no_mutation_of_unified_evidence():
    unified = _unify(
        csaf=[_csaf(remediations=[_remediation()])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )[0]
    before = unified.to_dict()
    csaf_id = id(unified.csaf)
    attack_id = id(unified.attack)
    rem_id = id(unified.csaf.remediations[0])
    rec_id = id(unified.attack.records[0])
    apply_recommendation_policy([unified])
    assert unified.to_dict() == before
    assert id(unified.csaf) == csaf_id
    assert id(unified.attack) == attack_id
    assert id(unified.csaf.remediations[0]) == rem_id
    assert id(unified.attack.records[0]) == rec_id


def test_empty_stage4_yields_empty_recommendations():
    assert apply_recommendation_policy([]) == []
    rows = apply_recommendation_policy(
        unify_step_defense_evidence([], [], evidence=[StepEvidence(step_id="step-empty", sequence=1)])
    )
    assert rows[0].candidates == []
    assert rows[0].step_id == "step-empty"


def test_constrained_scenario_has_no_attack_recommendation():
    contexts = load_defense_step_contexts(CONSTRAINED)
    attack_rows = inventory_attack_mitigations_from_contexts(contexts, ATTACK)
    csaf = [_csaf(step_id=item.step_id, sequence=item.sequence, remediations=[_remediation()]) for item in attack_rows]
    rows = apply_recommendation_policy(unify_step_defense_evidence(csaf, attack_rows))
    assert rows
    assert all(item.source_type != SOURCE_ATTACK for item in _flat(rows))
    assert any(item.source_type == SOURCE_CSAF for item in _flat(rows))
    example = apply_recommendation_policy(
        unify_step_defense_evidence([], inventory_attack_mitigations_from_contexts(load_defense_step_contexts(EXAMPLES_CONSTRAINED), ATTACK))
    )
    assert example
    assert all(item.source_type != SOURCE_ATTACK for item in _flat(example))


def test_suppressed_is_excluded_from_actionable_helper():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(details="Update to V2.0."),
                    _remediation(details="Rejected fix.", support_state=DefenseSupportState.REJECTED, provenance="rej"),
                    _remediation(
                        category="none_available",
                        details="Currently no fix is available",
                        support_state=DefenseSupportState.NOT_APPLICABLE,
                        provenance="none",
                    ),
                    _remediation(
                        details="Maybe later.",
                        support_state=DefenseSupportState.CONDITIONAL,
                        provenance="cond",
                        checks=[_check("version", TruthValue.UNKNOWN, "deployed version unknown")],
                    ),
                ]
            )
        ]
    )
    actionable = actionable_recommendation_candidates(rows)
    assert {item.policy_state for item in actionable} <= {
        RecommendationPolicyState.ELIGIBLE,
        RecommendationPolicyState.CONDITIONAL,
    }
    assert RecommendationPolicyState.SUPPRESSED not in {item.policy_state for item in actionable}
    assert RecommendationPolicyState.INFORMATIONAL not in {item.policy_state for item in actionable}
    assert any(item.policy_state is RecommendationPolicyState.SUPPRESSED for item in _flat(rows))
    assert any(item.policy_state is RecommendationPolicyState.INFORMATIONAL for item in _flat(rows))
