from __future__ import annotations

from pathlib import Path

from rag.defense.models import (
    AttackMitigationEvidence,
    DefenseApplicabilityCheck,
    DefenseSupportState,
    RecommendationCandidate,
    RecommendationCondition,
    RecommendationPolicyState,
    StepAttackMitigationInventory,
    StepDefenseEvidence,
    StepRecommendationCandidates,
    ValidatedRemediation,
)
from rag.defense.recommendation_policy import (
    SOURCE_ATTACK,
    SOURCE_CSAF,
    apply_recommendation_policy,
)
from rag.defense.recommendation_renderer import (
    render_actionable_recommendations,
    render_condition_clause,
    render_condition_explanations,
    render_defense_recommendations,
    render_informational_recommendations,
    serialize_defense_recommendation_report,
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


def _candidates(csaf=None, attack=None, evidence=None):
    return apply_recommendation_policy(
        unify_step_defense_evidence(csaf or [], attack or [], evidence=evidence)
    )


def _texts(report):
    return [item.rendered_text for step in report.steps for item in step.recommendations]


def _all_rendered(report):
    items = [item for step in report.steps for item in step.recommendations]
    items.extend(report.informational)
    return items


def test_eligible_vendor_fix_uses_fixed_prefix_and_verbatim_content():
    rows = _candidates(csaf=[_csaf(remediations=[_remediation()])])
    report = render_actionable_recommendations(rows)
    assert _texts(report) == ["Vendor remediation: Update to V2.0."]
    item = report.steps[0].recommendations[0]
    assert item.source_content == "Update to V2.0."
    assert item.citation == "CVE: CVE-2030-80001. Advisory: ICSA-30-001-01."
    assert "/tmp/" not in item.rendered_text
    assert "/tmp/" not in item.citation


def test_eligible_mitigation_and_workaround_use_fixed_prefixes():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(category="workaround", details="Disable unused services."),
                    _remediation(category="mitigation", details="Restrict management-plane access."),
                ]
            )
        ]
    )
    assert _texts(render_actionable_recommendations(rows)) == [
        "Mitigation: Restrict management-plane access.",
        "Workaround: Disable unused services.",
    ]


def test_conditional_vendor_fix_joins_condition_reasons():
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
    text = _texts(render_actionable_recommendations(rows))[0]
    assert text == (
        "Conditional vendor remediation: Update to V2.0. "
        "This recommendation is conditional because the deployed version is unknown."
    )


def test_conditional_joins_multiple_reasons_in_stage5_order():
    checks = [
        _check("unresolved_conditions", TruthValue.UNKNOWN, "selected CVE has unresolved conditions"),
        _check("version", TruthValue.UNKNOWN, "deployed version unknown"),
    ]
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(support_state=DefenseSupportState.CONDITIONAL, checks=checks)
                ]
            )
        ]
    )
    report = render_actionable_recommendations(rows)
    text = _texts(report)[0]
    item = report.steps[0].recommendations[0]
    assert text == (
        "Conditional vendor remediation: Update to V2.0. "
        "This recommendation is conditional because the deployed version is unknown."
    )
    assert "selected CVE has unresolved conditions" not in text
    assert [condition.reason for condition in item.conditions] == [
        "selected CVE has unresolved conditions",
        "deployed version unknown",
    ]


def test_conditional_with_empty_reasons_uses_unknown_applicability():
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="csaf:test",
        source_type=SOURCE_CSAF,
        policy_state=RecommendationPolicyState.CONDITIONAL,
        category="vendor_fix",
        content="Update later.",
        conditions=[RecommendationCondition(name="version", status=TruthValue.UNKNOWN, reason="")],
    )
    rows = [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
    text = _texts(render_actionable_recommendations(rows))[0]
    assert text == (
        "Conditional vendor remediation: Update later. "
        "This recommendation is conditional because the deployed version is unknown."
    )


def test_attack_template_keeps_name_and_content_and_unknown_deployment():
    rows = _candidates(attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])])
    item = render_actionable_recommendations(rows).steps[0].recommendations[0]
    assert item.rendered_text == (
        "ATT&CK technique-level mitigation: Network Isolation. "
        "Isolate the affected host from untrusted networks. "
        "Deployment-specific applicability is not confirmed."
    )
    assert item.citation == "Technique: T9990. ATT&CK mitigation: M9991."
    assert "CVE" not in item.rendered_text
    assert "/tmp/" not in item.rendered_text
    assert "/tmp/" not in item.citation


def test_attack_mentions_cve_only_when_cve_id_is_present():
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="attack:test",
        source_type=SOURCE_ATTACK,
        policy_state=RecommendationPolicyState.ELIGIBLE,
        category="attack_mitigation",
        name="Network Isolation",
        content="Isolate the affected host from untrusted networks.",
        cve_id="CVE-2030-80001",
        technique_id="T9990",
        mitigation_id="M9991",
        deployment_applicability="unknown",
    )
    rows = [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
    text = _texts(render_actionable_recommendations(rows))[0]
    assert text.endswith("CVE: CVE-2030-80001.")
    assert "CVE: CVE-2030-80001" in text


def test_none_available_is_informational_only():
    rows = _candidates(
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
    actionable = render_actionable_recommendations(rows)
    assert actionable.steps == []
    assert actionable.informational == []
    informational = render_informational_recommendations(rows)
    assert informational.steps == []
    assert [item.rendered_text for item in informational.informational] == [
        "Source information: no remediation is available."
    ]


def test_suppressed_never_appears_in_user_facing_views():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(details="Update to V2.0."),
                    _remediation(
                        details="Rejected fix.",
                        support_state=DefenseSupportState.REJECTED,
                        provenance="rej",
                    ),
                    _remediation(
                        category="none_available",
                        details="Currently no fix is available",
                        support_state=DefenseSupportState.NOT_APPLICABLE,
                        provenance="none",
                    ),
                ]
            )
        ]
    )
    combined = render_defense_recommendations(rows, include_informational=True)
    states = {item.policy_state for item in _all_rendered(combined)}
    assert RecommendationPolicyState.SUPPRESSED not in states
    assert RecommendationPolicyState.ELIGIBLE in states
    assert RecommendationPolicyState.INFORMATIONAL in states
    assert "Rejected fix." not in serialize_defense_recommendation_report(combined)


def test_default_view_excludes_informational():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(details="Update to V2.0."),
                    _remediation(
                        category="none_available",
                        details="Currently no fix is available",
                        support_state=DefenseSupportState.NOT_APPLICABLE,
                        provenance="none",
                    ),
                ]
            )
        ]
    )
    report = render_defense_recommendations(rows)
    assert _texts(report) == ["Vendor remediation: Update to V2.0."]
    assert report.informational == []


def test_csaf_and_attack_remain_separate_rendered_items():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation(details="Update to V2.0.")])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    items = _all_rendered(render_actionable_recommendations(rows))
    assert [item.source_type for item in items] == [SOURCE_CSAF, SOURCE_ATTACK]
    assert items[0].rendered_text.startswith("Vendor remediation:")
    assert items[1].rendered_text.startswith("ATT&CK technique-level mitigation:")


def test_stage5_order_is_preserved():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(category="workaround", details="Disable unused services."),
                    _remediation(
                        category="vendor_fix",
                        details="Update later.",
                        support_state=DefenseSupportState.CONDITIONAL,
                        checks=[_check("version", TruthValue.UNKNOWN, "deployed version unknown")],
                    ),
                    _remediation(category="mitigation", details="Restrict access."),
                    _remediation(category="vendor_fix", details="Update to V2.0."),
                ]
            )
        ],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    kinds = [(item.policy_state, item.source_type, item.category) for item in _all_rendered(render_actionable_recommendations(rows))]
    assert kinds == [
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "vendor_fix"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "mitigation"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_CSAF, "workaround"),
        (RecommendationPolicyState.CONDITIONAL, SOURCE_CSAF, "vendor_fix"),
        (RecommendationPolicyState.ELIGIBLE, SOURCE_ATTACK, "attack_mitigation"),
    ]


def test_no_mutation_of_stage5_candidates():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation()])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    before = [row.to_dict() for row in rows]
    candidate_id = id(rows[0].candidates[0])
    condition_list_id = id(rows[0].candidates[0].conditions)
    report = render_actionable_recommendations(rows)
    assert [row.to_dict() for row in rows] == before
    assert id(rows[0].candidates[0]) == candidate_id
    assert id(rows[0].candidates[0].conditions) == condition_list_id
    assert id(report.steps[0].recommendations[0].conditions) != condition_list_id


def test_deterministic_serialization():
    rows = _candidates(
        csaf=[_csaf(remediations=[_remediation()])],
        attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])],
    )
    first = serialize_defense_recommendation_report(render_actionable_recommendations(rows))
    second = serialize_defense_recommendation_report(render_actionable_recommendations(rows))
    assert first == second
    assert "created" not in first
    assert "You should" not in first
    assert "Vendor remediation: Update to V2.0." in first


def test_empty_stage5_yields_empty_report():
    report = render_actionable_recommendations([])
    assert report.steps == []
    assert report.informational == []
    rows = apply_recommendation_policy(
        unify_step_defense_evidence([], [], evidence=[StepEvidence(step_id="step-empty", sequence=1)])
    )
    empty_step = render_actionable_recommendations(rows)
    assert empty_step.steps == []


def test_constrained_scenario_has_no_attack_rendered_text():
    contexts = load_defense_step_contexts(CONSTRAINED)
    attack_rows = inventory_attack_mitigations_from_contexts(contexts, ATTACK)
    csaf = [_csaf(step_id=item.step_id, sequence=item.sequence, remediations=[_remediation()]) for item in attack_rows]
    rows = apply_recommendation_policy(unify_step_defense_evidence(csaf, attack_rows))
    report = render_actionable_recommendations(rows)
    assert report.steps
    assert all(item.source_type != SOURCE_ATTACK for item in _all_rendered(report))
    assert all("ATT&CK" not in item.rendered_text for item in _all_rendered(report))
    example = render_actionable_recommendations(
        apply_recommendation_policy(
            unify_step_defense_evidence(
                [],
                inventory_attack_mitigations_from_contexts(
                    load_defense_step_contexts(EXAMPLES_CONSTRAINED), ATTACK
                ),
            )
        )
    )
    assert example.steps == []
    assert all("ATT&CK" not in item.rendered_text for item in _all_rendered(example))


def _cond(name: str, reason: str, status: TruthValue = TruthValue.UNKNOWN) -> RecommendationCondition:
    return RecommendationCondition(name=name, status=status, reason=reason)


def test_single_condition_grammar():
    assert render_condition_clause([_cond("version", "The deployed version is unknown.")]) == (
        "the deployed version is unknown"
    )


def test_two_condition_grammar():
    clause = render_condition_clause(
        [
            _cond("version", "The deployed version is unknown."),
            _cond("remediation_scope", "remediation product_ids cannot be related to selected product evidence"),
        ]
    )
    assert clause == (
        "the deployed version is unknown and "
        "remediation applicability to the selected deployment is not fully confirmed"
    )


def test_three_or_more_condition_grammar():
    clause = render_condition_clause(
        [
            _cond("version", "The deployed version is unknown."),
            _cond("remediation_scope", "unresolved"),
            _cond("advisory_match", "advisory identity is not available on both sides"),
        ]
    )
    assert clause == (
        "the deployed version is unknown, "
        "remediation applicability to the selected deployment is not fully confirmed, and "
        "source applicability to the selected deployment is unresolved"
    )


def test_trailing_punctuation_and_capitalization_are_normalized():
    assert render_condition_explanations([_cond("version", "The deployed version is unknown.")]) == [
        "the deployed version is unknown"
    ]
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="csaf:test",
        source_type=SOURCE_CSAF,
        policy_state=RecommendationPolicyState.CONDITIONAL,
        category="vendor_fix",
        content="Update later.",
        conditions=[_cond("version", "The deployed version is unknown.")],
    )
    text = _texts(
        render_actionable_recommendations(
            [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
        )
    )[0]
    assert "because The" not in text
    assert ". and" not in text
    assert ".." not in text


def test_duplicate_reasons_are_deduped():
    phrases = render_condition_explanations(
        [
            _cond("version", "The deployed version is unknown."),
            _cond("version", "the deployed version is unknown"),
        ]
    )
    assert phrases == ["the deployed version is unknown"]


def test_internal_product_id_terminology_is_not_exposed():
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="csaf:test",
        source_type=SOURCE_CSAF,
        policy_state=RecommendationPolicyState.CONDITIONAL,
        category="vendor_fix",
        content="Update to CPCI85 V05 or later version.",
        conditions=[
            _cond("version", "The deployed version is unknown."),
            _cond("fixed_scope", "no fixed product_ids in source record"),
            _cond("unresolved_conditions", "selected CVE has unresolved conditions"),
        ],
    )
    report = render_actionable_recommendations(
        [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
    )
    item = report.steps[0].recommendations[0]
    assert item.rendered_text == (
        "Conditional vendor remediation: Update to CPCI85 V05 or later version. "
        "This recommendation is conditional because the deployed version is unknown."
    )
    assert "product_ids" not in item.rendered_text
    assert "fixed_product_ids" not in item.rendered_text
    assert "selected CVE has unresolved conditions" not in item.rendered_text
    assert [condition.reason for condition in item.conditions] == [
        "The deployed version is unknown.",
        "no fixed product_ids in source record",
        "selected CVE has unresolved conditions",
    ]


def test_generic_unresolved_is_suppressed_when_specific_condition_exists():
    phrases = render_condition_explanations(
        [
            _cond("unresolved_conditions", "selected CVE has unresolved conditions"),
            _cond("version", "deployed version unknown"),
        ]
    )
    assert phrases == ["the deployed version is unknown"]


def test_structured_original_conditions_remain_unchanged():
    original = [
        _cond("version", "The deployed version is unknown."),
        _cond("fixed_scope", "no fixed product_ids in source record"),
    ]
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="csaf:test",
        source_type=SOURCE_CSAF,
        policy_state=RecommendationPolicyState.CONDITIONAL,
        category="vendor_fix",
        content="Update later.",
        conditions=original,
    )
    report = render_actionable_recommendations(
        [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
    )
    item = report.steps[0].recommendations[0]
    assert original[0].reason == "The deployed version is unknown."
    assert original[1].reason == "no fixed product_ids in source record"
    assert [condition.to_dict() for condition in item.conditions] == [c.to_dict() for c in original]
    assert id(item.conditions) != id(original)


def test_condition_rendering_is_deterministic():
    conditions = [
        _cond("version", "The deployed version is unknown."),
        _cond("remediation_scope", "remediation product_ids cannot be related to selected product evidence"),
        _cond("unresolved_conditions", "selected CVE has unresolved conditions"),
    ]
    first = render_condition_clause(conditions)
    second = render_condition_clause(conditions)
    assert first == second
    assert first == (
        "the deployed version is unknown and "
        "remediation applicability to the selected deployment is not fully confirmed"
    )


def test_empty_conditions_use_unknown_applicability_fallback():
    candidate = RecommendationCandidate(
        step_id="step-compromise",
        sequence=5,
        recommendation_id="csaf:test",
        source_type=SOURCE_CSAF,
        policy_state=RecommendationPolicyState.CONDITIONAL,
        category="vendor_fix",
        content="Update later.",
        conditions=[],
    )
    text = _texts(
        render_actionable_recommendations(
            [StepRecommendationCandidates(step_id="step-compromise", sequence=5, candidates=[candidate])]
        )
    )[0]
    assert text.endswith("This recommendation is conditional because applicability is unknown.")


def test_attack_wording_unchanged():
    rows = _candidates(attack=[_attack(technique_ids=["T9990"], records=[_attack_record()])])
    item = render_actionable_recommendations(rows).steps[0].recommendations[0]
    assert item.rendered_text == (
        "ATT&CK technique-level mitigation: Network Isolation. "
        "Isolate the affected host from untrusted networks. "
        "Deployment-specific applicability is not confirmed."
    )


def test_eligible_recommendation_wording_unchanged():
    rows = _candidates(csaf=[_csaf(remediations=[_remediation()])])
    assert _texts(render_actionable_recommendations(rows)) == ["Vendor remediation: Update to V2.0."]


def test_stage1_to_5_semantics_unchanged_by_renderer():
    rows = _candidates(
        csaf=[
            _csaf(
                remediations=[
                    _remediation(
                        support_state=DefenseSupportState.CONDITIONAL,
                        checks=[
                            _check("version", TruthValue.UNKNOWN, "The deployed version is unknown."),
                            _check("fixed_scope", TruthValue.UNKNOWN, "no fixed product_ids in source record"),
                            _check("unresolved_conditions", TruthValue.UNKNOWN, "selected CVE has unresolved conditions"),
                        ],
                    )
                ]
            )
        ]
    )
    candidate = rows[0].candidates[0]
    assert candidate.policy_state is RecommendationPolicyState.CONDITIONAL
    before = [condition.to_dict() for condition in candidate.conditions]
    report = render_actionable_recommendations(rows)
    item = report.steps[0].recommendations[0]
    assert item.policy_state is RecommendationPolicyState.CONDITIONAL
    assert [condition.to_dict() for condition in item.conditions] == before
    assert [condition.to_dict() for condition in candidate.conditions] == before
    assert item.rendered_text == (
        "Conditional vendor remediation: Update to V2.0. "
        "This recommendation is conditional because the deployed version is unknown."
    )
