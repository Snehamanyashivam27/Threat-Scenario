from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from rag.defense.scenario_context import (
    align_defense_contexts,
    inventory_attack_mitigations_from_contexts,
    load_defense_step_contexts,
    serialize_defense_step_contexts,
)
from rag.scenario.evidence import CandidateEvidence, StepEvidence
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import AttackStep, ScenarioNarrativeResult

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "tests" / "fixtures" / "defense_scenarios" / "full"
CONSTRAINED = ROOT / "tests" / "fixtures" / "defense_scenarios" / "constrained"
ATTACK = ROOT / "tests" / "fixtures" / "attack"
EXAMPLES_FULL = ROOT / "examples" / "TS-TEST-001"
EXAMPLES_CONSTRAINED = ROOT / "examples" / "TS-OT-CONSTRAINED-001"
ALPHA_STIX = "attack-pattern--aaaa0001-0001-0001-0001-000000000001"


def _by_id(rows) -> dict[str, object]:
    return {item.step_id: item for item in rows}


def test_exact_technique_id_is_preserved():
    rows = load_defense_step_contexts(FULL)
    item = _by_id(rows)["step-external-id"]
    assert item.technique_ids == ["T9990"]
    assert "technique_id" in item.source_fields
    assert item.note == ""


def test_exact_external_id_is_passed_to_stage3():
    rows = load_defense_step_contexts(FULL)
    inventory = inventory_attack_mitigations_from_contexts(
        [item for item in rows if item.step_id == "step-external-id"],
        ATTACK,
    )
    assert inventory[0].technique_ids == ["T9990"]
    assert {item.mitigation_external_id for item in inventory[0].records} >= {"M9991", "M9992"}


def test_exact_stix_attack_pattern_id_is_passed():
    rows = load_defense_step_contexts(FULL)
    item = _by_id(rows)["step-stix-id"]
    assert item.technique_ids == [ALPHA_STIX]
    inventory = inventory_attack_mitigations_from_contexts([item], ATTACK)
    assert inventory[0].technique_ids == [ALPHA_STIX]
    assert {record.mitigation_external_id for record in inventory[0].records} == {"M9991", "M9992"}


def test_multiple_explicit_technique_ids_have_deterministic_order():
    item = _by_id(load_defense_step_contexts(FULL))["step-multiple-ids"]
    assert item.technique_ids == ["T9991", "T9990"]


def test_duplicate_ids_are_deduped_deterministically():
    item = _by_id(load_defense_step_contexts(FULL))["step-duplicate-ids"]
    assert item.technique_ids == ["T9990"]
    assert item.source_fields == ["technique_id", "attack_id", "attack_ids"]


def test_missing_technique_id_is_empty():
    item = _by_id(load_defense_step_contexts(FULL))["step-missing-id"]
    assert item.technique_ids == []
    assert item.note == "no_technique_id"


def test_technique_like_text_in_prose_is_not_extracted():
    item = _by_id(load_defense_step_contexts(FULL))["step-prose-only"]
    assert item.technique_ids == []


def test_tactic_without_technique_id_is_not_converted():
    item = _by_id(load_defense_step_contexts(FULL))["step-prose-only"]
    assert item.technique_ids == []
    assert "tactic" not in item.source_fields
    missing = _by_id(load_defense_step_contexts(FULL))["step-missing-id"]
    assert missing.technique_ids == []


def test_full_input_has_technique_id():
    item = _by_id(load_defense_step_contexts(FULL))["step-external-id"]
    assert item.technique_ids == ["T9990"]


def test_constrained_input_omits_technique_id_independently():
    full = _by_id(load_defense_step_contexts(FULL))["step-external-id"]
    constrained = _by_id(load_defense_step_contexts(CONSTRAINED))["step-external-id"]
    assert full.technique_ids == ["T9990"]
    assert constrained.technique_ids == []
    assert constrained.note == "no_technique_id"
    constrained_ids = [item.technique_ids for item in load_defense_step_contexts(CONSTRAINED)]
    assert constrained_ids == [[], [], [], [], [], []]


def test_current_example_scenarios_have_no_structured_technique_ids():
    full = load_defense_step_contexts(EXAMPLES_FULL)
    constrained = load_defense_step_contexts(EXAMPLES_CONSTRAINED)
    assert full
    assert constrained
    assert all(not item.technique_ids for item in full)
    assert all(not item.technique_ids for item in constrained)


def test_step_association_uses_exact_step_id():
    contexts = load_defense_step_contexts(FULL)
    evidence = [
        StepEvidence(step_id="step-external-id", sequence=2),
        StepEvidence(step_id="step-missing-id", sequence=6),
    ]
    aligned = align_defense_contexts(contexts, evidence)
    assert [item.step_id for item in aligned] == ["step-external-id", "step-missing-id"]
    assert aligned[0].technique_ids == ["T9990"]
    assert aligned[1].technique_ids == []


def test_unknown_step_mapping_is_empty_not_guessed():
    contexts = load_defense_step_contexts(FULL)
    evidence = [
        StepEvidence(step_id="step-unknown", sequence=1),
        StepEvidence(step_id="step-prose-only", sequence=1),
    ]
    aligned = align_defense_contexts(contexts, evidence)
    assert aligned[0].note == "no_step_mapping"
    assert aligned[0].technique_ids == []
    assert aligned[1].step_id == "step-prose-only"
    duplicate = [
        contexts[1],
        type(contexts[1])(
            scenario_id=contexts[1].scenario_id,
            step_id=contexts[1].step_id,
            sequence=99,
            technique_ids=["T9991"],
            source_fields=["technique_id"],
            provenance="other",
            note="",
        ),
    ]
    ambiguous = align_defense_contexts(duplicate, [StepEvidence(step_id="step-external-id", sequence=2)])
    assert ambiguous[0].technique_ids == []
    assert ambiguous[0].note == "ambiguous_step_id"


def test_stage3_consumes_exact_ids_from_adapter():
    contexts = [item for item in load_defense_step_contexts(FULL) if item.step_id == "step-multiple-ids"]
    inventory = inventory_attack_mitigations_from_contexts(contexts, ATTACK)
    assert inventory[0].technique_ids == ["T9991", "T9990"]
    mitigation_ids = [item.mitigation_external_id for item in inventory[0].records]
    assert "M9991" in mitigation_ids
    assert "M9992" in mitigation_ids
    constrained = inventory_attack_mitigations_from_contexts(
        [item for item in load_defense_step_contexts(CONSTRAINED) if item.step_id == "step-multiple-ids"],
        ATTACK,
    )
    assert constrained[0].records == []
    assert constrained[0].note == "no_technique_id"


def test_adapter_does_not_mutate_inputs():
    contexts = load_defense_step_contexts(FULL)
    candidate = CandidateEvidence(cve_id="CVE-2030-80001", advisory_id="ICSA-30-001-01", disposition="conditional")
    step = StepEvidence(
        step_id="step-external-id",
        sequence=2,
        context={"step_description": "Uses T9990 in prose."},
        candidates=[candidate],
        selected_cve="CVE-2030-80001",
    )
    result = ScenarioNarrativeResult(
        scenario_id="TS-DEF-FULL-001",
        title="Defense context",
        narrative="placeholder",
        evidence=[step],
    )
    evidence_id = id(result.evidence)
    step_obj_id = id(step)
    candidate_id = id(candidate)
    context_before = deepcopy(step.context)
    lifecycle_before = list(candidate.lifecycle)
    aligned = align_defense_contexts(contexts, result.evidence)
    inventory_attack_mitigations_from_contexts(aligned, ATTACK)
    assert result.narrative == "placeholder"
    assert id(result.evidence) == evidence_id
    assert id(result.evidence[0]) == step_obj_id
    assert id(result.evidence[0].candidates[0]) == candidate_id
    assert step.context == context_before
    assert candidate.lifecycle == lifecycle_before
    assert aligned[0].technique_ids == ["T9990"]
    assert "attack_id" not in step.context


def test_deterministic_serialization():
    first = load_defense_step_contexts(FULL)
    second = load_defense_step_contexts(FULL)
    assert serialize_defense_step_contexts(first) == serialize_defense_step_contexts(second)
    encoded = serialize_defense_step_contexts(first)
    assert "T9990" in encoded
    assert "created" not in encoded
    assert "recommend" not in encoded.lower()


def test_threat_loader_still_discards_unmodeled_technique_fields():
    bundle = load_scenario_bundle(EXAMPLES_FULL)
    assert all(isinstance(step, AttackStep) for step in bundle.scenario.attack_path)
    assert all(not hasattr(step, "technique_id") for step in bundle.scenario.attack_path)
    assert all(not hasattr(step, "attack_id") for step in bundle.scenario.attack_path)
