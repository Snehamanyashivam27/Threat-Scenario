from __future__ import annotations

"""Property/invariant tests for the applicability contract — not CVE-ID fixtures."""

from rag.scenario.canonical_cve import isolate_cwes_for_cve
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, TruthValue
from rag.scenario.models import (
    AttackStep,
    AttackerProfile,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)
from rag.scenario.narrative_composer import ScenarioNarrativeComposer
from rag.scenario.step_cve_selection import select_best_step_candidate


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "target-1",
        "name": "Orion GridBridge G7",
        "vendor": "Orion Industrial",
        "product_family": "GridBridge",
        "model": "G7",
        "part_number": "OR-G7-1000",
        "firmware_version": "V4.2",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _step(description: str, name: str = "Compromise Controller") -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="exploit",
        name=name,
        source_component_id="source-1",
        target_component_id="target-1",
        description=description,
    )


def _bundle(component: ComponentModel, step: AttackStep) -> ScenarioBundle:
    return ScenarioBundle(
        scenario=ScenarioModel(
            scenario_id="PROP-1",
            title="Property test",
            attacker_profile=AttackerProfile(capabilities=[]),
            attack_path=[step],
        ),
        components_by_id={component.id: component},
    )


def _evidence(
    *,
    cve: str = "CVE-2032-10001",
    product: str = "Orion GridBridge G7",
    model: str = "G7",
    part_number: str = "OR-G7-1000",
    versions: str = "prior to V5.0",
    description: str = "A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
    cwe: str = "CWE-77",
) -> str:
    return "\n".join(
        [
            f"CVE: {cve}",
            "Advisory: ICSA-32-001-01",
            "Vendor: Orion Industrial",
            f"Product: {product}",
            f"Model: {model}" if model else "",
            f"Part Number: {part_number}" if part_number else "",
            f"Affected Versions: {versions}",
            f"CWE: {cwe}",
            f"Description: {description}",
            "Prerequisites: network_access=remote; authentication_required=false; physical_access=false",
        ]
    )


def _evaluate(text: str, component: ComponentModel, step: AttackStep, cve: str = "CVE-2032-10001"):
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, step, _bundle(component, step))
    return next(item for item in candidates if item.cve_id == cve)


def test_exact_product_affected_version_compatible_effect_selected():
    step = _step("The attacker compromises the controller.")
    component = _component(firmware_version="V4.2")
    candidate = _evaluate(_evidence(), component, step)
    selection = select_best_step_candidate("exploit", [candidate], step=step, component=component)

    assert candidate.is_usable
    assert next(c.status.value for c in candidate.checks if c.name == "technical_effect") == "known_true"
    assert selection.selected is not None
    assert selection.selected.cve_id == candidate.cve_id


def test_exact_product_wrong_version_rejected():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(_evidence(), _component(firmware_version="V6.0"), step)

    assert candidate.disposition == "rejected"
    assert next(c.status.value for c in candidate.checks if c.name == "version") == "known_false"


def test_exact_product_version_unknown_compatible_effect_conditional():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(_evidence(), _component(firmware_version=None), step)

    assert candidate.disposition == "conditional"
    assert next(c.status.value for c in candidate.checks if c.name == "version") == "unknown"
    assert next(c.status.value for c in candidate.checks if c.name == "technical_effect") == "known_true"


def test_exact_product_affected_version_incompatible_effect_rejected_for_step():
    step = _step(
        "The attacker modifies network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    candidate = _evaluate(
        _evidence(
            description="A resource exhaustion flaw can cause denial of service.",
            cwe="CWE-400",
        ),
        _component(firmware_version="V4.2"),
        step,
    )

    assert candidate.disposition == "rejected"
    assert next(c.status.value for c in candidate.checks if c.name == "technical_effect") == "known_false"
    selection = select_best_step_candidate("exploit", [candidate], step=step, component=_component())
    assert selection.selected is None


def test_same_family_different_model_rejected():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _evidence(product="Orion GridBridge G9", model="G9", part_number=""),
        _component(model="G7", name="Orion GridBridge G7", part_number="OR-G7-1000"),
        step,
    )

    assert candidate.disposition == "rejected"
    assert next(c.status.value for c in candidate.checks if c.name == "product") == "known_false"


def test_multi_cve_advisory_does_not_leak_cwes():
    isolated = isolate_cwes_for_cve(
        cve_id="CVE-2032-10001",
        all_cves=["CVE-2032-10001", "CVE-2032-10002"],
        all_cwes={"CWE-269", "CWE-22"},
    )
    assert isolated == frozenset()

    shared = isolate_cwes_for_cve(
        cve_id="CVE-2032-10001",
        all_cves=["CVE-2032-10001", "CVE-2032-10002"],
        all_cwes={"CWE-22"},
    )
    assert shared == frozenset({"CWE-22"})


def test_dos_cannot_explain_device_takeover():
    step = _step("The attacker compromises the PLC to gain control.")
    candidate = _evaluate(
        _evidence(
            description="A resource exhaustion flaw can cause denial of service.",
            cwe="CWE-400",
        ),
        _component(),
        step,
    )
    assert next(c.status.value for c in candidate.checks if c.name == "technical_effect") == "known_false"
    assert select_best_step_candidate("exploit", [candidate], step=step, component=_component()).selected is None


def test_selected_cve_reaches_narrator_rejected_does_not():
    from rag.scenario.evidence import StepEvidence

    bundle = _bundle(_component(), _step("The attacker compromises the controller."))
    step = bundle.scenario.attack_path[0]
    selected = CandidateEvidence(
        cve_id="CVE-2032-10001",
        advisory_id="ICSA-32-001-01",
        disposition="conditional",
        final_status="conditional_version_unknown",
        checks=[
            ApplicabilityCheck("product", TruthValue.TRUE),
            ApplicabilityCheck("version", TruthValue.UNKNOWN),
            ApplicabilityCheck("technical_effect", TruthValue.TRUE, observed="command_injection"),
        ],
        vulnerability_phrase="a command-injection vulnerability",
        unresolved_conditions=["the deployed firmware version falls within the affected range"],
    )
    rejected = CandidateEvidence(
        cve_id="CVE-2032-99999",
        advisory_id="ICSA-32-001-01",
        disposition="rejected",
        final_status="rejected_effect_mismatch",
        checks=[ApplicabilityCheck("technical_effect", TruthValue.FALSE)],
    )
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        evidence=StepEvidence(
            step_id=step.step_id,
            sequence=step.sequence,
            candidates=[selected, rejected],
            selected_cve=selected.cve_id,
            selected_cves=[selected.cve_id],
            narrator_evidence=[
                {
                    "cve_id": selected.cve_id,
                    "advisory_id": selected.advisory_id,
                    "disposition": selected.disposition,
                    "final_status": selected.final_status,
                    "gate_table": {"Product": "TRUE", "Version": "UNKNOWN", "Effect match": "TRUE"},
                    "affected_versions": [],
                    "unresolved_conditions": selected.unresolved_conditions,
                    "vulnerability_phrase": selected.vulnerability_phrase,
                }
            ],
        ),
    )
    narrative = ScenarioNarrativeComposer().compose(bundle, [enrichment])
    assert selected.cve_id in narrative
    assert rejected.cve_id not in narrative


def test_confirmed_version_match_is_known_true():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _evidence(versions="version 13.0"),
        _component(firmware_version="13.0"),
        step,
    )
    version = next(c for c in candidate.checks if c.name == "version")
    assert version.status == TruthValue.TRUE


def test_unknown_effect_not_selectable_for_specific_step():
    step = _step(
        "The attacker modifies network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    candidate = CandidateEvidence(
        cve_id="CVE-2032-10001",
        advisory_id="ICSA-32-001-01",
        disposition="applicable",
        final_status="verified_applicable",
        checks=[
            ApplicabilityCheck("product", TruthValue.TRUE),
            ApplicabilityCheck("version", TruthValue.TRUE),
            ApplicabilityCheck("technical_effect", TruthValue.UNKNOWN),
        ],
    )
    selection = select_best_step_candidate("exploit", [candidate], step=step, component=_component())
    assert selection.selected is None


def test_downstream_component_is_not_exploit_target():
    from rag.scenario.step_targets import resolve_step_targets

    step = AttackStep(
        sequence=5,
        step_id="effect",
        name="Compromise HMI Functions",
        source_component_id="cmp-hmi",
        target_component_id="cmp-process",
        description="HMI compromise may affect visualization or operator commands.",
    )
    roles = resolve_step_targets(step, None)
    assert roles.vulnerable_component_id == "cmp-hmi"
    assert roles.downstream_affected_id == "cmp-process"
    assert select_best_step_candidate("effect", [], step=step, component=_component()).reason == (
        "step_not_vulnerability_relevant"
    )


def test_serial_applicability_not_narrated_as_firmware_version():
    from rag.scenario.canonical_cve import condition_text_for_constraint, parse_constraint_text

    parsed = parse_constraint_text("all serial numbers")
    assert parsed and parsed[0].dimension == "serial_number"
    assert condition_text_for_constraint(parsed[0]) == ""
