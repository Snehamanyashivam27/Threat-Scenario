from __future__ import annotations

"""CVE-local technical-effect tests — synthetic IDs only."""

from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.models import (
    AttackStep,
    AttackerProfile,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)
from rag.scenario.step_cve_selection import select_best_step_candidate


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "target-1",
        "name": "Acme FlowMaster X100",
        "vendor": "Acme Controls",
        "product_family": "FlowMaster",
        "model": "X100",
        "firmware_version": "V1.0",
    }
    values.update(overrides)
    return ComponentModel(**values)


def _step(
    description: str,
    *,
    name: str = "Compromise Controller",
    step_id: str = "exploit",
) -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id=step_id,
        name=name,
        source_component_id="source-1",
        target_component_id="target-1",
        description=description,
    )


def _bundle(component: ComponentModel, step: AttackStep) -> ScenarioBundle:
    return ScenarioBundle(
        scenario=ScenarioModel(
            scenario_id="EFF-1",
            title="Effect locality",
            attacker_profile=AttackerProfile(capabilities=[]),
            attack_path=[step],
        ),
        components_by_id={component.id: component},
    )


def _csaf(
    *,
    cve: str,
    description: str,
    cwe: str = "CWE-20",
    effect: str = "",
) -> str:
    lines = [
        f"CVE: {cve}",
        "Advisory: ADV-30-001-01",
        "Vendor: Acme Controls",
        "Product: FlowMaster X100",
        "Model: X100",
        "Affected Versions: prior to V2.0",
        f"CWE: {cwe}",
        f"Description: {description}",
        "Prerequisites: network_access=remote; authentication_required=false; physical_access=false",
        "document_type: csaf_security_advisory",
    ]
    if effect:
        lines.append(f"Effect: {effect}")
    return "\n".join(lines)


def _evaluate(text: str, step: AttackStep, component: ComponentModel | None = None):
    target = component or _component()
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    return evaluate_cve_candidates(enrichment, target, step, _bundle(target, step))


def _gate(candidate, name: str) -> str:
    return next(item.status.value for item in candidate.checks if item.name == name)


def test_a_dos_is_false_for_network_control_bypass():
    step = _step(
        "The attacker bypasses network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70001",
            description="A resource exhaustion flaw can cause denial of service.",
            cwe="CWE-400",
        ),
        step,
    )[0]
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "technical_effect") == "known_false"


def test_b_use_after_free_without_execution_is_unknown():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70002",
            description="A use-after-free weakness exists in a parser.",
            cwe="CWE-416",
        ),
        step,
    )[0]
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate("exploit", [candidate], step=step, component=_component())
    assert selection.selected is None


def test_c_command_injection_execution_is_true_for_device_compromise():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70003",
            description="A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
            cwe="CWE-77",
        ),
        step,
    )[0]
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "technical_effect") == "known_true"


def test_d_configuration_modification_true_only_when_compatible_with_bypass():
    bypass = _step(
        "The attacker bypasses network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    compatible = _evaluate(
        _csaf(
            cve="CVE-2030-70004",
            description="An attacker can modify network configuration and access-control settings.",
            cwe="CWE-863",
        ),
        bypass,
    )[0]
    generic = _evaluate(
        _csaf(
            cve="CVE-2030-70005",
            description="An attacker can perform configuration modification of local display preferences.",
            cwe="CWE-20",
        ),
        bypass,
    )[0]
    assert _gate(compatible, "technical_effect") == "known_true"
    assert _gate(generic, "technical_effect") != "known_true"


def test_e_input_validation_cwe_is_not_automatic_rce():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70006",
            description="The product does not validate input correctly.",
            cwe="CWE-20",
        ),
        step,
    )[0]
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "technical_effect") != "known_true"


def test_f_canonical_dos_wins_over_aggregate_code_execution():
    step = _step("The attacker compromises the controller.")
    text = "\n\n".join(
        [
            _csaf(
                cve="CVE-2030-70007",
                description="A resource exhaustion flaw can cause denial of service.",
                cwe="CWE-400",
            ),
            "\n".join(
                [
                    "Advisory: Aggregate row",
                    "Identifier: ADV-30-001-01",
                    "Vendor: Acme Controls",
                    "Product: FlowMaster X100",
                    "CVE: CVE-2030-70007",
                    "Effect: code execution",
                ]
            ),
        ]
    )
    candidate = next(item for item in _evaluate(text, step) if item.cve_id == "CVE-2030-70007")
    assert _gate(candidate, "technical_effect") == "known_false"
    effect = next(item for item in candidate.checks if item.name == "technical_effect")
    assert "denial_of_service" in (effect.observed or "")
    assert "code_execution" not in (effect.observed or "")
    assert "remote_code_execution" not in (effect.observed or "")


def test_g_sibling_cves_in_same_advisory_do_not_leak_effects():
    step = _step("The attacker compromises the controller.")
    text = "\n\n".join(
        [
            _csaf(
                cve="CVE-2030-70008",
                description="A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
                cwe="CWE-77",
            ),
            _csaf(
                cve="CVE-2030-70009",
                description="A resource exhaustion flaw can cause denial of service.",
                cwe="CWE-400",
            ),
        ]
    )
    by_cve = {item.cve_id: item for item in _evaluate(text, step)}
    exec_effect = next(item for item in by_cve["CVE-2030-70008"].checks if item.name == "technical_effect")
    dos_effect = next(item for item in by_cve["CVE-2030-70009"].checks if item.name == "technical_effect")
    assert exec_effect.status.value == "known_true"
    assert "denial_of_service" not in (exec_effect.observed or "")
    assert dos_effect.status.value == "known_false"
    assert "command_injection" not in (dos_effect.observed or "")


def test_h_attack_technique_text_cannot_make_effect_true():
    step = _step(
        "The attacker bypasses network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    text = "\n".join(
        [
            "ATT&CK ID: T1562",
            "Technique Name: Impair Defenses",
            "Description: Adversaries may bypass network segmentation controls.",
            "",
            _csaf(
                cve="CVE-2030-70010",
                description="The product does not validate input correctly.",
                cwe="CWE-20",
            ),
        ]
    )
    candidate = next(item for item in _evaluate(text, step) if item.cve_id == "CVE-2030-70010")
    assert _gate(candidate, "technical_effect") != "known_true"


def test_i_step_wording_cannot_create_configuration_modification_evidence():
    step = _step(
        "The attacker bypasses network segmentation controls on the switch.",
        name="Manipulation or Bypass of Network Segmentation",
    )
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70011",
            description="An input validation weakness was reported.",
            cwe="CWE-20",
        ),
        step,
    )[0]
    assert _gate(candidate, "technical_effect") != "known_true"
    effect = next(item for item in candidate.checks if item.name == "technical_effect")
    assert "configuration_modification" not in (effect.observed or "")
    assert "network_control_modification" not in (effect.observed or "")


def test_j_unknown_effect_is_not_selectable():
    step = _step("The attacker compromises the controller.")
    candidate = _evaluate(
        _csaf(
            cve="CVE-2030-70012",
            description="A use-after-free weakness exists in a parser.",
            cwe="CWE-416",
        ),
        step,
    )[0]
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "technical_effect") == "unknown"
    selection = select_best_step_candidate("exploit", [candidate], step=step, component=_component())
    assert selection.selected is None
