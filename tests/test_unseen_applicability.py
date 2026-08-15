from __future__ import annotations

from rag.scenario.applicability import FinalStatus
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.models import AttackStep, AttackerProfile, ComponentModel, ScenarioBundle, ScenarioModel, StepEnrichment


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


def _step(description: str = "The attacker compromises the controller.") -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="exploit",
        name="Compromise Controller",
        source_component_id="source-1",
        target_component_id="target-1",
        description=description,
    )


def _bundle(component: ComponentModel, step: AttackStep) -> ScenarioBundle:
    scenario = ScenarioModel(
        scenario_id="UNSEEN-1",
        title="Unseen applicability test",
        attacker_profile=AttackerProfile(capabilities=[]),
        attack_path=[step],
    )
    return ScenarioBundle(scenario=scenario, components_by_id={component.id: component})


def _evidence(
    *,
    cve: str = "CVE-2031-50001",
    product: str = "Orion GridBridge G7",
    model: str = "G7",
    part_number: str = "OR-G7-1000",
    versions: str = "prior to V5.0",
    description: str = "A command injection vulnerability in the web interface could allow a remote attacker to execute arbitrary code.",
    prerequisites: str = "network_access=remote; authentication_required=false; physical_access=false",
    cwe: str = "CWE-77",
    effects: str = "",
) -> str:
    lines = [
        f"CVE: {cve}",
        "Advisory: ICSA-31-050-01",
        "Vendor: Orion Industrial",
        f"Product: {product}",
        f"Model: {model}" if model else "",
        f"Part Number: {part_number}" if part_number else "",
        f"Affected Versions: {versions}",
        f"CWE: {cwe}",
        f"Description: {description}",
        f"Prerequisites: {prerequisites}",
    ]
    if effects:
        lines.append(f"Effect: {effects}")
    return "\n".join(line for line in lines if line)


def _evaluate(text: str, component: ComponentModel, step: AttackStep | None = None, cve: str = "CVE-2031-50001"):
    actual_step = step or _step()
    enrichment = StepEnrichment(
        step=actual_step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    candidates = evaluate_cve_candidates(enrichment, component, actual_step, _bundle(component, actual_step))
    return next(candidate for candidate in candidates if candidate.cve_id == cve)


def _gate(candidate, name: str) -> str:
    return next(check for check in candidate.checks if check.name == name).status.value


def test_verified_applicable_with_generic_gates():
    candidate = _evaluate(
        _evidence(
            description="A command injection vulnerability could allow a remote attacker to execute arbitrary code."
        ),
        _component(),
    )

    assert candidate.final_status == FinalStatus.VERIFIED_APPLICABLE.value
    assert candidate.disposition == "applicable"
    assert _gate(candidate, "product") == "known_true"
    assert _gate(candidate, "version") == "known_true"
    assert _gate(candidate, "technical_effect") == "known_true"
    assert candidate.gate_table["Product"] == "TRUE"


def test_sibling_product_rejected_with_product_gate():
    candidate = _evaluate(
        _evidence(product="Orion GridBridge G9", model="G9", part_number=""),
        _component(model="G7", name="Orion GridBridge G7"),
    )

    assert candidate.final_status == FinalStatus.REJECTED_PRODUCT_MISMATCH.value
    assert _gate(candidate, "product") == "known_false"


def test_wrong_version_rejected():
    candidate = _evaluate(_evidence(), _component(firmware_version="V6.0"))

    assert candidate.final_status == FinalStatus.REJECTED_VERSION_MISMATCH.value
    assert _gate(candidate, "version") == "known_false"


def test_unknown_version_is_conditional():
    candidate = _evaluate(_evidence(), _component(firmware_version=None))

    assert candidate.final_status == FinalStatus.CONDITIONAL_VERSION_UNKNOWN.value
    assert candidate.disposition == "conditional"
    assert _gate(candidate, "version") == "unknown"


def test_dos_effect_rejected_for_device_compromise_step():
    candidate = _evaluate(
        _evidence(
            description="A resource exhaustion flaw can cause denial of service.",
            cwe="CWE-400",
        ),
        _component(),
        step=_step("The attacker compromises the PLC to gain control."),
    )

    assert candidate.final_status == FinalStatus.REJECTED_EFFECT_MISMATCH.value
    assert _gate(candidate, "technical_effect") == "known_false"


def test_csaf_cwe_matrix_match_without_prose_confirmation_is_conditional_not_rejected():
    """CWE/taxonomy identifies class; without CVE-local consequence, effect stays UNKNOWN."""
    text = "\n".join(
        [
            "CVE: CVE-2031-50099",
            "Advisory: ICSA-31-099-01",
            "Vendor: Orion Industrial",
            "Product: Orion GridBridge G7",
            "Model: G7",
            "Part Number: OR-G7-1000",
            "Affected Versions: prior to V5.0",
            "CWE: CWE-77",
            "Description: Vendor advisory text without an explicit effect phrase.",
            "Prerequisites: network_access=remote; authentication_required=false; physical_access=false",
            "document_type: csaf_security_advisory",
            "cve_detail: present",
        ]
    )
    candidate = _evaluate(
        text,
        _component(firmware_version="V4.2"),
        step=_step("The attacker compromises the controller."),
        cve="CVE-2031-50099",
    )

    assert _gate(candidate, "technical_effect") == "unknown"
    assert candidate.final_status != FinalStatus.REJECTED_EFFECT_MISMATCH.value
    assert _gate(candidate, "product") == "known_true"


def test_dos_effect_allowed_for_availability_step():
    candidate = _evaluate(
        _evidence(
            description="A resource exhaustion flaw can cause denial of service.",
            cwe="CWE-400",
        ),
        _component(),
        step=_step("The attacker causes denial of service against the controller."),
    )

    assert candidate.final_status == FinalStatus.VERIFIED_APPLICABLE.value
    assert _gate(candidate, "technical_effect") == "known_true"


def test_service_mismatch_rejected():
    candidate = _evaluate(
        _evidence(
            description="An FTP service command injection could allow a remote attacker to execute arbitrary code.",
            effects="FTP service",
        ),
        _component(firmware_version="V4.2", services=["SSH"]),
    )

    assert candidate.final_status == FinalStatus.REJECTED_PREREQUISITE_MISMATCH.value
    assert _gate(candidate, "service") == "known_false"


def test_unknown_service_is_conditional_not_assumed():
    candidate = _evaluate(_evidence(), _component(firmware_version="V4.2", services=[]))

    assert candidate.final_status == FinalStatus.CONDITIONAL_PREREQUISITE_UNKNOWN.value
    assert _gate(candidate, "service") == "unknown"


def test_http_mention_does_not_create_web_service_requirement():
    text = _evidence(
        description="An HTTP request parsing flaw could allow information disclosure.",
        cwe="CWE-200",
        effects="",
    )
    candidate = _evaluate(
        text,
        _component(services=[]),
        step=_step("The attacker exfiltrates sensitive configuration data."),
        cve="CVE-2031-50001",
    )

    service_checks = [check for check in candidate.checks if check.name == "service"]
    assert service_checks == []


def test_multiple_candidates_rank_verified_above_rejected():
    verified_text = _evidence(
        cve="CVE-2031-50001",
        description="A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
    )
    rejected_text = _evidence(
        cve="CVE-2031-50002",
        description="A resource exhaustion flaw can cause denial of service.",
        cwe="CWE-400",
    )
    component = _component()
    step = _step("The attacker compromises the controller.")
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=f"{verified_text}\n\n{rejected_text}",
        retrieved_text=f"{verified_text}\n\n{rejected_text}",
    )
    candidates = evaluate_cve_candidates(enrichment, component, step, _bundle(component, step))

    assert candidates[0].cve_id == "CVE-2031-50001"
    assert candidates[0].final_status == FinalStatus.VERIFIED_APPLICABLE.value
    assert candidates[1].final_status == FinalStatus.REJECTED_EFFECT_MISMATCH.value
    assert candidates[0].rank_score > candidates[1].rank_score


def test_gate_summary_explains_rejection_reason():
    candidate = _evaluate(
        _evidence(product="Orion GridBridge G9", model="G9", part_number=""),
        _component(model="G7"),
    )

    assert candidate.rejection_reasons
    assert candidate.gate_table["Product"] == "FALSE"
    assert "product" in candidate.rejection_reasons[0].lower() or candidate.final_status.startswith("rejected_")


def test_segmentation_step_accepts_configuration_effect():
    candidate = _evaluate(
        _evidence(
            description="An incorrect authorization check could allow an attacker to modify network configuration settings.",
            cwe="CWE-863",
        ),
        _component(),
        step=_step("The attacker bypasses network segmentation controls on the switch."),
    )

    assert _gate(candidate, "technical_effect") == "known_true"
    assert candidate.final_status in {
        FinalStatus.VERIFIED_APPLICABLE.value,
        FinalStatus.CONDITIONAL_PREREQUISITE_UNKNOWN.value,
    }
