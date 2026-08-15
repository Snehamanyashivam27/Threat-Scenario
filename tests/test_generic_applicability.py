from __future__ import annotations

from rag.ingestion.csaf.documents import build_cve_retrieval_text
from rag.ingestion.csaf.parser import parse_csaf_file
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.claim_validator import narrative_uses_only_validated_cves
from rag.scenario.evidence import StepEvidence
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import (
    AttackStep,
    AttackerProfile,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "target-1",
        "name": "Acme FlowMaster X100",
        "vendor": "Acme Controls",
        "product_family": "FlowMaster",
        "model": "X100",
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


def _bundle(component: ComponentModel, step: AttackStep, capabilities: list[str] | None = None) -> ScenarioBundle:
    scenario = ScenarioModel(
        scenario_id="GENERIC-1",
        title="Generic applicability test",
        attacker_profile=AttackerProfile(capabilities=capabilities or []),
        attack_path=[step],
    )
    return ScenarioBundle(scenario=scenario, components_by_id={component.id: component})


def _evidence(
    *,
    cve: str = "CVE-2030-10001",
    product: str = "FlowMaster X100",
    model: str = "X100",
    versions: str = "prior to V2.0",
    description: str = "A command injection vulnerability could allow a remote attacker to execute arbitrary code.",
    prerequisites: str = "network_access=remote; authentication_required=false; physical_access=false",
    cwe: str = "CWE-77",
) -> str:
    return "\n".join(
        line
        for line in [
            f"CVE: {cve}",
            "Advisory: ICSA-30-001-01",
            "Vendor: Acme Controls",
            f"Product: {product}",
            f"Model: {model}" if model else "",
            f"Affected Versions: {versions}",
            f"CWE: {cwe}",
            f"Description: {description}",
            f"Prerequisites: {prerequisites}",
        ]
        if line
    )


def _evaluate(text: str, component: ComponentModel, step: AttackStep | None = None):
    actual_step = step or _step()
    enrichment = StepEnrichment(
        step=actual_step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    return evaluate_cve_candidates(
        enrichment,
        component,
        actual_step,
        _bundle(component, actual_step),
    )


def test_missing_version_and_ftp_are_conditional_not_assumed():
    component = _component(firmware_version=None, services=[])
    text = _evidence(
        description="An FTP service command injection could allow a remote attacker to execute arbitrary code."
    )

    candidate = _evaluate(text, component)[0]

    assert candidate.disposition == "conditional"
    assert any("version" in condition and "earlier than" in condition for condition in candidate.unresolved_conditions)
    assert any("ftp" in condition for condition in candidate.unresolved_conditions)


def test_known_service_mismatch_rejects_candidate():
    component = _component(firmware_version="V1.5", services=["SSH"])
    text = _evidence(
        description="An FTP service command injection could allow a remote attacker to execute arbitrary code."
    )

    candidate = _evaluate(text, component)[0]

    assert candidate.disposition == "rejected"
    assert any(check.name == "service" and check.status.value == "known_false" for check in candidate.checks)


def test_known_unaffected_version_rejects_candidate():
    candidate = _evaluate(_evidence(), _component(firmware_version="V2.1"))[0]

    assert candidate.disposition == "rejected"
    assert any(check.name == "version" and check.status.value == "known_false" for check in candidate.checks)


def test_wrong_product_rejects_candidate_even_with_matching_effect():
    candidate = _evaluate(
        _evidence(product="DifferentController Z9", model="Z9"),
        _component(firmware_version="V1.0"),
    )[0]

    assert candidate.disposition == "rejected"
    assert any(check.name == "product" and check.status.value == "known_false" for check in candidate.checks)


def test_wrong_technical_effect_is_rejected():
    candidate = _evaluate(
        _evidence(
            description="A resource exhaustion weakness can cause denial of service.",
            cwe="CWE-400",
        ),
        _component(firmware_version="V1.0"),
    )[0]

    assert candidate.disposition == "rejected"
    assert any(
        check.name == "technical_effect" and check.status.value == "known_false"
        for check in candidate.checks
    )


def test_session_step_prefers_mitm_effect_and_rejects_rce_effect():
    step = _step(
        "The attacker in a man-in-the-middle position compromises session confidentiality and integrity."
    )
    mitm = _evidence(
        cve="CVE-2030-10002",
        description=(
            "An authentication-by-spoofing weakness allows a man-in-the-middle attacker "
            "to observe and modify traffic during a valid session."
        ),
        cwe="CWE-290",
    )
    rce = _evidence(
        cve="CVE-2030-10003",
        description="A buffer overflow can allow remote code execution.",
        cwe="CWE-120",
    )

    candidates = _evaluate(f"{mitm}\n\n{rce}", _component(firmware_version="V1.0"), step)
    dispositions = {candidate.cve_id: candidate.disposition for candidate in candidates}

    assert dispositions["CVE-2030-10002"] == "applicable"
    assert dispositions["CVE-2030-10003"] == "rejected"


def test_csaf_relationship_preserves_product_local_version_range():
    record = next(
        item
        for item in parse_csaf_file("data/cisa_csaf/ICSA-24-326-03.json")
        if item.cve_id == "CVE-2024-8935"
    )
    text = build_cve_retrieval_text(record)
    step = _step(
        "The attacker in a man-in-the-middle position compromises engineering-session integrity."
    )
    component = ComponentModel(
        id="target-1",
        name="Modicon M340 PLC",
        vendor="Schneider Electric",
        product_family="Modicon M340",
        model="BMXP34 series CPU",
        part_number="BMXP34*",
        firmware_version="SV3.70",
    )

    candidate = _evaluate(text, component, step)[0]

    assert candidate.disposition == "rejected"
    version = next(check for check in candidate.checks if check.name == "version")
    assert version.status.value == "known_false"
    assert "16.2" not in version.required


def test_post_generation_check_rejects_unvalidated_cve_claims():
    evidence = [
        StepEvidence(
            step_id="exploit",
            sequence=1,
            selected_cves=["CVE-2030-10001"],
        )
    ]

    assert narrative_uses_only_validated_cves(
        "The attacker exploits CVE-2030-10001.",
        evidence,
    )
    assert not narrative_uses_only_validated_cves(
        "The attacker exploits CVE-2030-99999.",
        evidence,
    )


def test_reference_case_selects_direct_effect_not_prerequisite_downgrade():
    bundle = load_scenario_bundle("examples/TS-TEST-001")
    step = next(
        item
        for item in bundle.scenario.attack_path
        if item.step_id == "step-compromise-control-component"
    )
    records = {
        record.cve_id: record
        for record in parse_csaf_file("data/cisa_csaf/ICSA-24-137-02.json")
        + parse_csaf_file("data/cisa_csaf/ICSA-24-207-01.json")
        if record.cve_id in {"CVE-2024-31485", "CVE-2024-39601"}
    }
    text = "\n\n".join(build_cve_retrieval_text(record) for record in records.values())
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )

    candidates = evaluate_cve_candidates(
        enrichment,
        bundle.components_by_id[step.target_component_id],
        step,
        bundle,
    )
    product_31485 = next(item for item in candidates if item.cve_id == "CVE-2024-31485")
    other = next(item for item in candidates if item.cve_id == "CVE-2024-39601")
    assert next(check.status.value for check in product_31485.checks if check.name == "product") == "known_true"
    assert next(check.status.value for check in product_31485.checks if check.name == "technical_effect") == "known_true"
    assert next(check.status.value for check in other.checks if check.name == "technical_effect") != "known_true"
