from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from rag.generation.answer_service import DeterministicAnswerService
from rag.generation.rag_assistant import RAGAssistant
from rag.models.answer import AnswerResult, SourceReference
from rag.scenario.cve_validation import extract_validated_cve, parse_primary_advisory_record
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.loader import ScenarioLoadError, load_scenario_bundle
from rag.scenario.models import AttackStep, StepEnrichment
from rag.scenario.narrative_composer import ScenarioNarrativeComposer
from rag.scenario.narrative_generator import ScenarioNarrativeGenerator
from rag.scenario.query_builder import StepQueryBuilder
from rag.scenario.synthesizer import ScenarioNarrativeSynthesizer, ScenarioSynthesisAnswerService, build_scenario_synthesis_prompt


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "examples" / "TS-TEST-001"


def _switch_bypass_step() -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="step-bypass-segmentation",
        name="Manipulation or Bypass of Network Segmentation",
        source_component_id="cmp-station-switch-01",
        target_component_id="cmp-station-switch-01",
        description="The attacker exploits an applicable weakness to modify or bypass network or access-control settings on the switch.",
    )


def _rtu_compromise_step() -> AttackStep:
    return AttackStep(
        sequence=5,
        step_id="step-compromise-control-component",
        name="Compromise of the Control Component",
        source_component_id="cmp-station-switch-01",
        target_component_id="cmp-station-rtu-01",
        description="The attacker exploits an applicable vulnerability or insecure product function affecting the SICAM 8 CPCI85.",
    )


def _terrapin_advisory_text() -> str:
    return (
        "Advisory: Siemens RUGGEDCOM APE1808\n"
        "Identifier: ICSA-24-102-04\n"
        "Vendor: Siemens\n"
        "Product: RUGGEDCOM APE1808\n"
        "Affected Products: Siemens RUGGEDCOM APE1808: All versions with Palo Alto Networks Virtual NGFW configured\n"
        "CVE: CVE-2023-48795\n"
        "CWE: CWE-222\n"
        "Severity: High\n"
    )


def _single_cve_switch_advisory_text() -> str:
    return (
        "Advisory: Siemens SINEC OS\n"
        "Identifier: ICSA-25-254-04\n"
        "Vendor: Siemens\n"
        "Product: SINEC OS\n"
        "Affected Products: Siemens RUGGEDCOM RST2428P (6GK6242-6PA00): All versions.\n"
        "CVE: CVE-2025-40802\n"
        "CWE: CWE-287\n"
        "Severity: Low\n"
    )


def test_loader_reads_ts_test_001():
    bundle = load_scenario_bundle(SCENARIO_DIR)

    assert bundle.scenario.scenario_id == "TS-OT-TEST-001"
    assert len(bundle.scenario.attack_path) == 6
    assert len(bundle.components_by_id) == 3


def test_loader_rejects_missing_files(tmp_path):
    with pytest.raises(ScenarioLoadError, match="Missing scenario.json"):
        load_scenario_bundle(tmp_path)


def test_query_builder_is_deterministic():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    builder = StepQueryBuilder()
    step = bundle.scenario.attack_path[1]

    first = builder.build_primary_query(bundle, step)
    second = builder.build_primary_query(bundle, step)

    assert first == second
    assert "RUGGEDCOM RST2428P" in first


def test_parse_primary_advisory_record_extracts_single_cve():
    record = parse_primary_advisory_record(_single_cve_switch_advisory_text())

    assert record is not None
    assert record.cves == ["CVE-2025-40802"]
    assert "CWE-287" in record.cwes


def test_terrapin_cve_rejected_for_segmentation_step():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-switch-01"]
    enrichment = StepEnrichment(
        step=_switch_bypass_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_terrapin_advisory_text(),
        advisory_answer="CVE-2023-48795 is referenced in CISA ICS Advisory ICSA-24-102-04.",
        sources=[SourceReference(attack_id="ICSA-24-102-04", document_source="CISA ICS Advisory")],
    )

    assert extract_validated_cve(enrichment, component, _switch_bypass_step()) is None


def test_terrapin_cve_rejected_for_compromise_step():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_terrapin_advisory_text(),
        advisory_answer="CVE-2023-48795 is referenced in CISA ICS Advisory ICSA-24-102-04.",
        sources=[SourceReference(attack_id="ICSA-24-102-04", document_source="CISA ICS Advisory")],
    )

    assert extract_validated_cve(enrichment, component, _rtu_compromise_step()) is None


def test_multi_cve_advisory_is_rejected():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-switch-01"]
    enrichment = StepEnrichment(
        step=_switch_bypass_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=(
            "Advisory: Siemens SINEC OS\n"
            "Identifier: ICSA-26-043-06\n"
            "Vendor: Siemens\n"
            "Product: Siemens SINEC OS\n"
            "Affected Products: RUGGEDCOM RST2428P (6GK6242-6PA00)\n"
            "CVE: CVE-2022-48174, CVE-2023-7256\n"
            "CWE: CWE-287\n"
        ),
        advisory_answer="Multiple CVEs listed.",
        sources=[SourceReference(attack_id="ICSA-26-043-06", document_source="CISA ICS Advisory")],
    )

    assert extract_validated_cve(enrichment, component, _switch_bypass_step()) is None


def test_matching_single_cve_can_be_validated_for_compromise_step():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=(
            "Advisory: Siemens SICAM 8 Products\n"
            "Identifier: ICSA-26-092-01\n"
            "Vendor: Siemens\n"
            "Product: Siemens SICAM 8 Products\n"
            "Model: CPCI85 Central Processing/Communication\n"
            "Affected Products: CPCI85 Central Processing/Communication, RTUM85 RTU Base\n"
            "CVE: CVE-2026-27663\n"
            "CWE: CWE-287\n"
            "Description: An authentication bypass vulnerability allows an unauthenticated "
            "attacker to execute arbitrary code on the device.\n"
            "Severity: High\n"
        ),
        advisory_answer="CVE-2026-27663 is referenced in CISA ICS Advisory ICSA-26-092-01.",
        sources=[SourceReference(attack_id="ICSA-26-092-01", document_source="CISA ICS Advisory")],
    )

    validated = extract_validated_cve(enrichment, component, _rtu_compromise_step())

    assert validated is not None
    assert validated.cve_id == "CVE-2026-27663"
    assert "CWE-287" in validated.cwes


def test_same_cve_cannot_be_reused_across_steps():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=(
            "Advisory: Siemens SICAM 8 Products\n"
            "Identifier: ICSA-26-092-01\n"
            "Vendor: Siemens\n"
            "Product: Siemens SICAM 8 Products\n"
            "Model: CPCI85 Central Processing/Communication\n"
            "Affected Products: CPCI85 Central Processing/Communication\n"
            "CVE: CVE-2026-27663\n"
            "CWE: CWE-287\n"
            "Description: An authentication bypass vulnerability allows an unauthenticated "
            "attacker to execute arbitrary code on the device.\n"
        ),
        advisory_answer="CVE-2026-27663 is referenced in CISA ICS Advisory ICSA-26-092-01.",
        sources=[SourceReference(attack_id="ICSA-26-092-01", document_source="CISA ICS Advisory")],
    )

    first = extract_validated_cve(enrichment, component, _rtu_compromise_step(), used_cves=set())
    second = extract_validated_cve(enrichment, component, _rtu_compromise_step(), used_cves={"CVE-2026-27663"})

    assert first is not None
    assert second is None


def _csaf_ruggedcom_log_clear_text() -> str:
    return (
        "CVE: CVE-2024-41797\n"
        "Advisory: ICSA-25-162-03\n"
        "CVE-2024-41797 affects Siemens RUGGEDCOM RST2428P (6GK6242-6PA00).\n"
        "Vendor: Siemens\n"
        "Product: RUGGEDCOM RST2428P (6GK6242-6PA00)\n"
        "Part Number: 6GK6242-6PA00\n"
        "CWE: CWE-269\n"
        "Description: Affected devices contain an incorrect authorization check vulnerability. "
        "This could allow an authenticated remote attacker with guest role to invoke an internal "
        "do system command which exceeds their privileges. This command allows the execution of "
        "certain low-risk actions, the most critical of which is clearing the local system log.\n"
    )


def _csaf_cpci85_physical_spi_text() -> str:
    return (
        "CVE: CVE-2024-53832\n"
        "Advisory: ICSA-24-347-01\n"
        "CVE-2024-53832 affects Siemens CPCI85 Central Processing/Communication.\n"
        "Vendor: Siemens\n"
        "Product: CPCI85 Central Processing/Communication\n"
        "Model: CPCI85 Central Processing/Communication\n"
        "CWE: CWE-522\n"
        "Description: The affected devices contain a secure element which is connected via an "
        "unencrypted SPI bus. This could allow an attacker with physical access to the SPI bus "
        "to observe the password used for the secure element authentication.\n"
    )


def _csaf_network_config_bypass_text() -> str:
    return (
        "CVE: CVE-2025-40567\n"
        "Advisory: ICSA-25-999-01\n"
        "CVE-2025-40567 affects Siemens RUGGEDCOM RST2428P.\n"
        "Vendor: Siemens\n"
        "Product: RUGGEDCOM RST2428P\n"
        "Part Number: 6GK6242-6PA00\n"
        "CWE: CWE-863\n"
        "Description: Incorrect authorization in network configuration management allows an "
        "authenticated attacker to modify network access-control settings and bypass network "
        "segmentation controls on the switch.\n"
        "Effect: unauthorized modification of network configuration\n"
    )


def test_csaf_log_clear_cve_rejected_for_segmentation_bypass():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-switch-01"]
    enrichment = StepEnrichment(
        step=_switch_bypass_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_ruggedcom_log_clear_text(),
        advisory_answer="CVE-2024-41797 affects RUGGEDCOM RST2428P.",
        retrieved_text=_csaf_ruggedcom_log_clear_text(),
        sources=[SourceReference(attack_id="ICSA-25-162-03", document_source="cisa_csaf")],
    )

    assert extract_validated_cve(enrichment, component, _switch_bypass_step()) is None


def test_csaf_physical_spi_cve_rejected_for_remote_compromise():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_cpci85_physical_spi_text(),
        advisory_answer="CVE-2024-53832 affects CPCI85.",
        retrieved_text=_csaf_cpci85_physical_spi_text(),
        sources=[SourceReference(attack_id="ICSA-24-347-01", document_source="cisa_csaf")],
    )

    assert extract_validated_cve(enrichment, component, _rtu_compromise_step()) is None


def test_csaf_network_config_cve_accepted_for_segmentation_bypass():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-switch-01"]
    enrichment = StepEnrichment(
        step=_switch_bypass_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_network_config_bypass_text(),
        advisory_answer="CVE-2025-40567 enables modification of network access-control settings.",
        retrieved_text=_csaf_network_config_bypass_text(),
        sources=[SourceReference(attack_id="ICSA-25-999-01", document_source="cisa_csaf")],
    )

    validated = extract_validated_cve(enrichment, component, _switch_bypass_step())
    assert validated is not None
    assert validated.cve_id == "CVE-2025-40567"
    assert "CWE-863" in validated.cwes


def _csaf_cpci85_command_injection_text() -> str:
    return (
        "CVE: CVE-2024-31485\n"
        "Advisory: ICSA-24-137-02\n"
        "CVE-2024-31485 affects Siemens CPCI85 Central Processing/Communication.\n"
        "Vendor: Siemens\n"
        "Product: CPCI85 Central Processing/Communication\n"
        "Model: CPCI85 Central Processing/Communication\n"
        "Affected Versions: prior to V5.30\n"
        "CWE: CWE-77\n"
        "Description: The web interface of affected devices is vulnerable to command injection due to "
        "missing server side input sanitation. This could allow an authenticated privileged remote "
        "attacker to execute arbitrary code with root privileges.\n"
    )


def test_narrative_uses_natural_cve_phrasing_when_firmware_unknown():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]
    compromise = next(item for item in enrichments if item.step.step_id == "step-compromise-control-component")
    compromise.advisory_context = _csaf_cpci85_command_injection_text()
    compromise.advisory_answer = "CVE-2024-31485 command injection on CPCI85."
    compromise.retrieved_text = _csaf_cpci85_command_injection_text()
    compromise.sources = [SourceReference(attack_id="ICSA-24-137-02", document_source="cisa_csaf")]

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert "validated vulnerability (" not in narrative
    assert "falls within this affected range" not in narrative
    assert "..." not in narrative
    assert "CVE-2024-31485 affects SICAM 8 CPCI85" in narrative
    assert "command-injection vulnerability" in narrative
    assert "execute arbitrary code with root privileges" in narrative
    assert "device's web interface" in narrative
    assert narrative.count("device's web interface") == 1
    assert "The attacker then exploits CVE-2024-31485" not in narrative
    assert "If the deployed firmware is earlier than V5.30, the attacker can exploit CVE-2024-31485" not in narrative


def test_cve_remains_conditional_when_only_firmware_is_known():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    component.firmware_version = "V5.20"
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_cpci85_command_injection_text(),
        advisory_answer="CVE-2024-31485 command injection on CPCI85.",
        retrieved_text=_csaf_cpci85_command_injection_text(),
        sources=[SourceReference(attack_id="ICSA-24-137-02", document_source="cisa_csaf")],
    )

    validated = extract_validated_cve(enrichment, component, _rtu_compromise_step(), bundle=bundle)
    assert validated is not None
    assert validated.cve_id == "CVE-2024-31485"
    assert validated.applicability_status == "potentially_applicable_prerequisites_unconfirmed"
    assert "the attacker has authenticated privileged access to the device's web interface" in (
        validated.unresolved_prerequisites
    )
    assert "the deployed version falls within this affected range" not in validated.unresolved_prerequisites


def test_cve_generic_credentials_do_not_satisfy_privileged_auth_prerequisite():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_cpci85_command_injection_text(),
        advisory_answer="CVE-2024-31485 command injection on CPCI85.",
        retrieved_text=_csaf_cpci85_command_injection_text(),
        sources=[SourceReference(attack_id="ICSA-24-137-02", document_source="cisa_csaf")],
    )

    validated = extract_validated_cve(enrichment, component, _rtu_compromise_step(), bundle=bundle)
    assert validated is not None
    assert validated.applicability_status == "potentially_applicable_prerequisites_unconfirmed"
    assert any("authenticated privileged access" in item for item in validated.unresolved_prerequisites)


def test_narrative_uses_confident_exploit_when_all_prerequisites_confirmed():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    component.firmware_version = "V5.20"
    component.services = ["web_interface"]
    component.authentication = {"attacker_has_privileged_credentials": True}
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]
    compromise = next(item for item in enrichments if item.step.step_id == "step-compromise-control-component")
    compromise.advisory_context = _csaf_cpci85_command_injection_text()
    compromise.advisory_answer = "CVE-2024-31485 command injection on CPCI85."
    compromise.retrieved_text = _csaf_cpci85_command_injection_text()
    compromise.sources = [SourceReference(attack_id="ICSA-24-137-02", document_source="cisa_csaf")]

    validated = extract_validated_cve(
        compromise,
        component,
        compromise.step,
        bundle=bundle,
    )
    assert validated is not None
    assert validated.applicability_status == "verified_applicable"
    assert validated.unresolved_prerequisites == []

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert "If the deployed" not in narrative
    assert "The attacker then exploits CVE-2024-31485, a command-injection vulnerability" in narrative


def test_cve_rejected_when_firmware_outside_affected_range():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    component = bundle.components_by_id["cmp-station-rtu-01"]
    component.firmware_version = "V5.30"
    enrichment = StepEnrichment(
        step=_rtu_compromise_step(),
        primary_query="q",
        primary_answer="a",
        advisory_context=_csaf_cpci85_command_injection_text(),
        advisory_answer="CVE-2024-31485 command injection on CPCI85.",
        retrieved_text=_csaf_cpci85_command_injection_text(),
        sources=[SourceReference(attack_id="ICSA-24-137-02", document_source="cisa_csaf")],
    )

    assert extract_validated_cve(enrichment, component, _rtu_compromise_step()) is None


def test_narrative_composer_uses_unconfirmed_language_without_valid_cve():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert narrative.startswith("1. TS-OT-TEST-001 —")
    assert "could not be confirmed" in narrative.lower()
    assert "CVE-" not in narrative


def test_narrative_composer_uses_polished_threat_scenario_wording():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)
    lowered = narrative.lower()

    assert "gains access through a compromised maintenance device" in lowered
    assert "with access to a compromised maintenance device" not in lowered
    assert "RUGGEDCOM RST2428P" in narrative
    assert "RUGGEDCOMRST2428P" not in narrative
    assert "The attacker attempts to bypass the network-segmentation controls" in narrative
    assert "The scenario assumes that the network restrictions are successfully bypassed or modified" in narrative
    assert "After the network restrictions have been bypassed or modified" not in narrative
    assert "The attacker then attempts to compromise the SICAM 8 CPCI85." in narrative
    assert "The exact exploitation mechanism could not be confirmed." in narrative


def test_narrative_composer_rejects_terrapin_cve_in_output():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]

    for step_id in ("step-bypass-segmentation", "step-compromise-control-component"):
        enrichment = next(item for item in enrichments if item.step.step_id == step_id)
        enrichment.advisory_context = _terrapin_advisory_text()
        enrichment.advisory_answer = "CVE-2023-48795 is referenced in CISA ICS Advisory ICSA-24-102-04."

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert "CVE-2023-48795" not in narrative
    assert "Initial Access" not in narrative
    assert "Lateral Movement" not in narrative


def test_synthesizer_prompt_includes_all_steps():
    bundle = load_scenario_bundle(SCENARIO_DIR)
    enrichments = [
        Mock(
            step=AttackStep(
                sequence=index,
                step_id=f"step-{index}",
                name=f"Step {index}",
                source_component_id=None,
                target_component_id="cmp-station-rtu-01",
                description=f"Description {index}",
            ),
            primary_query=f"query {index}",
            primary_answer=f"answer {index}",
            advisory_query=None,
            advisory_answer=None,
            sources=[],
        )
        for index in range(1, 4)
    ]

    context = ScenarioNarrativeSynthesizer._build_synthesis_context(bundle, enrichments)
    prompt = build_scenario_synthesis_prompt("Generate narrative", context)

    assert "NarratorStepEvidence" in context
    assert "deterministic threat scenario narrative" in prompt


class FakeAssistant:
    def __init__(self):
        self.queries: list[str] = []

    def ask(self, query: str, k: int = 5) -> AnswerResult:
        self.queries.append(query)
        if "ICSA-" in query:
            return AnswerResult(
                question=query,
                answer=f"Advisory answer for {query}",
                sources=[SourceReference(attack_id="ICSA-26-188-05", document_source="CISA ICS Advisory")],
                context="Supporting Advisories",
                retrieved_text="Advisory: Example",
            )
        return AnswerResult(
            question=query,
            answer=f"Technique answer for {query[:40]}",
            sources=[SourceReference(attack_id="T0819", document_source="ICS ATT&CK")],
        )


def test_narrative_generator_with_fake_assistant():
    fake = FakeAssistant()
    generator = ScenarioNarrativeGenerator(
        assistant=fake,  # type: ignore[arg-type]
        synthesizer=ScenarioNarrativeSynthesizer(),
    )

    result = generator.generate(SCENARIO_DIR)

    assert result.scenario_id == "TS-OT-TEST-001"
    assert result.narrative.startswith("1. TS-OT-TEST-001 —")
    assert "CVE-" not in result.narrative
    assert len(fake.queries) >= 6


def test_rag_assistant_type_hint_still_works():
    retriever = Mock()
    retriever.retrieve.return_value = []
    assistant = RAGAssistant(retriever, DeterministicAnswerService())
    assert assistant is not None


def _selected_cve_evidence(
    step: AttackStep,
    cve_id: str,
    *,
    disposition: str = "conditional",
    final_status: str = "conditional_version_unknown",
    vulnerability_phrase: str = "a session-replay vulnerability",
    rejected_cve: str | None = None,
) -> StepEvidence:
    selected = CandidateEvidence(
        cve_id=cve_id,
        advisory_id="ICSA-24-030-03",
        disposition=disposition,
        final_status=final_status,
        checks=[
            ApplicabilityCheck("product", TruthValue.TRUE),
            ApplicabilityCheck("version", TruthValue.UNKNOWN),
            ApplicabilityCheck("technical_effect", TruthValue.TRUE),
        ],
        vulnerability_phrase=vulnerability_phrase,
        unresolved_conditions=["the deployed firmware version is earlier than V2.0"],
    )
    candidates = [selected]
    if rejected_cve:
        candidates.append(
            CandidateEvidence(
                cve_id=rejected_cve,
                advisory_id="ICSA-24-030-03",
                disposition="rejected",
                final_status="rejected_effect_mismatch",
                checks=[ApplicabilityCheck("technical_effect", TruthValue.FALSE)],
                rejection_reasons=["The vulnerability effect does not enable this attack step."],
            )
        )
    return StepEvidence(
        step_id=step.step_id,
        sequence=step.sequence,
        candidates=candidates,
        selected_cve=cve_id,
        selected_cves=[cve_id],
        narrator_evidence=[
            {
                "cve_id": cve_id,
                "advisory_id": "ICSA-24-030-03",
                "disposition": disposition,
                "final_status": final_status,
                "gate_table": {"Product": "TRUE", "Version": "UNKNOWN", "Effect match": "UNKNOWN"},
                "affected_versions": [],
                "unresolved_conditions": selected.unresolved_conditions,
                "vulnerability_phrase": vulnerability_phrase,
            }
        ],
    )


def test_narrative_composer_narrates_selected_cve_on_non_exploit_named_step():
    bundle = load_scenario_bundle(ROOT / "examples" / "TS-OT-TEST-003")
    cve_id = "CVE-2030-10001"
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]
    tamper = next(item for item in enrichments if item.step.step_id == "tamper")
    tamper.evidence = _selected_cve_evidence(
        tamper.step,
        cve_id,
        vulnerability_phrase="an authentication-replay vulnerability",
    )

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert narrative.count(cve_id) == 1
    assert cve_id in narrative
    assert "affects" in narrative.lower()
    assert "If the deployed firmware version is earlier than V2.0" in narrative
    assert "validated vulnerability" not in narrative.lower()


def test_narrative_composer_preserves_story_without_selected_cve():
    bundle = load_scenario_bundle(ROOT / "examples" / "TS-OT-TEST-003")
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert "CVE-" not in narrative
    assert "engineering workstation" in narrative.lower()
    assert "impair" in narrative.lower()


def test_narrative_composer_omits_rejected_cve_even_when_present_in_candidates():
    bundle = load_scenario_bundle(ROOT / "examples" / "TS-OT-TEST-003")
    selected_cve = "CVE-2030-10002"
    rejected_cve = "CVE-2030-10003"
    enrichments = [
        StepEnrichment(step=step, primary_query="q", primary_answer="a")
        for step in bundle.scenario.attack_path
    ]
    tamper = next(item for item in enrichments if item.step.step_id == "tamper")
    tamper.evidence = _selected_cve_evidence(
        tamper.step,
        selected_cve,
        rejected_cve=rejected_cve,
    )

    narrative = ScenarioNarrativeComposer().compose(bundle, enrichments)

    assert narrative.count(selected_cve) == 1
    assert rejected_cve not in narrative
