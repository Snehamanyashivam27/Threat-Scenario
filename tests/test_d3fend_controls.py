from __future__ import annotations

import inspect
from copy import deepcopy
from pathlib import Path

from rag.defense.d3fend_catalog import D3_NI, D3_NTA, D3_SU, controls_for_mitigation, controls_for_step_id
from rag.defense.report_pipeline import (
    D3FEND_SECTION_TITLE,
    NO_D3FEND_CONTROL,
    SECTION_TITLE,
    build_d3fend_control_report,
    build_d3fend_control_text,
    build_defense_recommendation_report,
    build_defense_recommendation_text,
    format_defense_recommendations,
)
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.models import ScenarioNarrativeResult

ROOT = Path(__file__).resolve().parents[1]
CSAF = ROOT / "tests" / "fixtures" / "cisa_csaf"
ATTACK = ROOT / "tests" / "fixtures" / "attack"
FULL = ROOT / "tests" / "fixtures" / "defense_scenarios" / "full"
CONSTRAINED = ROOT / "tests" / "fixtures" / "defense_scenarios" / "constrained"
EXAMPLES = ROOT / "examples" / "TS-TEST-001"


def _check(name: str, status: TruthValue) -> ApplicabilityCheck:
    return ApplicabilityCheck(name=name, status=status)


def _trace(product_id: str = "CSAFPID-0001") -> dict:
    return {
        "source": "cisa_csaf",
        "provenance": "product_status.known_affected",
        "scope": "cve_specific",
        "identity_origin": "product_tree_resolved",
        "evidence_strength": "SOURCE_MEMBERSHIP",
        "polarity": "POSITIVE",
        "matched_dimension": "model",
        "corroborating_evidence": "",
        "conflicting_evidence": "",
        "final_product_state": "TRUE",
        "product_id": product_id,
        "relationship_type": "",
        "version_constraint": "",
        "specificity_notes": [],
    }


def _candidate(
    cve: str = "CVE-2030-80001",
    *,
    advisory: str | None = "ICSA-30-001-01",
    product: TruthValue = TruthValue.TRUE,
    version: TruthValue = TruthValue.TRUE,
    description: str = "",
    effects: list[str] | None = None,
    cwes: list[str] | None = None,
) -> CandidateEvidence:
    if version == TruthValue.TRUE and product == TruthValue.TRUE:
        status = "verified_applicable"
        disp = "applicable"
    elif product == TruthValue.FALSE:
        status = "rejected_product_mismatch"
        disp = "rejected"
    else:
        status = "conditional_version_unknown"
        disp = "conditional"
    return CandidateEvidence(
        cve_id=cve,
        advisory_id=advisory,
        disposition=disp,
        final_status=status,
        checks=[
            _check("product", product),
            _check("version", version),
            _check("technical_effect", TruthValue.TRUE),
        ],
        description=description,
        effects=list(effects or []),
        cwes=list(cwes or []),
        product_evidence_trace=[_trace()],
        lifecycle=["SELECTED"],
    )


def _step(
    *,
    step_id: str = "step-external-id",
    sequence: int = 2,
    selected: str | None = "CVE-2030-80001",
    candidates: list[CandidateEvidence] | None = None,
) -> StepEvidence:
    return StepEvidence(
        step_id=step_id,
        sequence=sequence,
        candidates=candidates if candidates is not None else ([_candidate(selected)] if selected else []),
        selected_cve=selected,
        selected_cves=[selected] if selected else [],
    )


def _result(
    *,
    scenario_id: str = "TS-DEF-FULL-001",
    evidence: list[StepEvidence] | None = None,
) -> ScenarioNarrativeResult:
    return ScenarioNarrativeResult(
        scenario_id=scenario_id,
        title="D3FEND",
        narrative="Threat narrative.",
        evidence=list(evidence if evidence is not None else [_step()]),
    )


def _d3fend_text(result: ScenarioNarrativeResult, scenario_dir: Path = FULL) -> str:
    return build_d3fend_control_text(
        result,
        scenario_dir=scenario_dir,
        csaf_dir=CSAF,
        attack_sources=ATTACK,
    )


def _flat(report) -> list:
    return [item for step in report.steps for item in step.controls]


def test_stage6_text_is_unchanged_when_d3fend_is_generated():
    result = _result(evidence=[_step()])
    stage6 = build_defense_recommendation_text(
        result,
        scenario_dir=FULL,
        csaf_dir=CSAF,
        attack_sources=ATTACK,
    )
    d3fend = _d3fend_text(result)
    assert stage6.startswith(SECTION_TITLE)
    assert D3FEND_SECTION_TITLE not in stage6
    assert "Vendor remediation: Update to V2.0." in stage6
    assert d3fend.startswith(D3FEND_SECTION_TITLE)
    assert SECTION_TITLE not in d3fend
    report = build_defense_recommendation_report(
        result,
        scenario_dir=FULL,
        csaf_dir=CSAF,
        attack_sources=ATTACK,
    )
    assert format_defense_recommendations(report) == stage6


def test_attack_mitigation_maps_to_isolate_network_isolation():
    text = _d3fend_text(_result(evidence=[_step(selected=None, candidates=[])]))
    assert "Isolate — D3-NI Network Isolation:" in text
    assert "Source: Technique: T9990. ATT&CK mitigation: M9991." in text
    assert controls_for_mitigation(mitigation_id="M9991", mitigation_name="Network Isolation") == (D3_NI,)


def test_ts_test_001_step_ids_map_without_technique_ids():
    evidence = [
        _step(step_id="step-initial-access", sequence=1, selected=None, candidates=[]),
        _step(step_id="step-access-network-component", sequence=2, selected=None, candidates=[]),
        _step(step_id="step-bypass-segmentation", sequence=3, selected=None, candidates=[]),
        _step(step_id="step-lateral-movement", sequence=4, selected=None, candidates=[]),
        _step(
            step_id="step-compromise-control-component",
            sequence=5,
            selected="CVE-2024-31485",
            candidates=[
                _candidate(
                    "CVE-2024-31485",
                    advisory="ICSA-24-137-02",
                    version=TruthValue.UNKNOWN,
                    description="Command injection allows an authenticated attacker to execute arbitrary code.",
                    effects=["command injection"],
                    cwes=["CWE-77"],
                )
            ],
        ),
        _step(step_id="step-impact", sequence=6, selected=None, candidates=[]),
    ]
    text = _d3fend_text(_result(evidence=evidence), EXAMPLES)
    assert "Isolate — D3-NI Network Isolation:" in text
    assert "Detect — D3-NTA Network Traffic Analysis:" in text
    assert "Harden — D3-SU Software Update:" in text
    assert "Step step-bypass-segmentation:" in text
    assert "Step step-compromise-control-component:" in text
    assert "Technique: T" not in text
    mapped = controls_for_step_id("step-bypass-segmentation")
    assert D3_NI in mapped
    assert D3_NTA in mapped


def test_does_not_infer_attack_technique_from_prose():
    result = _result(evidence=[_step(step_id="step-prose-only", sequence=1, selected=None, candidates=[])])
    text = _d3fend_text(result)
    assert "Technique: T9990" not in text
    assert "ATT&CK mitigation: M9991" not in text


def test_vendor_fix_maps_to_conditional_software_update():
    result = _result(
        evidence=[
            _step(
                selected="CVE-2030-80001",
                candidates=[_candidate(version=TruthValue.UNKNOWN)],
            )
        ]
    )
    text = _d3fend_text(result)
    assert "Harden — D3-SU Software Update:" in text or "Conditional Harden — D3-SU Software Update:" in text
    assert "CVE: CVE-2030-80001" in text


def test_command_injection_effect_maps_to_detect_and_isolate():
    result = _result(
        evidence=[
            _step(
                step_id="step-compromise-control-component",
                sequence=5,
                selected="CVE-2030-80001",
                candidates=[
                    _candidate(
                        description="Command injection allows arbitrary code execution.",
                        effects=["command injection"],
                        cwes=["CWE-77"],
                    )
                ],
            )
        ]
    )
    text = _d3fend_text(result, EXAMPLES)
    assert "Detect — D3-PA Process Analysis:" in text
    assert "Isolate — D3-EI Execution Isolation:" in text
    assert "CWE: CWE-77" in text or "vulnerability effect command_injection" in text


def test_unknown_step_without_evidence_is_omitted():
    result = _result(evidence=[_step(step_id="step-unmapped-xyz", sequence=1, selected=None, candidates=[])])
    text = _d3fend_text(result, CONSTRAINED)
    assert "Step step-unmapped-xyz:" not in text
    assert text == f"{D3FEND_SECTION_TITLE}\n{'-' * len(D3FEND_SECTION_TITLE)}\n{NO_D3FEND_CONTROL}"


def test_repeated_calls_are_byte_identical():
    result = _result(evidence=[_step()])
    first = _d3fend_text(result)
    second = _d3fend_text(result)
    assert first == second
    report = build_d3fend_control_report(
        result,
        scenario_dir=FULL,
        csaf_dir=CSAF,
        attack_sources=ATTACK,
    )
    again = build_d3fend_control_report(
        result,
        scenario_dir=FULL,
        csaf_dir=CSAF,
        attack_sources=ATTACK,
    )
    assert [item.to_dict() for item in _flat(report)] == [item.to_dict() for item in _flat(again)]


def test_does_not_mutate_scenario_result():
    candidate = _candidate()
    step = _step(candidates=[candidate])
    result = _result(evidence=[step])
    before = deepcopy(step.to_dict())
    narrative = result.narrative
    _d3fend_text(result)
    assert result.narrative == narrative
    assert result.evidence[0].to_dict() == before


def test_d3fend_modules_are_deterministic_and_offline():
    import rag.defense.d3fend_catalog as catalog
    import rag.defense.d3fend_controls as controls

    for module in (catalog, controls):
        source = inspect.getsource(module)
        assert "ollama" not in source.lower()
        assert "rag.generation" not in source
        assert "random" not in source
        assert "datetime" not in source
