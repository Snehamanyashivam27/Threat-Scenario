from __future__ import annotations

import inspect
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

from rag.defense.models import RecommendationPolicyState
from rag.defense.recommendation_policy import SOURCE_ATTACK, SOURCE_CSAF
from rag.defense.report_pipeline import (
    D3FEND_SECTION_TITLE,
    NO_ACTIONABLE_RECOMMENDATION,
    SECTION_TITLE,
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
EXAMPLES_CONSTRAINED = ROOT / "examples" / "TS-OT-CONSTRAINED-001"
NARRATIVE = "Threat narrative."


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
    traces: list[dict] | None = None,
    unresolved: list[str] | None = None,
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
        unresolved_conditions=list(unresolved or []),
        product_evidence_trace=list(traces if traces is not None else [_trace()]),
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
    narrative: str = NARRATIVE,
) -> ScenarioNarrativeResult:
    return ScenarioNarrativeResult(
        scenario_id=scenario_id,
        title="Defense CLI",
        narrative=narrative,
        evidence=list(evidence if evidence is not None else [_step()]),
    )


def _text(
    result: ScenarioNarrativeResult,
    scenario_dir: Path,
    csaf_dir: Path = CSAF,
    attack_sources: Path = ATTACK,
) -> str:
    return build_defense_recommendation_text(
        result,
        scenario_dir=scenario_dir,
        csaf_dir=csaf_dir,
        attack_sources=attack_sources,
    )


def _report(
    result: ScenarioNarrativeResult,
    scenario_dir: Path,
    csaf_dir: Path = CSAF,
    attack_sources: Path = ATTACK,
):
    return build_defense_recommendation_report(
        result,
        scenario_dir=scenario_dir,
        csaf_dir=csaf_dir,
        attack_sources=attack_sources,
    )


def _flat(report):
    return [item for step in report.steps for item in step.recommendations]


def _run_cli(monkeypatch, capsys, argv: list[str], result: ScenarioNarrativeResult, retriever_calls: list | None = None):
    class FakeGenerator:
        def __init__(self, **kwargs):
            pass

        def generate(self, scenario):
            return result

    def fake_retriever(root, deterministic=False, reindex=False):
        if retriever_calls is not None:
            retriever_calls.append({"root": root, "deterministic": deterministic, "reindex": reindex})
        return MagicMock()

    monkeypatch.setattr("rag.scenario.cli.build_retriever", fake_retriever)
    monkeypatch.setattr("rag.scenario.cli.create_answer_service", lambda **kwargs: MagicMock())
    monkeypatch.setattr("rag.scenario.cli.RAGAssistant", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr("rag.scenario.cli.ScenarioNarrativeSynthesizer", lambda **kwargs: MagicMock())
    monkeypatch.setattr("rag.scenario.cli.ScenarioSynthesisAnswerService", lambda **kwargs: MagicMock())
    monkeypatch.setattr("rag.scenario.cli.ScenarioNarrativeGenerator", FakeGenerator)
    monkeypatch.setattr(sys, "argv", argv)
    from rag.scenario.cli import main

    main()
    captured = capsys.readouterr()
    return captured.out, captured.err


def test_default_cli_output_unchanged(monkeypatch, capsys):
    result = _result()
    out, err = _run_cli(
        monkeypatch,
        capsys,
        ["rag.scenario.cli", "--scenario", str(CONSTRAINED), "--deterministic"],
        result,
    )
    assert out == f"{NARRATIVE}\n\n"
    assert SECTION_TITLE not in out
    assert D3FEND_SECTION_TITLE not in out
    assert "ATT&CK" not in out
    assert "Vendor remediation" not in out
    assert err == ""


def test_show_defenses_appends_section_after_narrative(monkeypatch, capsys, tmp_path):
    csaf_dir = tmp_path / "data" / "cisa_csaf"
    csaf_dir.mkdir(parents=True)
    shutil.copy(CSAF / "remediation-inventory.json", csaf_dir / "remediation-inventory.json")
    shutil.copy(ATTACK / "enterprise-mitigations.json", tmp_path / "enterprise-mitigations.json")
    result = _result(evidence=[_step()])
    out, _ = _run_cli(
        monkeypatch,
        capsys,
        [
            "rag.scenario.cli",
            "--scenario",
            str(FULL),
            "--root",
            str(tmp_path),
            "--show-defenses",
            "--deterministic",
        ],
        result,
    )
    assert out.startswith(f"{NARRATIVE}\n\n{SECTION_TITLE}\n")
    assert "Vendor remediation: Update to V2.0." in out
    assert D3FEND_SECTION_TITLE in out
    assert "Isolate — D3-NI Network Isolation:" in out
    assert out.index(NARRATIVE) < out.index(SECTION_TITLE) < out.index(D3FEND_SECTION_TITLE)


def test_stage6_rendered_text_is_reused_not_rewritten():
    result = _result(evidence=[_step()])
    report = _report(result, FULL)
    formatted = format_defense_recommendations(report)
    for index, item in enumerate(_flat(report), start=1):
        assert f"{index}. {item.rendered_text}" in formatted
    assert "You should" not in formatted
    assert "recommend applying" not in formatted.lower()


def test_only_eligible_and_conditional_appear():
    report = _report(_result(evidence=[_step()]), FULL)
    states = {item.policy_state for item in _flat(report)}
    assert states <= {RecommendationPolicyState.ELIGIBLE, RecommendationPolicyState.CONDITIONAL}
    assert RecommendationPolicyState.SUPPRESSED not in states
    assert RecommendationPolicyState.INFORMATIONAL not in states


def test_suppressed_never_printed():
    result = _result(
        evidence=[
            _step(
                selected="CVE-2030-80001",
                candidates=[_candidate(product=TruthValue.FALSE)],
            )
        ]
    )
    text = _text(result, FULL)
    assert "Rejected" not in text
    report = _report(result, FULL)
    assert all(item.policy_state is not RecommendationPolicyState.SUPPRESSED for item in _flat(report))


def test_informational_not_mixed_into_actionable_output():
    result = _result(
        evidence=[
            _step(
                selected="CVE-2030-80003",
                candidates=[_candidate("CVE-2030-80003")],
            )
        ]
    )
    text = _text(result, FULL)
    assert "no remediation is available" not in text
    assert "Currently no fix is available" not in text
    report = _report(result, FULL)
    assert all(item.policy_state is not RecommendationPolicyState.INFORMATIONAL for item in _flat(report))
    assert "ATT&CK technique-level mitigation:" in text


def test_no_actionable_evidence_prints_neutral_message():
    result = _result(evidence=[_step(selected=None, candidates=[])])
    text = _text(result, CONSTRAINED)
    assert text == f"{SECTION_TITLE}\n{'-' * len(SECTION_TITLE)}\n{NO_ACTIONABLE_RECOMMENDATION}"
    assert "You should" not in text
    assert "firewall" not in text.lower()


def test_csaf_only_scenario_prints_csaf_recommendations():
    result = _result(evidence=[_step()])
    text = _text(result, CONSTRAINED)
    assert "Vendor remediation: Update to V2.0." in text
    assert "Source: CVE: CVE-2030-80001. Advisory: ICSA-30-001-01." in text
    assert "ATT&CK" not in text


def test_attack_only_fixture_prints_technique_level_recommendation():
    result = _result(evidence=[_step(selected=None, candidates=[])])
    text = _text(result, FULL)
    assert "ATT&CK technique-level mitigation: Network Isolation." in text
    assert "Vendor remediation:" not in text
    assert "Source: Technique: T9990. ATT&CK mitigation: M9991." in text


def test_both_sources_print_independently():
    result = _result(evidence=[_step()])
    report = _report(result, FULL)
    kinds = [item.source_type for item in _flat(report)]
    assert SOURCE_CSAF in kinds
    assert SOURCE_ATTACK in kinds
    text = format_defense_recommendations(report)
    assert "Vendor remediation: Update to V2.0." in text
    assert "ATT&CK technique-level mitigation: Network Isolation." in text


def test_no_attack_technique_id_does_not_infer():
    result = _result(evidence=[_step(step_id="step-prose-only", sequence=1)])
    text = _text(result, FULL)
    assert "ATT&CK" not in text
    assert "Vendor remediation: Update to V2.0." in text


def test_constrained_scenario_has_no_attack_output():
    result = _result(scenario_id="TS-DEF-CONSTRAINED-001", evidence=[_step()])
    text = _text(result, CONSTRAINED)
    assert "ATT&CK" not in text
    example = _text(
        _result(scenario_id="TS-OT-CONSTRAINED-001", evidence=[_step(step_id="step-compromise", sequence=5)]),
        EXAMPLES_CONSTRAINED,
    )
    assert "ATT&CK" not in example


def test_citations_use_structured_ids_not_paths():
    text = _text(_result(evidence=[_step()]), FULL)
    assert "CVE: CVE-2030-80001" in text
    assert "Advisory: ICSA-30-001-01" in text
    assert "Technique: T9990" in text
    assert "ATT&CK mitigation: M9991" in text
    assert "/tmp/" not in text
    assert "source_path" not in text
    assert "enterprise-mitigations.json" not in text
    assert "remediation-inventory.json" not in text


def test_recommendation_order_matches_stage6():
    result = _result(evidence=[_step()])
    report = _report(result, FULL)
    formatted = format_defense_recommendations(report)
    items = _flat(report)
    positions = [formatted.index(f"{index}. {item.rendered_text}") for index, item in enumerate(items, start=1)]
    assert positions == sorted(positions)
    again = _report(result, FULL)
    assert [item.recommendation_id for item in items] == [item.recommendation_id for item in _flat(again)]
    assert [item.rendered_text for item in items] == [item.rendered_text for item in _flat(again)]


def test_repeated_calls_are_byte_identical():
    result = _result(evidence=[_step()])
    first = _text(result, FULL)
    second = _text(result, FULL)
    assert first == second
    assert "created" not in first
    assert "timestamp" not in first.lower()


def test_cli_show_defenses_does_not_reindex(monkeypatch, capsys, tmp_path):
    calls: list[dict] = []
    csaf_dir = tmp_path / "data" / "cisa_csaf"
    csaf_dir.mkdir(parents=True)
    shutil.copy(CSAF / "remediation-inventory.json", csaf_dir / "remediation-inventory.json")
    _run_cli(
        monkeypatch,
        capsys,
        [
            "rag.scenario.cli",
            "--scenario",
            str(CONSTRAINED),
            "--root",
            str(tmp_path),
            "--show-defenses",
            "--deterministic",
        ],
        _result(evidence=[_step()]),
        retriever_calls=calls,
    )
    assert calls
    assert calls[0]["reindex"] is False


def test_pipeline_does_not_call_llm():
    import rag.defense.d3fend_controls as d3fend_controls
    import rag.defense.report_pipeline as pipeline

    source = inspect.getsource(pipeline)
    assert "ollama" not in source.lower()
    assert "rag.generation" not in source
    assert "RAGAssistant" not in source
    assert "create_answer_service" not in source
    assert "ScenarioNarrativeSynthesizer" not in source
    assert inspect.getsource(pipeline.build_defense_recommendation_report).count(
        "render_actionable_recommendations"
    ) == 1
    d3fend_source = inspect.getsource(d3fend_controls)
    assert "ollama" not in d3fend_source.lower()
    assert "rag.generation" not in d3fend_source


def test_no_mutation_of_scenario_narrative_result():
    candidate = _candidate()
    step = _step(candidates=[candidate])
    result = _result(evidence=[step])
    before = deepcopy(step.to_dict())
    narrative = result.narrative
    evidence_id = id(result.evidence)
    step_id = id(step)
    candidate_id = id(candidate)
    _text(result, FULL)
    assert result.narrative == narrative
    assert id(result.evidence) == evidence_id
    assert id(result.evidence[0]) == step_id
    assert id(result.evidence[0].candidates[0]) == candidate_id
    assert result.evidence[0].to_dict() == before


def test_empty_steps_are_omitted_when_other_steps_have_recommendations():
    result = _result(
        evidence=[
            _step(step_id="step-prose-only", sequence=1, selected=None, candidates=[]),
            _step(step_id="step-external-id", sequence=2),
        ]
    )
    text = _text(result, FULL)
    assert "Step step-external-id:" in text
    assert "Step step-prose-only:" not in text
    assert NO_ACTIONABLE_RECOMMENDATION not in text


def test_cli_without_flag_does_not_run_defense_pipeline(monkeypatch, capsys):
    calls: list[str] = []

    def fake_build(*args, **kwargs):
        calls.append("build")
        raise AssertionError("defense pipeline must not run without --show-defenses")

    monkeypatch.setattr(
        "rag.defense.report_pipeline.build_defense_recommendation_text",
        fake_build,
    )
    out, _ = _run_cli(
        monkeypatch,
        capsys,
        ["rag.scenario.cli", "--scenario", str(CONSTRAINED), "--deterministic"],
        _result(),
    )
    assert calls == []
    assert out == f"{NARRATIVE}\n\n"
