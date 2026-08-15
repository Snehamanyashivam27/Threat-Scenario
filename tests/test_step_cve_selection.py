from __future__ import annotations

from rag.scenario.applicability import classify_step_objective
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, TruthValue
from rag.scenario.models import AttackStep, ComponentModel, ComponentSource
from rag.scenario.step_cve_selection import select_best_step_candidate


def _step(**overrides) -> AttackStep:
    values = {
        "sequence": 3,
        "step_id": "exploit",
        "name": "Compromise Controller",
        "source_component_id": "source-1",
        "target_component_id": "target-1",
        "description": "The attacker exploits an applicable vulnerability to compromise the controller.",
    }
    values.update(overrides)
    return AttackStep(**values)


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "target-1",
        "name": "Acme Controller X100",
        "vendor": "Acme Controls",
        "product_family": "Controller",
        "model": "X100",
        "source": ComponentSource(reference="ICSA-24-030-03"),
    }
    values.update(overrides)
    return ComponentModel(**values)


def _candidate(
    cve_id: str,
    *,
    disposition: str = "conditional",
    product: TruthValue = TruthValue.TRUE,
    version: TruthValue = TruthValue.UNKNOWN,
    effect: TruthValue = TruthValue.TRUE,
    advisory_id: str | None = "ICSA-24-030-03",
    rank_score: int = 100,
) -> CandidateEvidence:
    return CandidateEvidence(
        cve_id=cve_id,
        advisory_id=advisory_id,
        disposition=disposition,
        final_status="conditional_version_unknown",
        checks=[
            ApplicabilityCheck("product", product),
            ApplicabilityCheck("version", version),
            ApplicabilityCheck("technical_effect", effect),
        ],
        rank_score=rank_score,
    )


def test_selects_at_most_one_candidate():
    candidates = [
        _candidate("CVE-2030-10001", rank_score=200),
        _candidate("CVE-2030-10002", rank_score=100),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-10001"


def test_rejects_effect_mismatch_candidates():
    candidates = [
        _candidate("CVE-2030-10001", effect=TruthValue.FALSE, disposition="rejected"),
        _candidate("CVE-2030-10002", effect=TruthValue.TRUE),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-10002"


def test_prefers_component_advisory_reference():
    candidates = [
        _candidate("CVE-2030-10001", advisory_id="2612", rank_score=500),
        _candidate("CVE-2030-10002", advisory_id="ICSA-24-030-03", rank_score=100),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-10002"


def test_skips_already_used_cves():
    candidates = [
        _candidate("CVE-2030-10001"),
        _candidate("CVE-2030-10002"),
    ]
    selection = select_best_step_candidate(
        "exploit",
        candidates,
        component=_component(),
        used_cves={"CVE-2030-10001"},
    )

    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-10002"


def test_returns_null_when_no_eligible_candidates():
    candidates = [
        _candidate("CVE-2030-10001", effect=TruthValue.FALSE, disposition="rejected"),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is None


def test_conditional_unknown_effect_not_eliminated_by_advisory_id_mismatch():
    """Advisory-id mismatch must not hard-reject; effect TRUE is required for selection."""
    candidates = [
        _candidate(
            "CVE-2030-10001",
            disposition="conditional",
            product=TruthValue.TRUE,
            version=TruthValue.UNKNOWN,
            effect=TruthValue.TRUE,
            advisory_id="2748",
            rank_score=100,
        ),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2030-10001"
    assert selection.selected.disposition == "conditional"


def test_unknown_effect_without_taxonomy_evidence_not_selected():
    candidates = [
        _candidate(
            "CVE-2030-10001",
            disposition="conditional",
            product=TruthValue.TRUE,
            version=TruthValue.UNKNOWN,
            effect=TruthValue.UNKNOWN,
            advisory_id="2748",
        ),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is None


def test_unknown_effect_with_taxonomy_still_not_selected_for_specific_step():
    """UNKNOWN effect must not authorize a specific attack-step claim."""
    candidates = [
        _candidate(
            "CVE-2030-10001",
            disposition="conditional",
            product=TruthValue.TRUE,
            version=TruthValue.TRUE,
            effect=TruthValue.UNKNOWN,
        ),
    ]
    candidates[0].checks = [
        ApplicabilityCheck("product", TruthValue.TRUE),
        ApplicabilityCheck("version", TruthValue.TRUE),
        ApplicabilityCheck("technical_effect", TruthValue.UNKNOWN, observed="session_hijack"),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is None


def test_rejected_disposition_never_selected():
    candidates = [
        _candidate(
            "CVE-2030-10001",
            disposition="rejected",
            product=TruthValue.TRUE,
            effect=TruthValue.FALSE,
        ),
    ]
    selection = select_best_step_candidate("exploit", candidates, component=_component())

    assert selection.selected is None


def test_capture_step_objective_classifies_authentication_capture():
    step = _step(
        step_id="capture",
        name="Capture Authentication Exchange",
        description="The attacker captures a legitimate authentication exchange.",
    )

    objective = classify_step_objective(step)

    assert objective.value == "session_compromise"
