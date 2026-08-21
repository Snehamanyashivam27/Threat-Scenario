from __future__ import annotations

"""Discovery ≠ validation ≠ selection. UNKNOWN is not FALSE."""

from rag.scenario.applicability import FinalStatus, compute_final_status, disposition_from_final_status
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, TruthValue
from rag.scenario.models import AttackStep, ComponentModel, ComponentSource, StepEnrichment
from rag.scenario.narrative_generator import DiscoveryHarvest, ScenarioNarrativeGenerator
from rag.scenario.step_cve_selection import select_best_step_candidate


def _step() -> AttackStep:
    return AttackStep(
        sequence=3,
        step_id="exploit",
        name="Compromise Controller",
        source_component_id="src-1",
        target_component_id="cmp-1",
        description="The attacker compromises the controller.",
    )


def _component(**overrides) -> ComponentModel:
    values = {
        "id": "cmp-1",
        "name": "Orion GridBridge G7",
        "vendor": "Orion Industrial",
        "product_family": "GridBridge",
        "model": "G7",
        "firmware_version": "V4.2",
        "source": ComponentSource(reference="ICSA-32-001-01"),
    }
    values.update(overrides)
    return ComponentModel(**values)


def _candidate(
    *,
    disposition: str,
    final_status: str,
    product: TruthValue,
    version: TruthValue,
    effect: TruthValue,
    cve_id: str = "CVE-2032-10001",
) -> CandidateEvidence:
    return CandidateEvidence(
        cve_id=cve_id,
        advisory_id="ICSA-32-001-01",
        disposition=disposition,
        final_status=final_status,
        checks=[
            ApplicabilityCheck("product", product),
            ApplicabilityCheck("version", version),
            ApplicabilityCheck("technical_effect", effect),
        ],
    )


def test_version_false_wins_over_product_unknown():
    status = compute_final_status(
        [
            ApplicabilityCheck("product", TruthValue.UNKNOWN),
            ApplicabilityCheck("version", TruthValue.FALSE),
            ApplicabilityCheck("technical_effect", TruthValue.UNKNOWN),
        ]
    )
    assert status == FinalStatus.REJECTED_VERSION_MISMATCH
    assert disposition_from_final_status(status) == "rejected"


def test_product_unknown_without_false_gates_is_insufficient_not_rejected():
    status = compute_final_status(
        [
            ApplicabilityCheck("product", TruthValue.UNKNOWN),
            ApplicabilityCheck("version", TruthValue.NOT_APPLICABLE),
            ApplicabilityCheck("technical_effect", TruthValue.UNKNOWN),
        ]
    )
    assert status == FinalStatus.INSUFFICIENT_CONTEXT
    assert disposition_from_final_status(status) == "insufficient"


def test_effect_unknown_with_product_true_is_insufficient_not_selected():
    status = compute_final_status(
        [
            ApplicabilityCheck("product", TruthValue.TRUE),
            ApplicabilityCheck("version", TruthValue.TRUE),
            ApplicabilityCheck("technical_effect", TruthValue.UNKNOWN),
        ]
    )
    assert status == FinalStatus.INSUFFICIENT_CONTEXT
    assert disposition_from_final_status(status) == "insufficient"
    candidate = _candidate(
        disposition="insufficient",
        final_status=status.value,
        product=TruthValue.TRUE,
        version=TruthValue.TRUE,
        effect=TruthValue.UNKNOWN,
    )
    selection = select_best_step_candidate("exploit", [candidate], step=_step(), component=_component())
    assert selection.selected is None
    assert selection.reason == "insufficient"


def test_empty_candidate_universe_is_abstain():
    selection = select_best_step_candidate("exploit", [], step=_step(), component=_component())
    assert selection.selected is None
    assert selection.reason == "abstain"


def test_all_rejected_candidates_are_rejected_not_abstain():
    candidate = _candidate(
        disposition="rejected",
        final_status="rejected_version_mismatch",
        product=TruthValue.TRUE,
        version=TruthValue.FALSE,
        effect=TruthValue.TRUE,
    )
    selection = select_best_step_candidate("exploit", [candidate], step=_step(), component=_component())
    assert selection.selected is None
    assert selection.reason == "rejected"


def test_weak_csv_product_stays_evaluated_as_insufficient():
    text = "\n".join(
        [
            "Advisory: Family-only listing",
            "ICS Advisory: ICSA-32-001-01",
            "Vendor: Orion Industrial",
            "Product: GridBridge G7",
            "Affected Products: GridBridge G7",
            "CVE: CVE-2032-10001",
            "CWE: CWE-77",
        ]
    )
    enrichment = StepEnrichment(
        step=_step(),
        primary_query="q",
        primary_answer="a",
        retrieved_text=text,
        advisory_context=text,
    )
    candidates = evaluate_cve_candidates(enrichment, _component(), _step(), None)
    match = next(item for item in candidates if item.cve_id == "CVE-2032-10001")
    product = next(check.status for check in match.checks if check.name == "product")
    assert product == TruthValue.UNKNOWN
    assert match.disposition == "insufficient"
    assert match.final_status == "insufficient_context"
    assert not match.is_usable
    selection = select_best_step_candidate("exploit", candidates, step=_step(), component=_component())
    assert selection.selected is None
    assert selection.reason == "insufficient"


def test_identifier_lookup_texts_are_admitted_when_rrf_missed_them():
    harvest = DiscoveryHarvest(
        ids=["CVE-2099-1"],
        ranks={"CVE-2099-1": 2},
        identity={"CVE-2099-1": 1},
        guaranteed=set(),
        sources={"CVE-2099-1": "other"},
        kinds={"CVE-2099-1": "aggregate"},
        objectives={"CVE-2099-1": 1},
    )
    merged = ScenarioNarrativeGenerator._admit_identifier_cves(
        harvest,
        ["Advisory: ICSA-32-001-01\nCVE: CVE-2032-10001\nProduct: GridBridge G7"],
        identity_fields={"product": ["GridBridge"], "model": ["G7"], "vendor": ["Orion"], "part": []},
        step=_step(),
    )
    assert "CVE-2032-10001" in merged.ids
    assert merged.kinds["CVE-2032-10001"] == "identifier"
    assert merged.ranks["CVE-2032-10001"] == 0
