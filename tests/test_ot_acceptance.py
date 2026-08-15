from __future__ import annotations

from pathlib import Path

import pytest

from rag.cli import build_retriever
from rag.retrieval.identifier_lookup import lookup_by_identifiers
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import StepEnrichment


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def retriever():
    return build_retriever(ROOT, deterministic=True, reindex=False)


@pytest.mark.parametrize(
    ("scenario_id", "step_id", "expected_cve"),
    [
        ("TS-OT-TEST-003", "replay", "CVE-2023-6374"),
        ("TS-OT-TEST-004", "crafted", "CVE-2023-2262"),
        ("TS-OT-TEST-005", "execute", "CVE-2024-7513"),
        ("TS-OT-TEST-007", "settings", "CVE-2024-7960"),
    ],
)
def test_ot_positive_scenarios_surface_expected_cve(
    retriever,
    scenario_id: str,
    step_id: str,
    expected_cve: str,
):
    bundle = load_scenario_bundle(ROOT / "examples" / scenario_id)
    step = next(item for item in bundle.scenario.attack_path if item.step_id == step_id)
    target = bundle.components_by_id[step.target_component_id or ""]
    reference = target.advisory_reference()
    assert reference

    texts = [hit.text for hit in lookup_by_identifiers(retriever.bm25_retriever.chunks, reference)]
    assert texts

    enrichment = StepEnrichment(
        step=step,
        primary_query="test",
        primary_answer="test",
        retrieved_text="\n\n".join(texts),
    )
    candidates = evaluate_cve_candidates(enrichment, target, step, bundle)
    match = next((item for item in candidates if item.cve_id == expected_cve), None)

    assert match is not None
    product = next(check.status.value for check in match.checks if check.name == "product")
    # Indexed CSV/advisory-aggregate rows are WEAK_DISCOVERY; CSAF known_affected
    # without source-stated model/part is SOURCE_MEMBERSHIP. Neither is product TRUE.
    if product == "unknown":
        assert not match.is_usable
        assert match.final_status == "insufficient_context"
    else:
        assert match.is_usable
        assert match.disposition in {"applicable", "conditional"}
        assert match.final_status.startswith("conditional") or match.final_status in {
            "applicable",
            "verified_applicable",
        }


def test_ot_negative_version_scenario_rejects_mismatched_firmware(retriever):
    bundle = load_scenario_bundle(ROOT / "examples" / "TS-OT-TEST-006")
    step = next(item for item in bundle.scenario.attack_path if item.step_id == "crafted")
    target = bundle.components_by_id[step.target_component_id or ""]
    reference = target.advisory_reference()
    texts = [hit.text for hit in lookup_by_identifiers(retriever.bm25_retriever.chunks, reference or "")]
    enrichment = StepEnrichment(
        step=step,
        primary_query="test",
        primary_answer="test",
        retrieved_text="\n\n".join(texts),
    )
    candidates = evaluate_cve_candidates(enrichment, target, step, bundle)
    match = next((item for item in candidates if item.cve_id == "CVE-2020-16850"), None)

    assert match is not None
    assert not match.is_usable
    assert match.disposition == "rejected"
    assert match.final_status in {"rejected_version_mismatch", "insufficient_context"}
