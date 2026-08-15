from __future__ import annotations

"""Generic discovery-admission tests — synthetic IDs only, no benchmark fixtures."""

from types import SimpleNamespace
from unittest.mock import Mock

from rag.generation.rag_assistant import RAGAssistant
from rag.models.answer import AnswerResult
from rag.models.document import RetrievedChunk
from rag.retrieval.context_selector import ContextSelector
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.models import (
    AttackStep,
    AttackerProfile,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)
from rag.scenario.narrative_generator import (
    CSAF_EXPANSION_CAP,
    DiscoveryHarvest,
    ScenarioNarrativeGenerator,
)
from rag.scenario.step_cve_selection import select_best_step_candidate


def _answer_with_rrf(hits: list[dict]) -> AnswerResult:
    return AnswerResult(
        question="q",
        answer="",
        retrieval_trace={"query": "q", "rrf": hits, "selected": [], "vector": [], "bm25": []},
    )


def test_aggregate_advisory_contributes_all_of_its_ids():
    result = _answer_with_rrf(
        [
            {
                "rank": 9,
                "document_id": "agg-1",
                "source": "CISA_ICS_ADV_Master.csv",
                "score": 0.1,
                "cves": ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-10003"],
                "text_preview": "Product GridBridge G7 affected by multiple issues.",
            }
        ]
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result],
        prefer_tokens=["GridBridge", "G7"],
        lane="rrf",
    )
    assert harvest.ids == ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-10003"]
    assert harvest.ranks["CVE-2099-10001"] == 9
    assert not harvest.guaranteed


def test_canonical_per_cve_rrf_hit_is_guaranteed():
    result = _answer_with_rrf(
        [
            {
                "rank": 1,
                "document_id": "agg-noise",
                "source": "CISA_ICS_ADV_Master.csv",
                "score": 1.0,
                "cves": [f"CVE-2099-{i:05d}" for i in range(1, 20)],
                "text_preview": "Unrelated vendor family advisory.",
            },
            {
                "rank": 8,
                "document_id": "ICSA-99-001-01::CVE-2099-55555",
                "source": "cisa_csaf",
                "score": 0.2,
                "cves": ["CVE-2099-55555"],
                "text_preview": "CVE-2099-55555 affects Orion GridBridge G7.",
            },
        ]
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result],
        prefer_tokens=["Orion", "GridBridge", "G7"],
        lane="rrf",
    )
    assert "CVE-2099-55555" in harvest.ids
    assert "CVE-2099-55555" in harvest.guaranteed
    assert harvest.identity["CVE-2099-55555"] >= 1

    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=list(harvest.ids),
        prefer_tokens=["Orion", "GridBridge", "G7"],
        harvested_rank={cve: 8 if cve == "CVE-2099-55555" else 1 for cve in harvest.ids},
        harvested_identity=harvest.identity,
        harvested_kinds=harvest.kinds,
        guaranteed_cves=harvest.guaranteed,
    )
    survivors = ordered[:CSAF_EXPANSION_CAP]
    assert "CVE-2099-55555" in survivors


def test_identity_prioritized_ids_win_scarce_expansion_slots():
    noise = [f"CVE-2099-{i:05d}" for i in range(1, 30)]
    relevant = "CVE-2099-90001"
    result = _answer_with_rrf(
        [
            {
                "rank": 1,
                "document_id": "noise-agg",
                "source": "CISA_ICS_ADV_Master.csv",
                "cves": noise,
                "text_preview": "Generic unrelated industrial products.",
            },
            {
                "rank": 9,
                "document_id": "target-agg",
                "source": "CISA_ICS_ADV_Master.csv",
                "cves": [relevant, "CVE-2099-90002"],
                "text_preview": "Orion GridBridge G7 part OR-G7-1000 command injection.",
            },
        ]
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result],
        prefer_tokens=["Orion", "GridBridge", "G7", "OR-G7-1000"],
        lane="rrf",
    )
    assert relevant in harvest.ids
    assert harvest.identity[relevant] > harvest.identity.get(noise[0], 0)

    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=list(harvest.ids),
        prefer_tokens=["Orion", "GridBridge", "G7", "OR-G7-1000"],
        harvested_rank=harvest.ranks,
        harvested_identity=harvest.identity,
        harvested_kinds=harvest.kinds,
        guaranteed_cves=harvest.guaranteed,
    )
    survivors = ordered[:CSAF_EXPANSION_CAP]
    assert relevant in survivors
    assert "CVE-2099-90002" in survivors
    assert len(survivors) == CSAF_EXPANSION_CAP


def test_unrelated_ids_can_still_be_pruned_by_expansion_cap():
    harvested = [f"CVE-2099-{i:05d}" for i in range(100, 140)]
    ranks = {cve: index + 1 for index, cve in enumerate(harvested)}
    identity = {cve: 0 for cve in harvested}
    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=harvested,
        prefer_tokens=[],
        harvested_rank=ranks,
        harvested_identity=identity,
        guaranteed_cves=set(),
    )
    survivors = ordered[:CSAF_EXPANSION_CAP]
    assert len(survivors) == CSAF_EXPANSION_CAP
    assert survivors == harvested[:CSAF_EXPANSION_CAP]
    assert harvested[CSAF_EXPANSION_CAP] not in survivors


def test_harvest_ignores_non_advisory_rrf_hits():
    result = _answer_with_rrf(
        [
            {
                "rank": 1,
                "document_id": "attack-1",
                "source": "enterprise-attack.json",
                "cves": ["CVE-2099-99999"],
                "text_preview": "attack pattern",
            },
            {
                "rank": 2,
                "document_id": "agg-1",
                "source": "cisa_csaf",
                "cves": ["CVE-2099-10001"],
                "text_preview": "advisory",
            },
        ]
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result], lane="rrf"
    )
    assert harvest.ids == ["CVE-2099-10001"]


def test_identity_matching_id_survives_blob_noise_and_expansion_cap():
    """A current-step identity match must not lose the cap to blob-first noise."""
    relevant = "CVE-2099-55555"
    blob_noise = " ".join(f"CVE-2099-{i:05d}" for i in range(1, 13))
    noise = [f"CVE-2099-{i:05d}" for i in range(1, 20)]
    result = _answer_with_rrf(
        [
            {
                "rank": 1,
                "document_id": "noise-agg",
                "source": "CISA_ICS_ADV_Master.csv",
                "cves": noise,
                "text_preview": "Generic unrelated industrial products.",
            },
            {
                "rank": 8,
                "document_id": "ICSA-99-001-01::CVE-2099-55555",
                "source": "cisa_csaf",
                "cves": [relevant],
                "text_preview": "CVE-2099-55555 affects Orion GridBridge G7 via command injection.",
            },
        ]
    )
    step = AttackStep(
        sequence=5,
        step_id="compromise",
        name="Compromise of the Control Component",
        source_component_id="source",
        target_component_id="target",
        description="The attacker attempts to compromise the controller.",
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result],
        prefer_tokens=["Orion", "GridBridge", "G7"],
        step=step,
        lane="rrf",
    )
    assert relevant in harvest.ids
    assert relevant in harvest.guaranteed
    assert harvest.kinds[relevant] == "canonical"

    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob=blob_noise,
        extra_cve_ids=list(harvest.ids),
        prefer_tokens=["Orion", "GridBridge", "G7"],
        harvested_rank=harvest.ranks,
        harvested_identity=harvest.identity,
        harvested_objectives=harvest.objectives,
        harvested_kinds=harvest.kinds,
        guaranteed_cves=harvest.guaranteed,
        step=step,
    )
    survivors = ordered[:CSAF_EXPANSION_CAP]
    assert relevant in survivors
    assert len(survivors) == CSAF_EXPANSION_CAP

    trace = ScenarioNarrativeGenerator._admission_trace(ordered, harvest)
    relevant_row = next(row for row in trace if row["cve_id"] == relevant)
    assert relevant_row["admitted"] is True
    assert relevant_row["kind"] == "canonical"
    assert relevant_row["drop_reason"] == ""
    dropped = [row for row in trace if not row["admitted"]]
    assert dropped
    assert all(row["drop_reason"] == "expansion_cap" for row in dropped)


def test_admission_trace_records_expansion_cap():
    harvested = [f"CVE-2099-{i:05d}" for i in range(100, 140)]
    ranks = {cve: index + 1 for index, cve in enumerate(harvested)}
    identity = {cve: 0 for cve in harvested}
    harvest = DiscoveryHarvest(
        ids=harvested,
        ranks=ranks,
        identity=identity,
        guaranteed=set(),
        sources={cve: "agg-1" for cve in harvested},
        kinds={cve: "aggregate" for cve in harvested},
        objectives={cve: 1 for cve in harvested},
    )
    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=harvested,
        harvested_rank=ranks,
        harvested_identity=identity,
        harvested_objectives=harvest.objectives,
        harvested_kinds=harvest.kinds,
        guaranteed_cves=set(),
    )
    trace = ScenarioNarrativeGenerator._admission_trace(ordered, harvest)
    assert len(trace) == len(harvested)
    admitted = [row for row in trace if row["admitted"]]
    dropped = [row for row in trace if not row["admitted"]]
    assert len(admitted) == CSAF_EXPANSION_CAP
    assert dropped[0]["drop_reason"] == "expansion_cap"
    assert dropped[0]["source_document"] == "agg-1"
    assert dropped[0]["kind"] == "aggregate"


def test_lookup_with_extra_cve_ids_and_empty_blob_reaches_csaf_expansion():
    chunk = RetrievedChunk(
        chunk_id="1",
        score=1.0,
        source="cisa_csaf",
        document_id="ICSA-99-001-01::CVE-2099-10001",
        metadata={"kind": "cisa-csaf-cve", "advisory_id": "ICSA-99-001-01"},
        text="CVE: CVE-2099-10001\nDescription: synthetic command injection.",
    )
    retriever = Mock()
    retriever.retrieve_with_debug = Mock(return_value=([], [], [chunk]))
    assistant = SimpleNamespace(retriever=retriever)
    generator = ScenarioNarrativeGenerator(assistant=assistant)  # type: ignore[arg-type]

    texts, sources, traces = generator._lookup_csaf_details_for_cves(
        blob="",
        prefer_tokens=[],
        extra_cve_ids=["CVE-2099-10001"],
        harvested_rank={"CVE-2099-10001": 2},
        harvested_identity={"CVE-2099-10001": 1},
        guaranteed_cves={"CVE-2099-10001"},
    )
    assert texts and "CVE-2099-10001" in texts[0]
    assert sources[0].document_source == "cisa_csaf"
    assert traces and traces[0].query == "CVE-2099-10001"
    retriever.retrieve_with_debug.assert_called()


def test_narrator_context_selector_still_tops_three():
    selector = ContextSelector(max_results=3, min_results=2, retrieval_pool_size=10)
    assert selector.max_results == 3
    chunks = [
        RetrievedChunk(
            chunk_id=str(i),
            score=1.0 - i * 0.01,
            source="cisa_csaf",
            document_id=f"doc-{i}",
            metadata={"kind": "cisa-csaf-cve"},
            text=f"chunk text {i} CVE-2099-{i:05d}",
        )
        for i in range(1, 8)
    ]
    hits = RAGAssistant._trace_hits(chunks)
    assert all("text_preview" in hit for hit in hits)
    assert hits[0]["text_preview"].startswith("chunk text")


def test_validation_and_selection_unchanged_for_synthetic_candidate():
    component = ComponentModel(
        id="target-1",
        name="Orion GridBridge G7",
        vendor="Orion Industrial",
        model="G7",
        part_number="OR-G7-1000",
        firmware_version="V4.2",
    )
    step = AttackStep(
        sequence=3,
        step_id="exploit",
        name="Compromise Controller",
        source_component_id="source-1",
        target_component_id="target-1",
        description="The attacker compromises the controller.",
    )
    text = "\n".join(
        [
            "CVE: CVE-2099-10001",
            "Advisory: ICSA-99-001-01",
            "Vendor: Orion Industrial",
            "Product: Orion GridBridge G7",
            "Model: G7",
            "Part Number: OR-G7-1000",
            "Affected Versions: prior to V5.0",
            "CWE: CWE-77",
            "Description: A command injection vulnerability could allow remote code execution.",
        ]
    )
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="a",
        advisory_context=text,
        retrieved_text=text,
    )
    bundle = ScenarioBundle(
        scenario=ScenarioModel(
            scenario_id="SYN-1",
            title="Synthetic",
            attacker_profile=AttackerProfile(capabilities=[]),
            attack_path=[step],
        ),
        components_by_id={component.id: component},
    )
    candidates = evaluate_cve_candidates(enrichment, component, step, bundle)
    match = next(item for item in candidates if item.cve_id == "CVE-2099-10001")
    selection = select_best_step_candidate("exploit", [match], step=step, component=component)
    assert match.is_usable
    assert selection.selected is not None
    assert selection.selected.cve_id == "CVE-2099-10001"


def test_no_raw_id_harvest_cap_keeps_lower_ranked_relevant_aggregate():
    high_rank_noise = [f"CVE-2099-{i:05d}" for i in range(1, 40)]
    result = _answer_with_rrf(
        [
            {
                "rank": 1,
                "document_id": "noise",
                "source": "CISA_ICS_ADV_Master.csv",
                "cves": high_rank_noise,
                "text_preview": "Unrelated products.",
            },
            {
                "rank": 9,
                "document_id": "2851",
                "source": "CISA_ICS_ADV_Master.csv",
                "cves": ["CVE-2099-31484", "CVE-2099-31485", "CVE-2099-31486"],
                "text_preview": "Orion GridBridge G7 advisory row.",
            },
        ]
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [result],
        prefer_tokens=["Orion", "GridBridge", "G7"],
        lane="rrf",
    )
    assert "CVE-2099-31485" in harvest.ids
    assert harvest.ranks["CVE-2099-31485"] == 9
    assert len(harvest.ids) > 24
    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=list(harvest.ids),
        prefer_tokens=["Orion", "GridBridge", "G7"],
        harvested_rank=harvest.ranks,
        harvested_identity=harvest.identity,
        guaranteed_cves=set(),
    )
    assert "CVE-2099-31485" in ordered[:CSAF_EXPANSION_CAP]


def test_higher_identity_aggregate_outranks_weak_identity_canonicals():
    """Target identity ranks first; canonical vs aggregate is only a tie-break."""
    weak_canonicals = [f"CVE-2099-{i:05d}" for i in range(1, 13)]
    relevant = "CVE-2099-80001"
    identity = {cve: 2 for cve in weak_canonicals}
    identity[relevant] = 7
    kinds = {cve: "canonical" for cve in weak_canonicals}
    kinds[relevant] = "aggregate"
    ranks = {cve: 1 for cve in weak_canonicals}
    ranks[relevant] = 10
    objectives = {cve: 1 for cve in weak_canonicals}
    objectives[relevant] = 2
    all_ids = weak_canonicals + [relevant]
    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=all_ids,
        harvested_rank=ranks,
        harvested_identity=identity,
        harvested_objectives=objectives,
        harvested_kinds=kinds,
        guaranteed_cves=set(weak_canonicals),
    )
    survivors = ordered[:CSAF_EXPANSION_CAP]
    assert ordered[0] == relevant
    assert relevant in survivors
    harvest = DiscoveryHarvest(
        ids=all_ids,
        ranks=ranks,
        identity=identity,
        guaranteed=set(weak_canonicals),
        sources={cve: f"ICSA-99-001-01::{cve}" for cve in weak_canonicals} | {relevant: "2851"},
        kinds=kinds,
        objectives=objectives,
    )
    trace = ScenarioNarrativeGenerator._admission_trace(ordered, harvest)
    relevant_row = next(row for row in trace if row["cve_id"] == relevant)
    assert relevant_row["admitted"] is True
    assert relevant_row["kind"] == "aggregate"
    assert relevant_row["identity_score"] == 7
    assert relevant_row["final_validation_state"] == "not_evaluated"
    dropped_canonical = next(row for row in trace if not row["admitted"])
    assert dropped_canonical["kind"] == "canonical"
    assert dropped_canonical["identity_score"] == 2


def test_harvest_ranks_identity_before_canonical_kind():
    weak_canonicals = [f"CVE-2099-{i:05d}" for i in range(1, 13)]
    relevant = "CVE-2099-80001"
    hits = [
        {
            "rank": index + 1,
            "document_id": f"ICSA-99-001-01::{cve}",
            "source": "cisa_csaf",
            "cves": [cve],
            "text_preview": f"{cve} affects Helios RelayBox R2.",
        }
        for index, cve in enumerate(weak_canonicals)
    ]
    hits.append(
        {
            "rank": 10,
            "document_id": "2851",
            "source": "CISA_ICS_ADV_Master.csv",
            "cves": [relevant],
            "text_preview": "Orion GridBridge G7 part OR-G7-1000 command injection.",
        }
    )
    harvest = ScenarioNarrativeGenerator._harvest_discovery_cve_ids(
        [_answer_with_rrf(hits)],
        prefer_tokens=["Orion", "GridBridge", "G7", "OR-G7-1000"],
        lane="rrf",
    )
    assert harvest.identity[relevant] > harvest.identity[weak_canonicals[0]]
    assert harvest.kinds[relevant] == "aggregate"
    assert harvest.ids[0] == relevant
    ordered = ScenarioNarrativeGenerator._order_cves_for_expansion(
        blob="",
        extra_cve_ids=list(harvest.ids),
        prefer_tokens=["Orion", "GridBridge", "G7", "OR-G7-1000"],
        harvested_rank=harvest.ranks,
        harvested_identity=harvest.identity,
        harvested_objectives=harvest.objectives,
        harvested_kinds=harvest.kinds,
        guaranteed_cves=harvest.guaranteed,
    )
    assert ordered[0] == relevant
    assert relevant in ordered[:CSAF_EXPANSION_CAP]


def test_admission_trace_joins_final_validation_state():
    ordered = ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-99999"]
    harvest = DiscoveryHarvest(
        ids=ordered,
        ranks={"CVE-2099-10001": 1, "CVE-2099-10002": 2, "CVE-2099-99999": 3},
        identity={"CVE-2099-10001": 7, "CVE-2099-10002": 2, "CVE-2099-99999": 0},
        guaranteed={"CVE-2099-10001"},
        sources={cve: "agg-1" for cve in ordered},
        kinds={cve: "aggregate" for cve in ordered},
        objectives={cve: 1 for cve in ordered},
    )
    trace = ScenarioNarrativeGenerator._admission_trace(ordered, harvest)
    candidates = [
        SimpleNamespace(cve_id="CVE-2099-10001", final_status="conditional_version_unknown"),
        SimpleNamespace(cve_id="CVE-2099-10002", final_status="insufficient_context"),
    ]
    ScenarioNarrativeGenerator._annotate_admission_validation(trace, candidates)
    by_cve = {row["cve_id"]: row for row in trace}
    assert by_cve["CVE-2099-10001"]["final_validation_state"] == "conditional_version_unknown"
    assert by_cve["CVE-2099-10002"]["final_validation_state"] == "insufficient_context"
    assert by_cve["CVE-2099-99999"]["final_validation_state"] == "not_evaluated"
