from __future__ import annotations

# RETRIEVAL FINDS CANDIDATES.
# CANONICAL EVIDENCE DEFINES FACTS.
# VALIDATION DETERMINES APPLICABILITY.
# EFFECT COMPATIBILITY DETERMINES WHETHER A CVE EXPLAINS A STEP.
# STEP SELECTION CHOOSES THE BEST CANDIDATE.
# THE LLM ONLY NARRATES THE RESULT.
#
# PRODUCT MATCH != STEP APPLICABILITY.
# UNKNOWN != FALSE.
# UNKNOWN EFFECT != PROOF OF A SPECIFIC ATTACK CAPABILITY.
#
# CVE METADATA MUST NEVER LEAK BETWEEN CVES.
# A SELECTED CVE MUST NEVER DISAPPEAR WITHOUT AN AUDITABLE REASON.

from pathlib import Path
import re
from typing import Callable, Iterable, NamedTuple

from rag.generation.rag_assistant import RAGAssistant
from rag.models.answer import AnswerResult, SourceReference, dedupe_sources
from rag.retrieval.document_fields import extract_cves
from rag.retrieval.identifier_lookup import ADVISORY_ID_PATTERN, lookup_by_identifiers
from rag.scenario.applicability import (
    DESCRIPTION_EFFECT_PATTERNS,
    EFFECT_OBJECTIVE_MATRIX,
    OBJECTIVE_NEGATIVE_PATTERNS,
    classify_step_objective,
)
from rag.scenario.claim_validator import mark_removed_by_validator, narrative_uses_only_validated_cves
from rag.scenario.cve_validation import evaluate_cve_candidates
from rag.scenario.evidence import RankedHit, RetrievalTrace, StepEvidence
from rag.scenario.loader import load_scenario_bundle
from rag.scenario.models import AttackStep, ScenarioNarrativeResult, StepEnrichment
from rag.scenario.query_builder import StepQueryBuilder
from rag.scenario.canonical_cve import NarratorStepEvidence
from rag.scenario.step_cve_selection import select_best_step_candidate, step_supports_cve_selection
from rag.scenario.step_targets import resolve_step_targets
from rag.scenario.technical_context import facts_as_payload, project_technical_context
from rag.scenario.synthesizer import ScenarioNarrativeSynthesizer

# Discovery admission is wider than narrator ContextSelector truncation.
# Aggregates may contribute CVE IDs; canonical per-CVE CSAF remains the fact source.
# Expensive CSAF expansion is the only hard discovery performance cap.
CSAF_EXPANSION_CAP = 12

_IDENTITY_WEIGHTS = {"vendor": 1, "product": 3, "model": 4, "part": 5}


def _hit_is_canonical_cve_document(hit, cve_id: str) -> bool:
    """Bind CSAF expansion to the queried CVE's own document, not a mention in another advisory."""
    wanted = (cve_id or "").upper()
    if not wanted.startswith("CVE-"):
        return False
    metadata = getattr(hit, "metadata", None) or {}
    meta_cve = str(metadata.get("cve_id") or metadata.get("meta_cve_id") or "").upper()
    if meta_cve:
        return meta_cve == wanted
    sections = metadata.get("sections") or {}
    if isinstance(sections, dict):
        section_cve = str(sections.get("cve_id") or "").upper()
        if section_cve:
            return section_cve == wanted
    document_id = str(getattr(hit, "document_id", "") or "").upper()
    return f"::{wanted}" in document_id or document_id.endswith(wanted)


class DiscoveryHarvest(NamedTuple):
    ids: list[str]
    ranks: dict[str, int]
    identity: dict[str, int]
    guaranteed: set[str]
    sources: dict[str, str]
    kinds: dict[str, str]
    objectives: dict[str, int]


class ScenarioNarrativeGenerator:
    def __init__(
        self,
        assistant: RAGAssistant,
        synthesizer: ScenarioNarrativeSynthesizer | None = None,
        query_builder: StepQueryBuilder | None = None,
        top_k: int = 5,
        on_query: Callable[[str], None] | None = None,
    ):
        self.assistant = assistant
        self.synthesizer = synthesizer or ScenarioNarrativeSynthesizer()
        self.query_builder = query_builder or StepQueryBuilder()
        self.top_k = top_k
        self.on_query = on_query

    def generate(self, scenario_dir: str | Path) -> ScenarioNarrativeResult:
        bundle = load_scenario_bundle(scenario_dir)
        enrichments: list[StepEnrichment] = []
        all_sources: list[SourceReference] = []
        all_evidence: list[StepEvidence] = []
        selected_cves: set[str] = set()

        for step in bundle.scenario.attack_path:
            step_queries = self.query_builder.build_step_queries(bundle, step)
            primary_query = next(item.query for item in step_queries if item.query_type == "primary")
            self._notify_query(primary_query)
            primary_result = self.assistant.ask(primary_query, k=self.top_k)

            advisory_queries = [item.query for item in step_queries if item.query_type == "advisory"]
            advisory_answers: list[str] = []
            advisory_contexts: list[str] = []
            advisory_retrieved: list[str] = []
            advisory_sources: list[SourceReference] = []
            advisory_results = []
            target = bundle.components_by_id.get(step.target_component_id or "")
            roles = resolve_step_targets(step, bundle)
            vulnerable = bundle.components_by_id.get(roles.vulnerable_component_id or "")
            eval_component = vulnerable or target
            reference_texts, reference_sources = self._lookup_component_advisory_reference(eval_component)
            advisory_retrieved.extend(reference_texts)
            advisory_sources.extend(reference_sources)
            for advisory_query in advisory_queries:
                self._notify_query(advisory_query)
                advisory_result = self.assistant.ask(advisory_query, k=self.top_k)
                advisory_results.append(advisory_result)
                advisory_answers.append(advisory_result.answer)
                if advisory_result.context:
                    advisory_contexts.append(advisory_result.context)
                if advisory_result.retrieved_text:
                    advisory_retrieved.append(advisory_result.retrieved_text)
                advisory_sources.extend(advisory_result.sources)

            # Discovery lane: document-first harvest from this step's RRF advisory
            # hits, then rank by step-local identity/objective before the CSAF cap.
            identity_fields = self._identity_fields(eval_component)
            prefer_tokens = [
                token
                for values in identity_fields.values()
                for token in values
                if token
            ]
            harvest = self._harvest_discovery_cve_ids(
                [primary_result, *advisory_results],
                prefer_tokens=prefer_tokens,
                identity_fields=identity_fields,
                step=step,
                lane="rrf",
            )
            harvest = self._admit_identifier_cves(
                harvest,
                reference_texts,
                identity_fields=identity_fields,
                prefer_tokens=prefer_tokens,
                step=step,
            )
            expansion_blob = "\n".join(advisory_retrieved + advisory_answers)
            ordered_cves = self._order_cves_for_expansion(
                expansion_blob,
                extra_cve_ids=list(harvest.ids),
                prefer_tokens=prefer_tokens,
                identity_fields=identity_fields,
                harvested_rank=harvest.ranks,
                harvested_identity=harvest.identity,
                harvested_objectives=harvest.objectives,
                harvested_kinds=harvest.kinds,
                guaranteed_cves=harvest.guaranteed,
                step=step,
            )
            admission_trace = self._admission_trace(ordered_cves, harvest)
            detail_texts, detail_sources, detail_traces = self._lookup_csaf_details_for_cves(
                expansion_blob,
                prefer_tokens=prefer_tokens,
                extra_cve_ids=list(harvest.ids),
                harvested_rank=harvest.ranks,
                harvested_identity=harvest.identity,
                harvested_objectives=harvest.objectives,
                harvested_kinds=harvest.kinds,
                guaranteed_cves=harvest.guaranteed,
                identity_fields=identity_fields,
                step=step,
            )
            advisory_retrieved.extend(detail_texts)
            advisory_sources.extend(detail_sources)

            step_sources = dedupe_sources(primary_result.sources + advisory_sources)
            all_sources.extend(step_sources)

            enrichment = StepEnrichment(
                step=step,
                primary_query=primary_query,
                primary_answer=primary_result.answer,
                advisory_query=" | ".join(advisory_queries) if advisory_queries else None,
                advisory_answer=" ".join(advisory_answers) if advisory_answers else None,
                advisory_context="\n\n".join(advisory_contexts + detail_texts) if (advisory_contexts or detail_texts) else None,
                retrieved_text="\n\n".join(advisory_retrieved) if advisory_retrieved else None,
                sources=step_sources,
            )
            candidates = evaluate_cve_candidates(enrichment, eval_component, step, bundle)
            self._apply_component_advisory_reference(eval_component, reference_texts, candidates)
            self._annotate_admission_validation(admission_trace, candidates)
            selection = select_best_step_candidate(
                step.step_id,
                candidates,
                step=step,
                component=eval_component,
                used_cves=selected_cves,
            )
            selected_candidate = selection.selected
            if selected_candidate is not None:
                selected_cves.add(selected_candidate.cve_id)
            traces = [self._retrieval_trace(primary_result.retrieval_trace)]
            traces.extend(
                self._retrieval_trace(result.retrieval_trace)
                for result in advisory_results
            )
            traces.extend(detail_traces)
            narrator_payload = []
            if selected_candidate is not None:
                effect_obs = next(
                    (check.observed for check in selected_candidate.checks if check.name == "technical_effect"),
                    "",
                )
                version_status = next(
                    (check.status.value for check in selected_candidate.checks if check.name == "version"),
                    "unknown",
                )
                narrator = NarratorStepEvidence(
                    step_id=step.step_id,
                    scenario_description=step.description,
                    selected_cve=selected_candidate.cve_id,
                    target_product=(eval_component.name if eval_component else "") or "",
                    applicability_status=selected_candidate.final_status,
                    confirmed_conditions=[
                        check.reason or check.name
                        for check in selected_candidate.checks
                        if check.status.value == "known_true" and check.name in {"version", "authentication", "service", "privileges"}
                    ],
                    unresolved_conditions=list(selected_candidate.unresolved_conditions),
                    vulnerability_type=selected_candidate.vulnerability_phrase,
                    prerequisites=list(selected_candidate.unresolved_conditions),
                    technical_effect=effect_obs or selected_candidate.vulnerability_phrase,
                    vulnerable_component_id=roles.vulnerable_component_id,
                    action_target_id=roles.action_target_id,
                    downstream_affected_id=roles.downstream_affected_id,
                    technical_context=[],
                )
                narrator_payload = [
                    {
                        "cve_id": narrator.selected_cve,
                        "advisory_id": selected_candidate.advisory_id,
                        "disposition": selected_candidate.disposition,
                        "final_status": selected_candidate.final_status,
                        "gate_table": selected_candidate.gate_table,
                        "affected_versions": selected_candidate.affected_versions,
                        "unresolved_conditions": narrator.unresolved_conditions,
                        "confirmed_conditions": narrator.confirmed_conditions,
                        "vulnerability_phrase": selected_candidate.vulnerability_phrase,
                        "vulnerability_type": narrator.vulnerability_type,
                        "technical_effect": narrator.technical_effect,
                        "target_product": narrator.target_product,
                        "applicability_status": narrator.applicability_status,
                        "version_status": version_status,
                        "vulnerable_component_id": narrator.vulnerable_component_id,
                        "action_target_id": narrator.action_target_id,
                        "downstream_affected_id": narrator.downstream_affected_id,
                        "scenario_description": narrator.scenario_description,
                        "technical_context": [],
                    }
                ]
            elif step_supports_cve_selection(step):
                facts = project_technical_context(step, eval_component, candidates)
                narrator = NarratorStepEvidence(
                    step_id=step.step_id,
                    scenario_description=step.description,
                    selected_cve=None,
                    target_product=(eval_component.name if eval_component else "") or "",
                    applicability_status="",
                    technical_context=facts,
                    vulnerable_component_id=roles.vulnerable_component_id,
                    action_target_id=roles.action_target_id,
                    downstream_affected_id=roles.downstream_affected_id,
                )
                narrator_payload = [
                    {
                        "cve_id": None,
                        "target_product": narrator.target_product,
                        "vulnerable_component_id": narrator.vulnerable_component_id,
                        "action_target_id": narrator.action_target_id,
                        "downstream_affected_id": narrator.downstream_affected_id,
                        "scenario_description": narrator.scenario_description,
                        "technical_context": facts_as_payload(facts),
                    }
                ]
            step_evidence = StepEvidence(
                step_id=step.step_id,
                sequence=step.sequence,
                context=self.query_builder.build_step_context(bundle, step),
                queries=[item.query for item in step_queries],
                retrieval=[trace for trace in traces if trace.query],
                candidates=candidates,
                selected_cve=selected_candidate.cve_id if selected_candidate else None,
                selected_cves=[selected_candidate.cve_id] if selected_candidate else [],
                selection_reason=selection.reason,
                narrator_evidence=narrator_payload,
                vulnerable_component_id=roles.vulnerable_component_id,
                action_target_id=roles.action_target_id,
                downstream_affected_id=roles.downstream_affected_id,
                admission_trace=admission_trace,
            )
            enrichment.evidence = step_evidence
            enrichments.append(enrichment)
            all_evidence.append(step_evidence)

        narrative = self.synthesizer.synthesize(bundle, enrichments)
        if not narrative_uses_only_validated_cves(narrative, all_evidence):
            narrative = self.synthesizer.composer.compose(bundle, enrichments)
            if not narrative_uses_only_validated_cves(narrative, all_evidence):
                # Deterministic grounded fallback already emitted; mark removals for audit.
                pass
        mark_removed_by_validator(all_evidence, narrative)
        return ScenarioNarrativeResult(
            scenario_id=bundle.scenario.scenario_id,
            title=bundle.scenario.title,
            narrative=narrative,
            sources=dedupe_sources(all_sources),
            step_enrichments=enrichments,
            evidence=all_evidence,
        )

    def _apply_component_advisory_reference(
        self,
        component,
        reference_texts: list[str],
        candidates: list,
    ) -> None:
        if component is None or not reference_texts:
            return
        reference = component.advisory_reference()
        if not reference:
            return
        reference_cves = {
            cve_id.upper()
            for text in reference_texts
            for cve_id in extract_cves(text)
        }
        for candidate in candidates:
            if candidate.cve_id.upper() in reference_cves:
                candidate.advisory_id = reference.upper()

    @staticmethod
    def _is_advisory_source(source: str) -> bool:
        """Reuse the existing source-string convention (cisa / ics_adv)."""
        lowered = (source or "").lower()
        return "cisa" in lowered or "ics_adv" in lowered

    @staticmethod
    def _identity_fields(component) -> dict[str, list[str]]:
        if component is None:
            return {"vendor": [], "product": [], "model": [], "part": []}
        return {
            "vendor": [str(component.vendor or ""), str(component.manufacturer or "")],
            "product": [str(component.name or ""), str(component.product_family or "")],
            "model": [str(component.model or "")],
            "part": [str(component.part_number or "")],
        }

    @staticmethod
    def _field_tokens(values: Iterable[str], *, field: str) -> list[str]:
        tokens: list[str] = []
        seen: set[str] = set()
        for raw in values:
            for part in re.findall(r"[a-z0-9]+", str(raw).lower()):
                if field in {"model", "part"}:
                    if len(part) < 2:
                        continue
                elif part.isdigit() or len(part) < 3:
                    continue
                if part in seen:
                    continue
                seen.add(part)
                tokens.append(part)
        return tokens

    @classmethod
    def _dimensioned_identity_score(
        cls,
        text: str,
        identity_fields: dict[str, list[str]] | None = None,
        prefer_tokens: Iterable[str] | None = None,
    ) -> int:
        if not text:
            return 0
        lowered = text.lower()
        score = 0
        if identity_fields:
            for field, weight in _IDENTITY_WEIGHTS.items():
                for token in cls._field_tokens(identity_fields.get(field) or [], field=field):
                    if token in lowered:
                        score += weight
            return score
        for raw in prefer_tokens or []:
            for part in re.findall(r"[a-z0-9]+", str(raw).lower()):
                if len(part) < 2 or part not in lowered:
                    continue
                if part.isdigit():
                    continue
                if any(char.isdigit() for char in part) and len(part) >= 3:
                    score += _IDENTITY_WEIGHTS["part"]
                elif len(part) < 3:
                    score += _IDENTITY_WEIGHTS["model"]
                else:
                    score += _IDENTITY_WEIGHTS["product"]
        return score

    @staticmethod
    def _objective_score(text: str, step: AttackStep | None) -> int:
        """Cheap lexical ranking only — never a validation reject."""
        if step is None or not text:
            return 1
        objective = classify_step_objective(step)
        blob = text.lower()
        negatives = OBJECTIVE_NEGATIVE_PATTERNS.get(objective, frozenset())
        if any(pattern in blob for pattern in negatives):
            return 0
        for pattern, effect in DESCRIPTION_EFFECT_PATTERNS:
            if not re.search(pattern, blob, flags=re.IGNORECASE):
                continue
            if objective in EFFECT_OBJECTIVE_MATRIX.get(effect, frozenset()):
                return 2
        return 1

    @classmethod
    def _is_canonical_per_cve_hit(cls, hit: dict) -> bool:
        """True when the RRF hit itself is a per-CVE canonical advisory document."""
        document_id = str(hit.get("document_id") or "")
        source = str(hit.get("source") or "").lower()
        cves = [str(item).upper() for item in (hit.get("cves") or []) if str(item).strip()]
        if "::CVE-" in document_id.upper():
            return True
        if "cisa_csaf" in source and len(cves) == 1:
            return True
        return False

    @classmethod
    def _harvest_discovery_cve_ids(
        cls,
        answer_results: Iterable[AnswerResult],
        *,
        prefer_tokens: list[str] | None = None,
        identity_fields: dict[str, list[str]] | None = None,
        step: AttackStep | None = None,
        lane: str = "rrf",
    ) -> DiscoveryHarvest:
        """Document-first CVE ID harvest from this step's advisory RRF hits.

        Bound by advisory documents already in ask() RRF pools (no raw-ID cap).
        Each admitted document contributes all CVE IDs. Target identity ranks
        first; canonical per-CVE hits for the current target then outrank
        aggregates at the same identity, then step-objective, then RRF.
        """
        docs: dict[str, tuple[int, str, list[str], bool]] = {}
        for result in answer_results:
            trace = getattr(result, "retrieval_trace", None) or {}
            hits = trace.get(lane) or []
            if not isinstance(hits, list):
                continue
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                if not cls._is_advisory_source(str(hit.get("source") or "")):
                    continue
                document_id = str(hit.get("document_id") or "")
                if not document_id:
                    continue
                rank = int(hit.get("rank") or 10**9)
                preview = str(hit.get("text_preview") or hit.get("text") or "")
                cves = [
                    str(raw).upper()
                    for raw in (hit.get("cves") or [])
                    if str(raw).upper().startswith("CVE-")
                ]
                if not cves:
                    continue
                canonical = cls._is_canonical_per_cve_hit(hit)
                current = docs.get(document_id)
                if current is None or rank < current[0]:
                    docs[document_id] = (rank, preview, cves, canonical)
                else:
                    best_rank, best_preview, existing_cves, existing_canonical = current
                    merged = list(dict.fromkeys([*existing_cves, *cves]))
                    docs[document_id] = (
                        best_rank,
                        best_preview or preview,
                        merged,
                        existing_canonical or canonical,
                    )

        best_rank: dict[str, int] = {}
        identity_score: dict[str, int] = {}
        objectives: dict[str, int] = {}
        sources: dict[str, str] = {}
        kinds: dict[str, str] = {}
        source_identity: dict[str, int] = {}
        first_seen: dict[str, int] = {}
        guaranteed: set[str] = set()
        seen_index = 0
        for document_id, (rank, preview, cves, canonical) in sorted(
            docs.items(),
            key=lambda item: (item[1][0], item[0]),
        ):
            doc_score = cls._dimensioned_identity_score(
                preview, identity_fields=identity_fields, prefer_tokens=prefer_tokens
            )
            obj_score = cls._objective_score(preview, step)
            for cve_id in cves:
                if cve_id not in first_seen:
                    first_seen[cve_id] = seen_index
                    seen_index += 1
                previous_rank = best_rank.get(cve_id)
                if previous_rank is None or rank < previous_rank:
                    best_rank[cve_id] = rank
                identity_score[cve_id] = max(identity_score.get(cve_id, 0), doc_score)
                objectives[cve_id] = max(objectives.get(cve_id, 0), obj_score)
                if canonical:
                    guaranteed.add(cve_id)
                    kinds[cve_id] = "canonical"
                else:
                    kinds.setdefault(cve_id, "aggregate")
                take_source = False
                if cve_id not in sources:
                    take_source = True
                elif canonical and kinds.get(cve_id) != "canonical":
                    take_source = True
                elif kinds.get(cve_id) != "canonical" or canonical:
                    if doc_score > source_identity.get(cve_id, -1):
                        take_source = True
                if take_source:
                    sources[cve_id] = document_id
                    source_identity[cve_id] = doc_score

        ordered = sorted(
            best_rank.keys(),
            key=lambda cve_id: cls._admission_sort_key(
                cve_id,
                identity_map=identity_score,
                kinds=kinds,
                guaranteed=guaranteed,
                objective_map=objectives,
                rank_map=best_rank,
                first_seen=first_seen,
            ),
        )
        return DiscoveryHarvest(
            ids=ordered,
            ranks=best_rank,
            identity=identity_score,
            guaranteed=guaranteed,
            sources=sources,
            kinds=kinds,
            objectives=objectives,
        )

    @classmethod
    def _admit_identifier_cves(
        cls,
        harvest: DiscoveryHarvest,
        reference_texts: list[str],
        *,
        identity_fields: dict[str, list[str]] | None = None,
        prefer_tokens: list[str] | None = None,
        step: AttackStep | None = None,
    ) -> DiscoveryHarvest:
        """Keep identifier-lookup CVEs in the discovery universe even if RRF missed them."""
        if not reference_texts:
            return harvest
        ids = list(harvest.ids)
        ranks = dict(harvest.ranks)
        identity = dict(harvest.identity)
        guaranteed = set(harvest.guaranteed)
        sources = dict(harvest.sources)
        kinds = dict(harvest.kinds)
        objectives = dict(harvest.objectives)
        for index, text in enumerate(reference_texts):
            preview = text or ""
            doc_score = cls._dimensioned_identity_score(
                preview, identity_fields=identity_fields, prefer_tokens=prefer_tokens
            )
            obj_score = cls._objective_score(preview, step)
            for cve_id in extract_cves(preview):
                upper = str(cve_id).upper()
                if not upper.startswith("CVE-"):
                    continue
                if upper not in ids:
                    ids.append(upper)
                ranks.setdefault(upper, 0)
                identity[upper] = max(identity.get(upper, 0), doc_score)
                objectives[upper] = max(objectives.get(upper, 0), obj_score)
                kinds.setdefault(upper, "identifier")
                sources.setdefault(upper, f"identifier:{index}")
        ordered = sorted(
            ids,
            key=lambda cve_id: cls._admission_sort_key(
                cve_id,
                identity_map=identity,
                kinds=kinds,
                guaranteed=guaranteed,
                objective_map=objectives,
                rank_map=ranks,
                first_seen={cve: index for index, cve in enumerate(ids)},
            ),
        )
        return DiscoveryHarvest(
            ids=ordered,
            ranks=ranks,
            identity=identity,
            guaranteed=guaranteed,
            sources=sources,
            kinds=kinds,
            objectives=objectives,
        )

    @classmethod
    def _order_cves_for_expansion(
        cls,
        blob: str,
        extra_cve_ids: list[str] | None = None,
        prefer_tokens: list[str] | None = None,
        harvested_rank: dict[str, int] | None = None,
        harvested_identity: dict[str, int] | None = None,
        harvested_objectives: dict[str, int] | None = None,
        harvested_kinds: dict[str, str] | None = None,
        guaranteed_cves: set[str] | None = None,
        identity_fields: dict[str, list[str]] | None = None,
        step: AttackStep | None = None,
    ) -> list[str]:
        """Step-local ranking before CSAF_EXPANSION_CAP.

        Target identity first, then canonical vs aggregate, then step-objective,
        then RRF rank. Blob IDs compete in the same ranking; they do not consume
        the cap first. Canonical hits for other products must not crowd out a
        stronger current-step identity match.
        """
        rank_map = harvested_rank or {}
        identity_map = dict(harvested_identity or {})
        objective_map = dict(harvested_objectives or {})
        kinds = harvested_kinds or {}
        guaranteed = {cve.upper() for cve in (guaranteed_cves or set())}

        first_seen: dict[str, int] = {}
        pool: list[str] = []

        def add(cve_id: str) -> None:
            cve_id = str(cve_id or "").upper()
            if not cve_id.startswith("CVE-") or cve_id in first_seen:
                return
            first_seen[cve_id] = len(first_seen)
            pool.append(cve_id)

        for raw in extra_cve_ids or []:
            add(str(raw or ""))
        for cve_id in extract_cves(blob):
            add(cve_id)
            if cve_id.upper() not in identity_map:
                upper = blob.upper()
                idx = upper.find(cve_id.upper())
                window = blob[max(0, idx - 240) : idx + 240] if idx >= 0 else blob
                identity_map[cve_id.upper()] = cls._dimensioned_identity_score(
                    window, identity_fields=identity_fields, prefer_tokens=prefer_tokens
                )
                objective_map[cve_id.upper()] = cls._objective_score(window, step)

        def sort_key(cve_id: str) -> tuple:
            return cls._admission_sort_key(
                cve_id,
                identity_map=identity_map,
                kinds=kinds,
                guaranteed=guaranteed,
                objective_map=objective_map,
                rank_map=rank_map,
                first_seen=first_seen,
            )

        return sorted(pool, key=sort_key)

    @staticmethod
    def _admission_sort_key(
        cve_id: str,
        *,
        identity_map: dict[str, int],
        kinds: dict[str, str],
        guaranteed: set[str],
        objective_map: dict[str, int],
        rank_map: dict[str, int],
        first_seen: dict[str, int],
    ) -> tuple:
        canonical = cve_id in guaranteed or kinds.get(cve_id) == "canonical"
        return (
            -identity_map.get(cve_id, 0),
            0 if canonical else 1,
            -objective_map.get(cve_id, 1),
            rank_map.get(cve_id, 10**9),
            first_seen.get(cve_id, 10**9),
            cve_id,
        )

    @staticmethod
    def _admission_trace(ordered: list[str], harvest: DiscoveryHarvest) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for index, cve_id in enumerate(ordered):
            admitted = index < CSAF_EXPANSION_CAP
            rows.append(
                {
                    "cve_id": cve_id,
                    "source_document": harvest.sources.get(cve_id, ""),
                    "kind": harvest.kinds.get(cve_id, "aggregate"),
                    "identity_score": harvest.identity.get(cve_id, 0),
                    "objective_score": harvest.objectives.get(cve_id, 1),
                    "best_rrf_rank": harvest.ranks.get(cve_id),
                    "admitted": admitted,
                    "drop_reason": "" if admitted else "expansion_cap",
                    "final_validation_state": "not_evaluated",
                }
            )
        return rows

    @staticmethod
    def _annotate_admission_validation(
        admission_trace: list[dict[str, object]],
        candidates: list,
    ) -> None:
        by_cve = {getattr(item, "cve_id", ""): item for item in candidates}
        for row in admission_trace:
            if not row.get("admitted"):
                row["final_validation_state"] = "not_evaluated"
                continue
            candidate = by_cve.get(str(row.get("cve_id") or ""))
            if candidate is None:
                row["final_validation_state"] = "not_evaluated"
                continue
            row["final_validation_state"] = getattr(candidate, "final_status", "") or "not_evaluated"

    def _lookup_csaf_details_for_cves(
        self,
        blob: str,
        prefer_tokens: list[str] | None = None,
        extra_cve_ids: list[str] | None = None,
        harvested_rank: dict[str, int] | None = None,
        harvested_identity: dict[str, int] | None = None,
        harvested_objectives: dict[str, int] | None = None,
        harvested_kinds: dict[str, str] | None = None,
        guaranteed_cves: set[str] | None = None,
        identity_fields: dict[str, list[str]] | None = None,
        step: AttackStep | None = None,
    ) -> tuple[list[str], list[SourceReference], list[RetrievalTrace]]:
        cves = self._order_cves_for_expansion(
            blob,
            extra_cve_ids=extra_cve_ids,
            prefer_tokens=prefer_tokens,
            harvested_rank=harvested_rank,
            harvested_identity=harvested_identity,
            harvested_objectives=harvested_objectives,
            harvested_kinds=harvested_kinds,
            guaranteed_cves=guaranteed_cves,
            identity_fields=identity_fields,
            step=step,
        )
        if not cves:
            return [], [], []

        texts: list[str] = []
        sources: list[SourceReference] = []
        traces: list[RetrievalTrace] = []
        seen_docs: set[str] = set()
        for cve_id in cves[:CSAF_EXPANSION_CAP]:
            self._notify_query(cve_id)
            if hasattr(self.assistant.retriever, "retrieve_with_debug"):
                vector, bm25, hits = self.assistant.retriever.retrieve_with_debug(cve_id, k=3)
                traces.append(
                    RetrievalTrace(
                        query=cve_id,
                        vector=self._ranked_hits(vector),
                        bm25=self._ranked_hits(bm25),
                        rrf=self._ranked_hits(hits),
                        selected=self._ranked_hits(hits),
                    )
                )
            else:
                hits = self.assistant.retriever.retrieve(cve_id, k=3)
            for hit in hits:
                kind = str(hit.metadata.get("kind") or hit.metadata.get("meta_kind") or "")
                if kind != "cisa-csaf-cve" and hit.source != "cisa_csaf":
                    continue
                if not _hit_is_canonical_cve_document(hit, cve_id):
                    continue
                if hit.document_id in seen_docs:
                    continue
                seen_docs.add(hit.document_id)
                texts.append(hit.text)
                advisory_id = str(
                    hit.metadata.get("advisory_id")
                    or hit.metadata.get("meta_advisory_id")
                    or hit.document_id.split("::", 1)[0]
                )
                sources.append(SourceReference(attack_id=advisory_id or cve_id, document_source="cisa_csaf"))
        return texts, sources, traces

    def _lookup_component_advisory_reference(
        self,
        component,
    ) -> tuple[list[str], list[SourceReference]]:
        if component is None:
            return [], []
        reference = component.advisory_reference()
        if not reference or not ADVISORY_ID_PATTERN.fullmatch(reference.upper()):
            return [], []
        self._notify_query(reference)
        retriever = getattr(self.assistant, "retriever", None)
        if retriever is None:
            return [], []
        bm25 = getattr(retriever, "bm25_retriever", None)
        if bm25 is not None:
            hits = lookup_by_identifiers(bm25.chunks, reference)
        else:
            hits = retriever.retrieve(reference, k=3)
        texts: list[str] = []
        sources: list[SourceReference] = []
        seen_docs: set[str] = set()
        for hit in hits:
            if hit.document_id in seen_docs:
                continue
            seen_docs.add(hit.document_id)
            texts.append(hit.text)
            sources.append(
                SourceReference(
                    attack_id=reference,
                    document_source=str(hit.source or "cisa_csv"),
                )
            )
        return texts, sources

    @classmethod
    def _retrieval_trace(cls, data: dict) -> RetrievalTrace:
        return RetrievalTrace(
            query=str(data.get("query") or ""),
            vector=cls._ranked_hits(data.get("vector") or []),
            bm25=cls._ranked_hits(data.get("bm25") or []),
            rrf=cls._ranked_hits(data.get("rrf") or []),
            selected=cls._ranked_hits(data.get("selected") or []),
        )

    @staticmethod
    def _ranked_hits(items) -> list[RankedHit]:
        hits: list[RankedHit] = []
        for rank, item in enumerate(items, start=1):
            if isinstance(item, dict):
                hits.append(
                    RankedHit(
                        rank=int(item.get("rank") or rank),
                        document_id=str(item.get("document_id") or ""),
                        source=str(item.get("source") or ""),
                        score=float(item.get("score") or 0.0),
                        cves=list(item.get("cves") or []),
                    )
                )
            else:
                hits.append(
                    RankedHit(
                        rank=rank,
                        document_id=item.document_id,
                        source=item.source,
                        score=float(item.score),
                        cves=sorted(extract_cves(item.text)),
                    )
                )
        return hits

    def _notify_query(self, query: str) -> None:
        if self.on_query is not None:
            self.on_query(query)
