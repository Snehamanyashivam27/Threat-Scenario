from __future__ import annotations

"""Orchestrate frozen defense Stages 1–6 after threat generation.

Read-only post-processing. Does not change eligibility, rewrite rendered text,
infer ATT&CK techniques, call an LLM, or touch retrieval/indexing.
"""

from pathlib import Path

from rag.defense.inventory import inventory_scenario_result
from rag.defense.models import DefenseRecommendationReport, RenderedRecommendation
from rag.defense.recommendation_policy import apply_recommendation_policy
from rag.defense.recommendation_renderer import render_actionable_recommendations
from rag.defense.scenario_context import (
    align_defense_contexts,
    inventory_attack_mitigations_from_contexts,
    load_defense_step_contexts,
)
from rag.defense.unified_evidence import unify_step_defense_evidence
from rag.defense.validation import validate_scenario_result
from rag.scenario.models import ScenarioNarrativeResult

SECTION_TITLE = "Evidence-backed Defense Recommendations"
SECTION_RULE = "-" * len(SECTION_TITLE)
NO_ACTIONABLE_RECOMMENDATION = "No evidence-backed actionable defense recommendation available."


def default_csaf_dir(root: str | Path) -> Path:
    return Path(root) / "data" / "cisa_csaf"


def default_attack_sources(root: str | Path) -> Path:
    return Path(root)


def build_defense_recommendation_report(
    result: ScenarioNarrativeResult,
    *,
    scenario_dir: str | Path,
    csaf_dir: str | Path,
    attack_sources: str | Path,
) -> DefenseRecommendationReport:
    inventory = inventory_scenario_result(result, csaf_dir)
    csaf = validate_scenario_result(result, inventory)
    contexts = align_defense_contexts(
        load_defense_step_contexts(scenario_dir),
        result.evidence,
    )
    attack = inventory_attack_mitigations_from_contexts(contexts, attack_sources)
    unified = unify_step_defense_evidence(csaf, attack, evidence=result.evidence)
    policy = apply_recommendation_policy(unified)
    return render_actionable_recommendations(policy)


def format_defense_recommendations(report: DefenseRecommendationReport) -> str:
    header = f"{SECTION_TITLE}\n{SECTION_RULE}"
    steps = [step for step in report.steps if step.recommendations]
    if not steps:
        return f"{header}\n{NO_ACTIONABLE_RECOMMENDATION}"
    blocks = [header, ""]
    rendered_steps: list[str] = []
    for step in steps:
        lines = [f"Step {step.step_id}:"]
        for index, item in enumerate(step.recommendations, start=1):
            lines.append(f"{index}. {item.rendered_text}")
            source = _source_line(item)
            if source:
                lines.append(source)
        rendered_steps.append("\n".join(lines))
    blocks.append("\n\n".join(rendered_steps))
    return "\n".join(blocks)


def build_defense_recommendation_text(
    result: ScenarioNarrativeResult,
    *,
    scenario_dir: str | Path,
    csaf_dir: str | Path,
    attack_sources: str | Path,
) -> str:
    return format_defense_recommendations(
        build_defense_recommendation_report(
            result,
            scenario_dir=scenario_dir,
            csaf_dir=csaf_dir,
            attack_sources=attack_sources,
        )
    )


def _source_line(item: RenderedRecommendation) -> str:
    if item.citation:
        return f"   Source: {item.citation}"
    return ""
