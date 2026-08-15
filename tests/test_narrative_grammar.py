from __future__ import annotations

from rag.scenario.models import (
    AttackStep,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)
from rag.scenario.narrative_composer import ScenarioNarrativeComposer


def _step(description: str, *, name: str = "Impact") -> AttackStep:
    return AttackStep(
        sequence=2,
        step_id="synthetic-step",
        name=name,
        source_component_id="source",
        target_component_id="target",
        description=description,
    )


def _bundle(step: AttackStep) -> ScenarioBundle:
    return ScenarioBundle(
        scenario=ScenarioModel(
            scenario_id="SYNTHETIC-GRAMMAR",
            title="Synthetic grammar scenario",
            attack_path=[step],
        ),
        components_by_id={
            "target": ComponentModel(
                id="target",
                name="Target Controller",
                type="controller",
            )
        },
    )


def test_reachability_uses_allowing_target_to_become_accessible():
    step = _step(
        "The Target Controller becomes accessible.",
        name="Lateral Movement",
    )

    sentence = ScenarioNarrativeComposer._assumption_reachability_sentence(
        step,
        _bundle(step),
    )

    assert "allowing the Target Controller to become accessible" in sentence
    assert "allowing the Target Controller becomes accessible" not in sentence


def test_complete_impact_sentence_is_returned_directly():
    step = _step("The attack may impair an operational control function.")
    enrichment = StepEnrichment(step=step, primary_query="q", primary_answer="a")

    sentence = ScenarioNarrativeComposer()._compose_impact_paragraph(
        _bundle(step),
        enrichment,
    )

    assert sentence == "The attack may impair an operational control function."
    assert not sentence.startswith("As a result")


def test_impact_fragment_uses_lowercase_continuation_after_as_a_result():
    step = _step("Loss of an operational control function")
    enrichment = StepEnrichment(step=step, primary_query="q", primary_answer="a")

    sentence = ScenarioNarrativeComposer()._compose_impact_paragraph(
        _bundle(step),
        enrichment,
    )

    assert sentence == "As a result, loss of an operational control function."
    assert "As a result, Loss" not in sentence


def test_complete_impact_sentence_preserves_terminal_punctuation():
    step = _step("The attack may impair an operational control function!")
    enrichment = StepEnrichment(step=step, primary_query="q", primary_answer="a")

    sentence = ScenarioNarrativeComposer()._compose_impact_paragraph(
        _bundle(step),
        enrichment,
    )

    assert sentence == "The attack may impair an operational control function!"


def test_reachability_rewrite_preserves_only_original_security_facts():
    step = _step(
        "The Target Controller becomes accessible from the established path.",
        name="Lateral Movement",
    )

    sentence = ScenarioNarrativeComposer._assumption_reachability_sentence(
        step,
        _bundle(step),
    )

    assert "Target Controller" in sentence
    assert "accessible from the established path" in sentence
    assert "exploit" not in sentence.lower()
    assert "CVE-" not in sentence
