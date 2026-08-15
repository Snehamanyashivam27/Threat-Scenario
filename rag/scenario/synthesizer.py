from __future__ import annotations

import os

from rag.generation.answer_cleanup import clean_answer_text
from rag.generation.answer_service import AnswerService, DeterministicAnswerService, OllamaAnswerService
from rag.scenario.models import ScenarioBundle, StepEnrichment
from rag.scenario.narrative_composer import ScenarioNarrativeComposer


class ScenarioSynthesisAnswerService(AnswerService):
    def __init__(self, base_service: AnswerService | None = None):
        self.base_service = base_service or OllamaAnswerService()

    def generate(self, query: str, context: str) -> str:
        if isinstance(self.base_service, DeterministicAnswerService):
            return self._deterministic_narrative(query, context)
        if isinstance(self.base_service, OllamaAnswerService):
            prompt = build_scenario_synthesis_prompt(query, context)
            if os.getenv("DEBUG", "").lower() == "true" or os.getenv("RAG_DEBUG_CONTEXT", "").lower() in {"1", "true", "yes"}:
                print("=" * 80, flush=True)
                print("SCENARIO SYNTHESIS CONTEXT LENGTH:", len(context), flush=True)
                print(context, flush=True)
                print("=" * 80, flush=True)
            response = self.base_service._get_client().invoke(prompt)
            return clean_answer_text(getattr(response, "content", str(response)).strip(), context)
        return clean_answer_text(self.base_service.generate(query, context), context)

    @staticmethod
    def _deterministic_narrative(query: str, context: str) -> str:
        lines = [line.strip() for line in context.splitlines() if line.strip()]
        title = next((line.removeprefix("Title: ") for line in lines if line.startswith("Title: ")), "Threat Scenario")
        overview = next(
            (line.removeprefix("Attacker Profile: ") for line in lines if line.startswith("Attacker Profile: ")),
            "",
        )
        paragraphs = [f"This threat scenario describes {title}."]
        if overview:
            paragraphs.append(overview)
        step_lines = [line for line in lines if line.startswith("Step ") and " - " in line]
        if step_lines:
            paragraphs.append("The attack path proceeds through the following steps.")
            paragraphs.extend(step_lines)
        paragraphs.append("The resulting impact follows the conditions described in the provided scenario context.")
        return " ".join(paragraphs)


class ScenarioNarrativeSynthesizer:
    def __init__(
        self,
        answer_service: AnswerService | None = None,
        composer: ScenarioNarrativeComposer | None = None,
        use_llm_polish: bool = False,
    ):
        self.answer_service = answer_service or ScenarioSynthesisAnswerService()
        self.composer = composer or ScenarioNarrativeComposer()
        self.use_llm_polish = use_llm_polish

    def synthesize(self, bundle: ScenarioBundle, enrichments: list[StepEnrichment]) -> str:
        narrative = self.composer.compose(bundle, enrichments)
        if not self.use_llm_polish:
            return narrative

        context = self._build_synthesis_context(bundle, enrichments)
        prompt_query = (
            f"Polish the following threat scenario narrative for {bundle.scenario.scenario_id}: "
            f"{bundle.scenario.title}. Preserve all CVE references and unconfirmed-vulnerability statements exactly."
        )
        polished = clean_answer_text(self.answer_service.generate(prompt_query, f"{context}\n\nDraft:\n{narrative}"), context)
        return polished or narrative

    @classmethod
    def _build_synthesis_context(cls, bundle: ScenarioBundle, enrichments: list[StepEnrichment]) -> str:
        """LLM may only see final structured NarratorStepEvidence — never the candidate pool."""
        scenario = bundle.scenario
        sections: list[str] = [
            "Scenario Overview",
            f"Scenario ID: {scenario.scenario_id}",
            f"Title: {scenario.title}",
            f"Operational State: {scenario.operational_state}",
        ]

        if scenario.attacker_profile and scenario.attacker_profile.description:
            sections.append(f"Attacker Profile: {scenario.attacker_profile.description}")

        sections.append("")
        sections.append("NarratorStepEvidence (authoritative; do not invent CVEs or applicability)")
        for enrichment in enrichments:
            step = enrichment.step
            sections.append(f"Step {step.sequence} - {step.name} ({step.step_id})")
            sections.append(f"Description: {step.description}")
            evidence = getattr(enrichment, "evidence", None)
            narrator_items = getattr(evidence, "narrator_evidence", None) if evidence is not None else None
            if isinstance(narrator_items, list) and narrator_items:
                for item in narrator_items:
                    if not isinstance(item, dict):
                        continue
                    sections.append(f"selected_cve: {item.get('cve_id')}")
                    sections.append(f"target_product: {item.get('target_product')}")
                    sections.append(f"applicability_status: {item.get('applicability_status')}")
                    sections.append(
                        "vulnerability_type: "
                        + str(item.get("vulnerability_type") or item.get("vulnerability_phrase") or "")
                    )
                    sections.append(f"technical_effect: {item.get('technical_effect')}")
                    sections.append(
                        "confirmed_conditions: "
                        + "; ".join(item.get("confirmed_conditions") or [])
                    )
                    sections.append(
                        "unresolved_conditions: "
                        + "; ".join(item.get("unresolved_conditions") or [])
                    )
                    sections.append(f"vulnerable_component_id: {item.get('vulnerable_component_id')}")
                    sections.append(f"action_target_id: {item.get('action_target_id')}")
                    sections.append(f"downstream_affected_id: {item.get('downstream_affected_id')}")
                    technical_context = item.get("technical_context") or []
                    if technical_context:
                        sections.append(
                            "technical_context: "
                            + "; ".join(
                                f"{fact.get('polarity', '')} {fact.get('statement', '')}".strip()
                                for fact in technical_context
                                if isinstance(fact, dict)
                            )
                        )
                    if not item.get("cve_id"):
                        sections.append("selected_cve: none")
                        sections.append("Narrate the attack path step without inventing a CVE.")
            else:
                # Preserve legacy context fields used by tests / deterministic polish when
                # structured narrator evidence is absent.
                primary = getattr(enrichment, "primary_answer", None)
                advisory = getattr(enrichment, "advisory_answer", None)
                if primary:
                    sections.append(f"Knowledge Summary: {primary}")
                if advisory:
                    sections.append(f"Advisory Summary: {advisory}")
                sections.append("selected_cve: none")
                sections.append("Narrate the attack path step without inventing a CVE.")
            sections.append("")

        if scenario.impact:
            sections.append("Impact")
            sections.append(f"Confidentiality: {scenario.impact.confidentiality}")
            sections.append(f"Integrity: {scenario.impact.integrity}")
            sections.append(f"Availability: {scenario.impact.availability}")
            sections.append(f"Safety: {scenario.impact.safety}")

        return "\n".join(sections)


def build_scenario_synthesis_prompt(query: str, context: str) -> str:
    return f"""
You are a cybersecurity analyst writing a deterministic threat scenario narrative for an industrial control system.

The structured NarratorStepEvidence below is the ONLY source of truth for CVE claims.

Your task is to turn the provided selected evidence into one cohesive narrative suitable for terminal display.

Strict Rules:
1. Use ONLY the provided context.
2. Never invent ATT&CK techniques, ATT&CK IDs, CVEs, CWEs, vendors, products, or attack steps.
3. Never choose a CVE. Narrate only selected_cve values already present in NarratorStepEvidence.
4. Never determine applicability, prerequisites, vulnerability type, or technical effect — copy them from evidence.
5. Preserve the attack path order from Step 1 through the final step.
6. Do not claim the attacker exploits a downstream_affected component unless that component is also the selected vulnerable target for a step.
7. Do not include a Sources section; sources are displayed separately by the application.
8. Do not use markdown.
9. Write in professional cybersecurity language.
10. Do not repeat the scenario ID as a heading inside the narrative body.

Question:
{query}

Structured Context:
{context}
""".strip()
