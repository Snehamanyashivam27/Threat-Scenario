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

import re

from rag.scenario.cve_validation import extract_validated_cve, extract_validated_cves
from rag.scenario.evidence import TruthValue
from rag.scenario.models import AttackStep, ComponentModel, ScenarioBundle, StepEnrichment

UNCONFIRMED_ACTION_TEXT = "The exact vulnerability used for this action could not be confirmed."
UNCONFIRMED_MECHANISM_TEXT = "The exact exploitation mechanism could not be confirmed."


class ScenarioNarrativeComposer:
    def compose(self, bundle: ScenarioBundle, enrichments: list[StepEnrichment]) -> str:
        header = f"1. {bundle.scenario.scenario_id} — {bundle.scenario.title}"
        used_cves: set[str] = set()
        paragraphs = self._build_paragraphs(bundle, enrichments, used_cves)
        if not paragraphs:
            return header
        return f"{header}\n" + "\n".join(paragraphs)

    def _build_paragraphs(
        self,
        bundle: ScenarioBundle,
        enrichments: list[StepEnrichment],
        used_cves: set[str],
    ) -> list[str]:
        paragraphs: list[str] = []
        index = 0
        while index < len(enrichments):
            enrichment = enrichments[index]
            step = enrichment.step

            if self._is_impact_step(step):
                paragraphs.append(self._compose_impact_paragraph(bundle, enrichment, enrichments))
                index += 1
                continue

            transition_steps, next_index = self._collect_transition_steps(enrichments, index)
            if transition_steps:
                paragraphs.append(self._compose_transition_paragraph(bundle, transition_steps))
                index = next_index
                continue

            if self._should_narrate_vulnerability(enrichment, step):
                follow_up: list[str] = []
                advance = 1
                if index + 1 < len(enrichments) and self._is_post_bypass_reachability(enrichments[index + 1].step):
                    follow_up.append(
                        self._assumption_reachability_sentence(enrichments[index + 1].step, bundle)
                    )
                    advance = 2

                paragraphs.append(
                    self._compose_vulnerability_paragraph(
                        bundle,
                        enrichment,
                        used_cves,
                        extra_sentences=follow_up,
                        use_then_prefix=self._is_compromise_step(step),
                    )
                )
                index += advance
                continue

            index += 1

        return [paragraph for paragraph in paragraphs if paragraph.strip()]

    def _collect_transition_steps(
        self,
        enrichments: list[StepEnrichment],
        start_index: int,
    ) -> tuple[list[StepEnrichment], int]:
        collected: list[StepEnrichment] = []
        index = start_index
        while index < len(enrichments):
            step = enrichments[index].step
            if self._is_impact_step(step) or self._is_vulnerability_step(step):
                break
            if self._narrator_eligible(enrichments[index]):
                break
            if self._is_post_bypass_reachability(step):
                break
            collected.append(enrichments[index])
            index += 1
        return collected, index

    def _compose_transition_paragraph(self, bundle: ScenarioBundle, steps: list[StepEnrichment]) -> str:
        if not steps:
            return ""

        sentences: list[str] = []
        use_profile = (
            steps[0].step.sequence == 1
            and bundle.scenario.attacker_profile
            and bundle.scenario.attacker_profile.description
        )
        if use_profile:
            sentences.append(
                self._normalize_opening_sentence(bundle.scenario.attacker_profile.description.rstrip("."))
            )

        for enrichment in steps:
            if use_profile and enrichment.step.sequence == 1:
                continue
            sentence = self._transition_sentence(enrichment, include_full_subject=not sentences)
            if sentence:
                sentences.append(sentence)

        return self._join_sentences(sentences)

    def _compose_vulnerability_paragraph(
        self,
        bundle: ScenarioBundle,
        enrichment: StepEnrichment,
        used_cves: set[str],
        extra_sentences: list[str] | None = None,
        use_then_prefix: bool = False,
    ) -> str:
        step = enrichment.step
        from rag.scenario.step_targets import resolve_step_targets

        roles = resolve_step_targets(step, bundle)
        exploit_id = roles.vulnerable_component_id or step.target_component_id
        target = self._component_label(bundle, exploit_id)
        component = self._component(bundle, exploit_id)
        validated_items = extract_validated_cves(
            enrichment,
            component,
            step,
            used_cves,
            bundle=bundle,
        )
        used_cves.update(item.cve_id for item in validated_items)

        sentences: list[str] = []
        if validated_items:
            for index, validated in enumerate(validated_items):
                sentences.extend(
                    self._compose_validated_cve_sentences(
                        step,
                        target,
                        validated,
                        use_then_prefix and index == 0,
                    )
                )
        else:
            # Do not narrate downstream consequence targets as exploit subjects.
            if roles.downstream_affected_id and roles.downstream_affected_id != exploit_id:
                downstream = self._component_label(bundle, roles.downstream_affected_id)
                sentences.append(
                    self._normalize_sentence(
                        f"Compromise of {self._with_article(target)} may affect "
                        f"{self._with_article(downstream)}"
                    )
                )
            else:
                sentences.append(self._attempt_sentence(step, target, use_then_prefix=use_then_prefix))
                context_facts = self._narrator_technical_context(enrichment)
                if context_facts:
                    sentences[-1] = self._with_confirmed_technical_context(sentences[-1], context_facts)
                    sentences.extend(self._conditional_technical_context_sentences(context_facts))
                qualifier = (
                    UNCONFIRMED_MECHANISM_TEXT
                    if self._is_compromise_step(step)
                    else UNCONFIRMED_ACTION_TEXT
                )
                sentences.append(qualifier)

        if extra_sentences:
            sentences.extend(extra_sentences)

        return self._join_sentences(sentences)

    @staticmethod
    def _compose_validated_cve_sentences(
        step: AttackStep,
        target: str,
        validated,
        use_then_prefix: bool,
    ) -> list[str]:
        phrase = validated.vulnerability_phrase or validated.enablement
        target_ref = ScenarioNarrativeComposer._with_article(target)
        version_bound = validated.affected_version_bound
        exploit_phrase = ScenarioNarrativeComposer._exploit_action_phrase(phrase)
        unresolved = list(validated.unresolved_prerequisites or [])
        verified = validated.applicability_status == "verified_applicable"

        if verified:
            prefix = "The attacker then exploits" if use_then_prefix else "The attacker exploits"
            return [f"{prefix} {validated.cve_id}, {phrase}."]

        # Potentially applicable: state the advisory fact, then list unresolved prerequisites.
        fact = ScenarioNarrativeComposer._vulnerability_fact_sentence(
            target_ref,
            validated.cve_id,
            version_bound,
        )
        condition = ScenarioNarrativeComposer._join_conditions(unresolved)
        if condition:
            if "web interface" in condition.lower():
                exploit_phrase = re.sub(
                    r"\s+in the (?:device(?:'s)?|affected device(?:'s)?) web interface",
                    "",
                    exploit_phrase,
                    count=1,
                    flags=re.IGNORECASE,
                )
            return [
                fact,
                f"If {condition}, the attacker can exploit {exploit_phrase}.",
            ]

        prefix = "The attacker then may exploit" if use_then_prefix else "The attacker may exploit"
        return [
            f"{prefix} {validated.cve_id}, {phrase}, if remaining applicability conditions are satisfied."
        ]

    @staticmethod
    def _vulnerability_fact_sentence(target_ref: str, cve_id: str, version_bound: str | None) -> str:
        subject = re.sub(r"^the\s+", "", target_ref, count=1, flags=re.IGNORECASE)
        if version_bound:
            return f"{cve_id} affects {subject} when the deployed version is earlier than {version_bound}."
        return f"{cve_id} affects {subject}."

    @staticmethod
    def _join_conditions(conditions: list[str]) -> str:
        cleaned = [item.strip().rstrip(".") for item in conditions if item and item.strip()]
        if not cleaned:
            return ""
        if len(cleaned) == 1:
            return cleaned[0]
        if len(cleaned) == 2:
            return f"{cleaned[0]} and {cleaned[1]}"
        return ", ".join(cleaned[:-1]) + f", and {cleaned[-1]}"

    @staticmethod
    def _exploit_action_phrase(vulnerability_phrase: str) -> str:
        """Turn a vulnerability phrase into smooth exploit wording without repeating the CVE ID."""
        phrase = vulnerability_phrase.strip().rstrip(".")
        if not phrase:
            return "the vulnerability"

        # "a command-injection vulnerability ... that can allow an attacker to X"
        # -> "the command-injection vulnerability ... to X"
        rewritten = re.sub(
            r"^(an?)\s+",
            "the ",
            phrase,
            count=1,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            r"\sthat can allow .+? to\s+",
            " to ",
            rewritten,
            count=1,
            flags=re.IGNORECASE,
        )
        rewritten = re.sub(
            r"\sthat allows .+? to\s+",
            " to ",
            rewritten,
            count=1,
            flags=re.IGNORECASE,
        )
        return rewritten

    @staticmethod
    def _with_article(label: str) -> str:
        cleaned = label.strip()
        if not cleaned:
            return "the target component"
        if cleaned.lower().startswith(("a ", "an ", "the ")):
            return cleaned
        return f"the {cleaned}"

    def _validate_and_track(
        self,
        enrichment: StepEnrichment,
        component: ComponentModel | None,
        step: AttackStep,
        used_cves: set[str],
        bundle: ScenarioBundle | None = None,
    ):
        validated = extract_validated_cve(enrichment, component, step, used_cves, bundle=bundle)
        if validated is not None:
            used_cves.add(validated.cve_id)
        return validated

    def _compose_impact_paragraph(
        self,
        bundle: ScenarioBundle,
        enrichment: StepEnrichment,
        all_enrichments: list[StepEnrichment] | None = None,
    ) -> str:
        impact = bundle.scenario.impact
        if impact is None:
            description = enrichment.step.description.strip()
            if self._looks_like_complete_clause(description):
                return self._normalize_sentence(description)
            return self._with_introductory_prefix("As a result", description)

        scenario_dims = {
            "confidentiality": bool(
                impact.confidentiality and impact.confidentiality.lower() not in {"none", "n/a", "na"}
            ),
            "integrity": bool(impact.integrity and impact.integrity.lower() not in {"none", "n/a", "na"}),
            "availability": bool(
                impact.availability and impact.availability.lower() not in {"none", "n/a", "na"}
            ),
        }
        evidence_dims = self._impact_dimensions_from_enrichments(all_enrichments or [enrichment])
        dimensions = [
            name
            for name, enabled in scenario_dims.items()
            if enabled and (not evidence_dims or name in evidence_dims)
        ]
        if not dimensions and any(scenario_dims.values()):
            dimensions = [name for name, enabled in scenario_dims.items() if enabled]

        if not dimensions:
            description = enrichment.step.description.strip()
            if self._looks_like_complete_clause(description):
                return self._normalize_sentence(description)
            return self._with_introductory_prefix("As a result", description)
        if len(dimensions) == 1:
            return self._normalize_sentence(
                f"As a result, {dimensions[0]} of the affected operational functions may be impaired"
            )
        if len(dimensions) == 2:
            return self._normalize_sentence(
                f"As a result, {dimensions[0]} and {dimensions[1]} of the affected operational functions may be impaired"
            )
        body = ", ".join(dimensions[:-1]) + f", and {dimensions[-1]}"
        return self._normalize_sentence(
            f"As a result, {body} of the affected operational functions may be impaired"
        )

    @staticmethod
    def _impact_dimensions_from_enrichments(enrichments: list[StepEnrichment]) -> set[str]:
        """Map validated technical effects to CIA dimensions; never invent dimensions."""
        dims: set[str] = set()
        effect_blobs: list[str] = []
        for enrichment in enrichments:
            evidence = enrichment.evidence
            if evidence is None:
                continue
            for item in evidence.narrator_evidence:
                effect_blobs.append(str(item.get("technical_effect") or ""))
                effect_blobs.append(str(item.get("vulnerability_phrase") or ""))
            for candidate in evidence.candidates:
                if candidate.cve_id == evidence.selected_cve or candidate.cve_id in evidence.selected_cves:
                    effect_blobs.append(" ".join(candidate.effects))
                    effect_blobs.append(candidate.vulnerability_phrase)
                    effect_blobs.append(candidate.description)
        blob = " ".join(effect_blobs).lower()
        if not blob.strip():
            return set()
        if any(
            token in blob
            for token in ("denial_of_service", "denial of service", "availability", "resource exhaustion")
        ):
            dims.add("availability")
        if any(
            token in blob
            for token in (
                "integrity",
                "command_injection",
                "command-injection",
                "code_execution",
                "remote_code_execution",
                "configuration",
                "privilege",
                "modify",
                "tamper",
            )
        ):
            dims.add("integrity")
        if any(
            token in blob
            for token in ("confidential", "information_disclosure", "credential", "disclosure")
        ):
            dims.add("confidentiality")
        if any(
            token in blob
            for token in ("remote_code_execution", "code_execution", "command_injection", "command-injection")
        ):
            dims.update({"integrity", "availability"})
        return dims

    @staticmethod
    def _assumption_reachability_sentence(step: AttackStep, bundle: ScenarioBundle) -> str:
        description = step.description.strip().rstrip(".")
        target = ScenarioNarrativeComposer._component_label(bundle, step.target_component_id)
        lowered = description.lower()

        if lowered.startswith("after the network restrictions"):
            match = re.search(
                r"after the network restrictions have been bypassed or modified,\s*(.+)$",
                description,
                flags=re.IGNORECASE,
            )
            if match:
                outcome = match.group(1).strip().rstrip(".")
                reachable_match = re.match(
                    r"^(?:the )?(?P<target>.+?) becomes reachable from (?P<path>.+)$",
                    outcome,
                    flags=re.IGNORECASE,
                )
                if reachable_match:
                    target = reachable_match.group("target").strip()
                    path = reachable_match.group("path").strip()
                    return ScenarioNarrativeComposer._normalize_sentence(
                        "The scenario assumes that the network restrictions are successfully bypassed or modified, "
                        f"making {ScenarioNarrativeComposer._with_article(target)} reachable from {path}"
                    )
                if outcome.lower().startswith("the "):
                    outcome = outcome[4:]
                return ScenarioNarrativeComposer._normalize_sentence(
                    "The scenario assumes that the network restrictions are successfully bypassed or modified, "
                    f"making {outcome}"
                )

        if "becomes reachable" in lowered or "become reachable" in lowered:
            return ScenarioNarrativeComposer._normalize_sentence(
                "The scenario assumes that the preceding network-control change succeeds, "
                f"making {target} reachable from the compromised network path"
            )

        accessibility = re.match(
            r"^(?:the\s+)?(?P<subject>.+?)\s+(?:becomes?|is)\s+"
            r"(?P<state>accessible|reachable)(?P<tail>\s+.*)?$",
            description,
            flags=re.IGNORECASE,
        )
        if accessibility:
            subject = accessibility.group("subject").strip()
            state = accessibility.group("state").lower()
            tail = (accessibility.group("tail") or "").strip()
            outcome = f"{ScenarioNarrativeComposer._with_article(subject)} to become {state}"
            if tail:
                outcome += f" {tail}"
            return ScenarioNarrativeComposer._normalize_sentence(
                "The scenario assumes that the preceding step succeeds, "
                f"allowing {outcome}"
            )

        # An arbitrary step description may already be an independent clause.
        # Keep it independent rather than placing a finite verb after "allowing".
        assumption = ScenarioNarrativeComposer._normalize_sentence(
            "The scenario assumes that the preceding step succeeds"
        )
        return f"{assumption} {ScenarioNarrativeComposer._normalize_sentence(description)}".strip()

    @staticmethod
    def _transition_sentence(enrichment: StepEnrichment, include_full_subject: bool) -> str:
        description = enrichment.step.description.strip().rstrip(".")
        if include_full_subject:
            return ScenarioNarrativeComposer._normalize_sentence(
                ScenarioNarrativeComposer._normalize_opening_sentence(description)
            )

        lowered = description.lower()
        if lowered.startswith("through "):
            return ScenarioNarrativeComposer._normalize_sentence(description)
        if lowered.startswith("the attacker "):
            remainder = description[len("The attacker ") :].strip()
            return ScenarioNarrativeComposer._normalize_sentence(
                f"Through the established path, the attacker {remainder}"
            )
        return ScenarioNarrativeComposer._normalize_sentence(description)

    @staticmethod
    def _attempt_sentence(step: AttackStep, target: str, use_then_prefix: bool = False) -> str:
        prefix = "The attacker then attempts" if use_then_prefix else "The attacker attempts"
        description = step.description.strip().rstrip(".")
        lowered = description.lower()
        if ScenarioNarrativeComposer._is_compromise_step(step):
            return ScenarioNarrativeComposer._normalize_sentence(
                f"{prefix} to compromise {ScenarioNarrativeComposer._with_article(target)}."
            )
        if "segmentation" in lowered or ("bypass" in lowered and "network" in lowered):
            return ScenarioNarrativeComposer._normalize_sentence(
                f"{prefix} to bypass the network-segmentation controls on "
                f"{ScenarioNarrativeComposer._with_article(target)}."
            )
        if lowered.startswith("the attacker exploits"):
            objective = ScenarioNarrativeComposer._step_objective(step)
            objective = re.sub(
                r"^exploits an applicable (?:weakness|vulnerability[^,]*?) to ",
                "",
                objective,
                flags=re.IGNORECASE,
            )
            return ScenarioNarrativeComposer._normalize_sentence(f"{prefix} to {objective}")
        return ScenarioNarrativeComposer._normalize_sentence(
            f"{prefix} to {ScenarioNarrativeComposer._step_objective(step)}."
        )

    @staticmethod
    def _narrator_technical_context(enrichment: StepEnrichment) -> list[dict]:
        """Read only narrator-safe technical_context. Never inspect candidates[]."""
        evidence = enrichment.evidence
        if evidence is None:
            return []
        facts: list[dict] = []
        for item in evidence.narrator_evidence or []:
            if not isinstance(item, dict):
                continue
            if item.get("cve_id"):
                continue
            for fact in item.get("technical_context") or []:
                if isinstance(fact, dict) and fact.get("statement"):
                    facts.append(fact)
        return facts[:2]

    @staticmethod
    def _with_confirmed_technical_context(attempt: str, facts: list[dict]) -> str:
        tails = [
            str(fact.get("statement") or "").strip().rstrip(".")
            for fact in facts
            if fact.get("polarity") == "confirmed"
        ]
        tails = [item for item in tails if item]
        if not tails:
            return attempt
        base = attempt.strip().rstrip(".")
        return ScenarioNarrativeComposer._normalize_sentence(f"{base} {' '.join(tails)}")

    @staticmethod
    def _conditional_technical_context_sentences(facts: list[dict]) -> list[str]:
        sentences: list[str] = []
        for fact in facts:
            if fact.get("polarity") != "conditional":
                continue
            statement = str(fact.get("statement") or "").strip()
            if statement:
                sentences.append(ScenarioNarrativeComposer._normalize_sentence(statement))
        return sentences

    @staticmethod
    def _normalize_opening_sentence(text: str) -> str:
        cleaned = text.strip().rstrip(".")
        with_access = re.match(
            r"^(?P<subject>An?\s+.+?)\s+with access to\s+(?P<object>.+)$",
            cleaned,
            flags=re.IGNORECASE,
        )
        if with_access:
            return f"{with_access.group('subject')} gains access through {with_access.group('object')}"
        with_valid = re.match(
            r"^(?P<subject>An?\s+.+?)\s+with valid\s+(?P<object>.+)$",
            cleaned,
            flags=re.IGNORECASE,
        )
        if with_valid:
            return f"{with_valid.group('subject')} gains access using valid {with_valid.group('object')}"
        return cleaned

    @staticmethod
    def _fix_product_spacing(text: str) -> str:
        spaced = re.sub(r"([A-Z]{4,})([A-Z]{2,}\d[\w]*)", r"\1 \2", text)
        return re.sub(r"\s+", " ", spaced).strip()

    @staticmethod
    def _exploit_objective(step: AttackStep, target: str) -> str:
        if ScenarioNarrativeComposer._is_compromise_step(step):
            return f"compromise {target}"
        objective = ScenarioNarrativeComposer._step_objective(step)
        if objective.startswith("affecting "):
            return f"compromise {target}"
        return objective

    @staticmethod
    def _step_objective(step: AttackStep) -> str:
        description = step.description.strip().rstrip(".")
        lowered = description.lower()
        if lowered.startswith("the attacker "):
            objective = description[len("The attacker ") :].strip().rstrip(".")
        else:
            objective = description
        objective = re.sub(
            r"^exploits an applicable (?:weakness|vulnerability(?: or insecure product function)?[^,]*?) to ",
            "",
            objective,
            flags=re.IGNORECASE,
        )
        objective = re.sub(
            r"^exploits an applicable (?:weakness|vulnerability(?: or insecure product function)?[^,]*?) ",
            "",
            objective,
            flags=re.IGNORECASE,
        )
        if objective and objective[0].isupper():
            objective = objective[0].lower() + objective[1:]
        return objective.rstrip(".")

    @staticmethod
    def _is_post_bypass_reachability(step: AttackStep) -> bool:
        blob = f"{step.name} {step.description}".lower()
        if "lateral movement" in blob:
            return True
        return blob.startswith("after the network restrictions") or "becomes reachable" in blob

    @staticmethod
    def _is_compromise_step(step: AttackStep) -> bool:
        blob = f"{step.name} {step.description}".lower()
        return "compromise" in blob

    @staticmethod
    def _component(bundle: ScenarioBundle, component_id: str | None) -> ComponentModel | None:
        if not component_id:
            return None
        return bundle.components_by_id.get(component_id)

    @staticmethod
    def _component_label(bundle: ScenarioBundle, component_id: str | None) -> str:
        component = ScenarioNarrativeComposer._component(bundle, component_id)
        if component is None:
            return "the target component"
        return ScenarioNarrativeComposer._fix_product_spacing(component.name)

    @staticmethod
    def _narrator_eligible(enrichment: StepEnrichment) -> bool:
        if not enrichment.evidence or not enrichment.evidence.selected_cve:
            return False
        return any(
            item.get("disposition") in {"applicable", "conditional"}
            for item in enrichment.evidence.narrator_evidence
        )

    @classmethod
    def _should_narrate_vulnerability(cls, enrichment: StepEnrichment, step: AttackStep) -> bool:
        # Selected applicable/conditional evidence always narrates for this step.
        if cls._narrator_eligible(enrichment):
            return True
        if cls._is_vulnerability_step(step):
            return True
        return False

    @staticmethod
    def _selected_effect_confirmed(enrichment: StepEnrichment) -> bool:
        if not enrichment.evidence or not enrichment.evidence.selected_cve:
            return False
        candidate = next(
            (
                item
                for item in enrichment.evidence.candidates
                if item.cve_id == enrichment.evidence.selected_cve
            ),
            None,
        )
        if candidate is None:
            return False
        effect = next(
            (check.status for check in candidate.checks if check.name == "technical_effect"),
            None,
        )
        return effect == TruthValue.TRUE

    @staticmethod
    def _is_vulnerability_step(step: AttackStep) -> bool:
        from rag.scenario.step_targets import is_downstream_consequence_step

        if is_downstream_consequence_step(step):
            return False
        name = step.name.lower()
        description = step.description.lower()

        if "lateral movement" in name or "initial access" in name:
            return False

        if any(term in name for term in ("bypass", "segmentation", "compromise", "exploit", "vulnerabilit")):
            return True

        if re.search(r"\b(?:exploit|bypass(?:es|ing)?|vulnerabilit\w*|weakness|insecure)\b", description):
            return True

        if "compromise" in description and any(
            phrase in description for phrase in ("compromise the", "compromise of", "compromises the")
        ):
            return True

        return False

    @staticmethod
    def _is_impact_step(step: AttackStep) -> bool:
        return "impact" in step.name.lower()

    @staticmethod
    def _normalize_sentence(text: str) -> str:
        cleaned = ScenarioNarrativeComposer._fix_product_spacing(re.sub(r"\s+", " ", text.strip()))
        if not cleaned:
            return ""
        if cleaned[-1] not in ".!?":
            cleaned += "."
        return cleaned[0].upper() + cleaned[1:]

    @staticmethod
    def _looks_like_complete_clause(text: str) -> bool:
        """Recognize grounded step descriptions that already form a sentence."""
        cleaned = text.strip()
        if not cleaned:
            return False
        if cleaned[-1:] in ".!?":
            return True
        return bool(
            re.match(r"^(?:the|a|an|this|that|it)\s+", cleaned, flags=re.IGNORECASE)
            and re.search(
                r"\b(?:is|are|was|were|has|have|can|could|may|might|will|would|"
                r"becomes?|impairs?|affects?|disrupts?|causes?)\b",
                cleaned,
                flags=re.IGNORECASE,
            )
        )

    @staticmethod
    def _with_introductory_prefix(prefix: str, clause: str) -> str:
        """Join an introductory phrase to a fragment without mid-sentence capitalization."""
        cleaned = clause.strip().rstrip(".")
        if not cleaned:
            return ScenarioNarrativeComposer._normalize_sentence(prefix)
        continuation = cleaned[0].lower() + cleaned[1:]
        return ScenarioNarrativeComposer._normalize_sentence(f"{prefix}, {continuation}")

    @staticmethod
    def _join_sentences(sentences: list[str]) -> str:
        cleaned = [sentence.strip().rstrip(".") for sentence in sentences if sentence.strip()]
        if not cleaned:
            return ""
        if len(cleaned) == 1:
            return ScenarioNarrativeComposer._normalize_sentence(cleaned[0])
        body = ". ".join(cleaned)
        return ScenarioNarrativeComposer._normalize_sentence(body)
