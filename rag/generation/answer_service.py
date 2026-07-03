from __future__ import annotations

from abc import ABC, abstractmethod
import os
import re

from rag.generation.answer_cleanup import clean_answer_text, strip_embedded_sources
from rag.generation.ollama_config import OllamaGenerationConfig, load_ollama_generation_config


class AnswerService(ABC):
    @abstractmethod
    def generate(self, query: str, context: str) -> str:
        raise NotImplementedError


class OllamaAnswerService(AnswerService):
    def __init__(
        self,
        model: str = "qwen2.5:14b",
        base_url: str | None = None,
        generation_config: OllamaGenerationConfig | None = None,
    ):
        self.model = model
        self.base_url = base_url
        self.generation_config = generation_config or load_ollama_generation_config()
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from langchain_ollama import ChatOllama
        except ImportError as error:  # pragma: no cover
            raise RuntimeError("langchain-ollama is required for Ollama generation") from error

        kwargs = {"model": self.model, **self.generation_config.to_chat_kwargs()}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client = ChatOllama(**kwargs)
        return self._client

    def generate(self, query: str, context: str) -> str:
        prompt = f"""
                You are a cybersecurity analyst operating in a Retrieval-Augmented Generation (RAG) system.

                The retrieved context below is the ONLY source of truth.

                Your task is to synthesize the retrieved information into a concise, technically accurate answer.

                Strict Rules:

                1. Use ONLY the retrieved context.
                2. Never use your own knowledge.
                3. Never invent or infer ATT&CK techniques, ATT&CK IDs, CVEs, CWEs, vendors, mitigations, detections, tactics, attack paths or relationships.
                4. Every factual statement must be directly supported by the retrieved context.
                5. If the retrieved context contains partial information that directly answers the question, summarize all available information from the retrieved context.
                Only reply:
                "The retrieved context does not contain enough information to answer this question."
                When the retrieved context contains no relevant information for the user's query.
                6. Prefer correctness over completeness.
                7. If multiple documents are retrieved, synthesize across all documents that directly answer the question. The first document in the Retrieved Context is the primary source; anchor the answer to that primary document unless the user explicitly asks about another identifier in the context.
                8. If both Enterprise ATT&CK and ICS ATT&CK describe the same technique, explain both separately while highlighting their differences.
                9. If only Enterprise ATT&CK is retrieved, discuss only Enterprise ATT&CK.
                10. If only ICS ATT&CK is retrieved, discuss only ICS ATT&CK.
                11. If only CISA advisories are retrieved, summarize only the advisory.
                12. Never associate a CVE with an ATT&CK technique unless BOTH appear in the retrieved context.
                13. Never mention information absent from the retrieved context.
                14. Do not explain your reasoning.
                15. Do not include markdown.
                16. Write in professional cybersecurity language.
                17. Never explain the meaning of a CVE, CWE, ATT&CK ID, or security concept unless that explanation appears explicitly in the retrieved context.
                For example, if the context contains only "CWE-121", report "CWE-121" without describing what it represents.
                18. Do not include a Sources section, citations list, or references. Sources are displayed separately by the application.
                19. Never recommend mitigations, password policies, multi-factor authentication, user training, or other defensive guidance unless the exact wording appears in the retrieved context.
                20. Never write concluding synthesis sentences such as "Both contexts highlight..." or "This underscores the importance of...".
                21. Never infer examples such as default credentials, publicly available passwords, or common security controls unless they appear in the retrieved context.
                22. Stay close to the retrieved Description and Tactic fields. Do not interpret or expand them with general cybersecurity knowledge.
                23. When answering questions about a CVE, summarize all available advisory fields that appear in the retrieved context, including the advisory title, vendor, product, severity, CVE, CWE, affected products, and sector if present. Do not invent technical details that are not in the advisory.
                24. When the retrieved context contains multiple related ATT&CK techniques for a broad topic, summarize the shared idea using their Description fields and mention each relevant technique as supporting evidence.
                25. Identify whether the question asks for a definition, a specific identifier lookup, or a threat scenario before structuring the answer. State clearly when the retrieved context is insufficient.

                Answer Style:

                - Begin immediately with the answer.
                - Do NOT repeat the question.
                - Write one coherent explanation instead of listing retrieved chunks.
                - Combine Enterprise and ICS information naturally when both are available.
                - Explain similarities and differences only when supported by the retrieved context.
                - Summarize instead of copying long passages.
                - Keep the answer concise.
                - If the retrieved context contains only a short advisory, produce a short answer that summarizes only the available information.
                - Do not reject the question simply because the retrieved context is brief.
                - Do not use bullet points unless the user explicitly asks for a list.

                Question:
                {query}

                Retrieved Context:
                {context}

                Answer:
                """
        if os.getenv("DEBUG", "").lower() == "true" or os.getenv("RAG_DEBUG_CONTEXT", "").lower() in {"1", "true", "yes"}:
            print("=" * 80, flush=True)
            print("CONTEXT LENGTH:", len(context), flush=True)
            print(context, flush=True)
            print("=" * 80, flush=True)
        response = self._get_client().invoke(prompt)
        return clean_answer_text(getattr(response, "content", str(response)).strip())


class DeterministicAnswerService(AnswerService):
    def generate(self, query: str, context: str) -> str:
        from rag.retrieval.context_selector import QueryIntent, detect_query_intent

        if detect_query_intent(query) == QueryIntent.GENERAL_CONCEPT_QUERY:
            return self._format_concept_answer(query, context)

        enterprise = self._select_primary_framework_technique(
            self._parse_framework_techniques(context, "Enterprise ATT&CK"),
            query,
        )
        ics = self._select_primary_framework_technique(
            self._parse_framework_techniques(context, "ICS ATT&CK"),
            query,
        )
        advisories = self._parse_advisories(context)

        if advisories and not enterprise and not ics:
            if self._should_summarize_advisories(query):
                return self._format_advisory_answer(query, advisories)
            return f"I could not derive a concise answer from the selected context for: {query}"

        if not enterprise and not ics and not advisories:
            return f"I could not derive a concise answer from the selected context for: {query}"

        title = enterprise.get("title") or ics.get("title") or "the requested technique"
        opening_description = enterprise.get("description") or ics.get("description") or ""
        opening_normalized = self._normalized_text(opening_description)
        paragraphs: list[str] = []

        if opening_description:
            paragraphs.append(
                f"{title} is an ATT&CK technique in which {self._summary_clause(opening_description)}."
            )
        else:
            paragraphs.append(f"{title} is an ATT&CK technique.")

        if enterprise:
            enterprise_paragraph = self._framework_paragraph(
                enterprise,
                framework="Enterprise ATT&CK",
                opening_description=opening_normalized,
            )
            if enterprise_paragraph:
                paragraphs.append(enterprise_paragraph)
        if ics:
            ics_paragraph = self._framework_paragraph(
                ics,
                framework="ICS ATT&CK",
                corresponding=True,
                opening_description=opening_normalized,
            )
            if ics_paragraph:
                paragraphs.append(ics_paragraph)
        if advisories:
            if self._should_summarize_advisories(query):
                paragraphs.append(self._format_advisory_answer(query, advisories))

        return " ".join(part for part in paragraphs if part).strip()

    @staticmethod
    def _should_summarize_advisories(query: str) -> bool:
        from rag.retrieval.context_selector import ADVISORY_INTENTS, detect_query_intent
        from rag.retrieval.document_fields import extract_cves
        from rag.retrieval.identifier_lookup import extract_cwes

        intent = detect_query_intent(query)
        if intent in ADVISORY_INTENTS:
            return True
        return bool(extract_cves(query) or extract_cwes(query))

    @classmethod
    def _format_concept_answer(cls, query: str, context: str) -> str:
        from rag.retrieval.context_selector import extract_technique_phrase
        from rag.retrieval.query_understanding import extract_security_concepts

        concepts = extract_security_concepts(query)
        concept_label = extract_technique_phrase(query) or (concepts[0].match_phrases[0] if concepts else "the concept")
        enterprise = cls._parse_framework_techniques(context, "Enterprise ATT&CK")
        ics = cls._parse_framework_techniques(context, "ICS ATT&CK")
        techniques = enterprise + ics

        if not techniques:
            return f"I could not derive a concise answer from the selected context for: {query}"

        opening_description = cls._concept_opening_description(concepts, techniques)
        label = concept_label.strip().rstrip("?.!")
        label_text = label[0].upper() + label[1:] if label else "This concept"
        paragraphs: list[str] = []

        if opening_description:
            paragraphs.append(f"{label_text} is a cybersecurity concept in which {cls._summary_clause(opening_description)}.")
        else:
            paragraphs.append(f"The retrieved ATT&CK context describes several techniques related to {label_text.lower()}.")

        if enterprise:
            paragraphs.append(
                "In the Enterprise ATT&CK framework, related techniques include "
                + cls._format_technique_list(enterprise)
                + "."
            )
        if ics:
            paragraphs.append(
                "In the ICS ATT&CK framework, related techniques include "
                + cls._format_technique_list(ics)
                + "."
            )

        return " ".join(part for part in paragraphs if part).strip()

    @staticmethod
    def _concept_opening_description(concepts, techniques: list[dict[str, str]]) -> str:
        if not techniques:
            return ""
        match_phrases = [phrase.lower() for concept in concepts for phrase in concept.match_phrases]
        for technique in techniques:
            description = technique.get("description", "")
            lowered = description.lower()
            if any(phrase in lowered for phrase in match_phrases):
                return description
        return techniques[0].get("description", "")

    @staticmethod
    def _format_technique_list(techniques: list[dict[str, str]]) -> str:
        formatted: list[str] = []
        for technique in techniques:
            attack_id = technique.get("attack_id", "")
            title = technique.get("title", "")
            if attack_id and title:
                formatted.append(f"{attack_id} ({title})")
            elif attack_id:
                formatted.append(attack_id)
            elif title:
                formatted.append(title)
        return ", ".join(formatted)

    @classmethod
    def _format_advisory_answer(cls, query: str, advisories: list[dict[str, str]]) -> str:
        from rag.retrieval.document_fields import extract_cves
        from rag.retrieval.identifier_lookup import extract_cwes

        query_cves = extract_cves(query)
        query_cwes = extract_cwes(query)
        advisory = cls._select_advisory(advisories, query_cves, query_cwes, query=query)

        identifier = advisory.get("identifier", "")
        title = advisory.get("advisory", "")
        product = advisory.get("product", "")
        severity = advisory.get("severity", "")
        cves = advisory.get("cve", "")
        cwes = advisory.get("cwe", "")
        sector = advisory.get("sector", "")
        affected = advisory.get("affected products", "")

        focus_cve = next(iter(sorted(query_cves & cls._split_identifiers(cves)))) if query_cves else ""
        if not focus_cve and query_cves:
            focus_cve = next(iter(sorted(query_cves)))
        if not focus_cve and cves:
            focus_cve = next(iter(sorted(cls._split_identifiers(cves))), "")

        sentences: list[str] = []
        if focus_cve and identifier and title:
            sentences.append(f"{focus_cve} is referenced in CISA ICS Advisory {identifier} for the {title}.")
        elif focus_cve and title:
            sentences.append(f"{focus_cve} is referenced in the CISA advisory for the {title}.")
        elif identifier and title and product:
            sentences.append(
                f"CISA ICS Advisory {identifier} for the {title} describes vulnerabilities affecting {product}."
            )
        elif identifier and title:
            sentences.append(f"CISA ICS Advisory {identifier} covers the {title}.")
        elif title:
            sentences.append(f"The CISA advisory {title} describes the retrieved vulnerability information.")

        detail_parts: list[str] = []
        if severity:
            detail_parts.append(f"the vulnerability as {severity}")
        if cves and not focus_cve:
            detail_parts.append(f"references {cves}")
        if cwes:
            detail_parts.append(f"associates it with {cwes}")
        if detail_parts:
            sentences.append(f"The advisory identifies {' and '.join(detail_parts)}.")

        affected_summary = cls._summarize_affected_products(affected, product)
        if affected_summary:
            sentences.append(affected_summary + ".")
        elif product:
            sentences.append(f"The affected product is {product}.")

        if sector:
            sentences.append(f"The affected sector is {sector}.")

        return " ".join(sentence.strip() for sentence in sentences if sentence.strip())

    @staticmethod
    def _select_advisory(
        advisories: list[dict[str, str]],
        query_cves: set[str],
        query_cwes: set[str],
        query: str = "",
    ) -> dict[str, str]:
        if query_cves:
            for advisory in advisories:
                if query_cves & DeterministicAnswerService._split_identifiers(advisory.get("cve", "")):
                    return advisory
        if query_cwes:
            for advisory in advisories:
                if query_cwes & DeterministicAnswerService._split_identifiers(advisory.get("cwe", "")):
                    return advisory
        phrase = DeterministicAnswerService._product_query_phrase(query)
        if phrase:
            for advisory in advisories:
                blob = DeterministicAnswerService._normalized_text(
                    " ".join(
                        advisory.get(key, "")
                        for key in ("advisory", "product", "vendor", "affected products")
                    )
                )
                if phrase in blob:
                    return advisory
                if any(token in blob for token in phrase.split() if len(token) >= 4):
                    return advisory
        return advisories[0]

    @staticmethod
    def _product_query_phrase(query: str) -> str:
        from rag.retrieval.context_selector import extract_technique_phrase

        return DeterministicAnswerService._normalized_text(extract_technique_phrase(query) or query)

    @staticmethod
    def _split_identifiers(value: str) -> set[str]:
        return {
            part.strip().upper()
            for part in re.split(r"[,;]", value)
            if part.strip()
        }

    @staticmethod
    def _summarize_affected_products(affected: str, product: str) -> str:
        affected = re.sub(r"\s+", " ", affected.strip())
        if not affected:
            return ""
        prior_match = re.search(r"prior to ([\d.]+)", affected, flags=re.IGNORECASE)
        if prior_match and product:
            return f"It affects multiple {product} products prior to version {prior_match.group(1)}"
        if prior_match:
            return f"It affects multiple products prior to version {prior_match.group(1)}"
        if len(affected) > 180:
            return f"It affects {affected[:180].rsplit(' ', 1)[0]}"
        return f"It affects {affected}"

    @staticmethod
    def _parse_advisories(context: str) -> list[dict[str, str]]:
        pattern = re.compile(
            r"^Supporting Advisories\n(.*?)(?=\n\n[A-Z][^\n]+\n|\Z)",
            flags=re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(context)
        if not match:
            return []

        advisories: list[dict[str, str]] = []
        for block in re.split(r"\n\s*\n", match.group(1).strip()):
            if not block.strip():
                continue
            fields: dict[str, str] = {}
            for line in block.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
            if fields:
                advisories.append(fields)
        return advisories

    @classmethod
    def _framework_paragraph(
        cls,
        framework_data: dict[str, str],
        *,
        framework: str,
        corresponding: bool = False,
        opening_description: str = "",
    ) -> str:
        attack_id = framework_data.get("attack_id") or "the relevant technique ID"
        description = framework_data.get("description", "").strip()
        platforms = framework_data.get("platforms", "").strip()
        description_normalized = cls._normalized_text(description)

        if corresponding:
            prefix = f"In the {framework} framework, the corresponding technique is {attack_id}"
        else:
            prefix = f"In the {framework} framework, this technique is identified as {attack_id}"

        if corresponding and description:
            if description_normalized != opening_description:
                return f"{prefix}, where {cls._summary_clause(description)}."
            return prefix + "."
        if description and description_normalized != opening_description:
            return f"{prefix} and describes {cls._detail_phrase(description)}."
        if platforms:
            return f"{prefix} and applies to platforms such as {platforms}."
        return prefix + "."

    @staticmethod
    def _framework_section_pattern(heading: str) -> re.Pattern[str]:
        next_sections = ("Enterprise ATT&CK", "ICS ATT&CK", "Supporting Advisories", "Other Sources")
        alternatives = "|".join(re.escape(section) for section in next_sections if section != heading)
        return re.compile(
            rf"^{re.escape(heading)}\n(.*?)(?=\n\n(?:{alternatives})\n|\Z)",
            flags=re.MULTILINE | re.DOTALL,
        )

    @staticmethod
    def _select_primary_framework_technique(techniques: list[dict[str, str]], query: str) -> dict[str, str]:
        if not techniques:
            return {}
        from rag.retrieval.context_selector import extract_technique_phrase, normalize_text
        from rag.retrieval.document_fields import extract_attack_ids

        query_ids = extract_attack_ids(query)
        if query_ids:
            for technique in techniques:
                if technique.get("attack_id", "").upper() in query_ids:
                    return technique

        phrase = normalize_text(extract_technique_phrase(query) or "")
        if phrase:
            matches: list[dict[str, str]] = []
            for technique in techniques:
                title = normalize_text(technique.get("title", ""))
                if title == phrase or phrase in title or title in phrase:
                    matches.append(technique)
            if len(matches) == 1:
                return matches[0]

        # Anchor to the first rendered technique (highest-ranked selected chunk).
        return techniques[0]

    @staticmethod
    def _parse_framework(context: str, heading: str) -> dict[str, str]:
        techniques = DeterministicAnswerService._parse_framework_techniques(context, heading)
        return techniques[0] if techniques else {}

    @staticmethod
    def _parse_framework_techniques(context: str, heading: str) -> list[dict[str, str]]:
        match = DeterministicAnswerService._framework_section_pattern(heading).search(context)
        if not match:
            return []

        techniques: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in match.group(1).splitlines():
            if line.startswith("Technique:"):
                if current:
                    techniques.append(current)
                technique = line.split(":", 1)[1].strip()
                attack_id_match = re.search(r"\((T\d{4}(?:\.\d{3})?)\)", technique)
                current = {
                    "technique": technique,
                    "attack_id": attack_id_match.group(1) if attack_id_match else "",
                    "title": re.sub(r"\s*\(T\d{4}(?:\.\d{3})?\)\s*$", "", technique).strip(),
                }
                continue
            if ":" not in line or not current:
                continue
            key, value = line.split(":", 1)
            current[key.strip().lower()] = value.strip()
        if current:
            techniques.append(current)
        return techniques

    @staticmethod
    def _parse_section_lines(context: str, heading: str) -> list[str]:
        pattern = re.compile(rf"^{re.escape(heading)}\n(.*?)(?=\n\n[A-Z][^\n]+\n|\Z)", flags=re.MULTILINE | re.DOTALL)
        match = pattern.search(context)
        if not match:
            return []
        return [line.split(":", 1)[1].strip() for line in match.group(1).splitlines() if ":" in line]

    @staticmethod
    def _normalized_text(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    @staticmethod
    def _normalize_description_clause(text: str) -> str:
        text = re.sub(r"\s+", " ", text.strip())
        return re.sub(r"(?i)\badversaries\s*may\b", "Adversaries may", text)

    @staticmethod
    def _lead_description(description: str) -> str:
        description = DeterministicAnswerService._normalize_description_clause(description)
        first_sentence = re.split(r"(?<=[.!?])\s+", description)[0]
        return first_sentence.rstrip(".")

    @staticmethod
    def _detail_phrase(description: str) -> str:
        clause = DeterministicAnswerService._summary_clause(description)
        if clause.startswith("adversaries "):
            return f"how {clause}"
        return clause

    @staticmethod
    def _summary_clause(description: str) -> str:
        clause = DeterministicAnswerService._lead_description(description)
        if not clause:
            return ""
        if clause[0].isupper():
            return clause[0].lower() + clause[1:]
        return clause
