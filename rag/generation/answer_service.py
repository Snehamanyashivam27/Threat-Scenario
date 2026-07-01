from __future__ import annotations

from abc import ABC, abstractmethod
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
                5. If information is missing, explicitly state:
                "The retrieved context does not contain enough information to answer this question."
                6. Prefer correctness over completeness.
                7. If multiple documents are retrieved, prioritize the documents that directly answer the question and ignore loosely related documents.
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

                Answer Style:

                - Begin immediately with the answer.
                - Do NOT repeat the question.
                - Write one coherent explanation instead of listing retrieved chunks.
                - Combine Enterprise and ICS information naturally when both are available.
                - Explain similarities and differences only when supported by the retrieved context.
                - Summarize instead of copying long passages.
                - Keep the answer between 120 and 180 words.
                - Do not use bullet points unless the user explicitly asks for a list.

                Question:
                {query}

                Retrieved Context:
                {context}

                Answer:
                """
        response = self._get_client().invoke(prompt)
        return clean_answer_text(getattr(response, "content", str(response)).strip())


class DeterministicAnswerService(AnswerService):
    def generate(self, query: str, context: str) -> str:
        enterprise = self._parse_framework(context, "Enterprise ATT&CK")
        ics = self._parse_framework(context, "ICS ATT&CK")
        advisories = self._parse_section_lines(context, "Supporting Advisories")

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
            paragraphs.append(f"Supporting advisory context: {advisories[0]}")

        return " ".join(part for part in paragraphs if part).strip()

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
            return f"{prefix}; {cls._lead_description(description)}."
        if description and description_normalized != opening_description:
            return f"{prefix} and describes {cls._detail_phrase(description)}."
        if platforms:
            return f"{prefix} and applies to platforms such as {platforms}."
        return prefix + "."

    @staticmethod
    def _parse_framework(context: str, heading: str) -> dict[str, str]:
        pattern = re.compile(rf"^{re.escape(heading)}\n(.*?)(?=\n\n[A-Z][^\n]+\n|\Z)", flags=re.MULTILINE | re.DOTALL)
        match = pattern.search(context)
        if not match:
            return {}
        block = match.group(1)
        data: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip().lower()] = value.strip()
        technique = data.get("technique", "")
        attack_id_match = re.search(r"\((T\d{4}(?:\.\d{3})?)\)", technique)
        data["attack_id"] = attack_id_match.group(1) if attack_id_match else ""
        data["title"] = re.sub(r"\s*\(T\d{4}(?:\.\d{3})?\)\s*$", "", technique).strip()
        return data

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
    def _lead_description(description: str) -> str:
        first_sentence = re.split(r"(?<=[.!?])\s+", description.strip())[0]
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
