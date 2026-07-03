from __future__ import annotations

from rag.generation.answer_cleanup import clean_answer_text
from rag.generation.answer_service import AnswerService, DeterministicAnswerService
from rag.generation.context_builder import ContextBuilder
from rag.models.answer import AnswerResult, dedupe_sources
from rag.retrieval.context_selector import ADVISORY_INTENTS, ATTACK_INTENTS, CONCEPT_INTENTS, ContextSelector, QueryIntent, detect_query_intent
from rag.retrieval.document_fields import extract_cves
from rag.retrieval.identifier_lookup import extract_cwes
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.retrieval_debug import log_ranked_chunks, log_stage


class RAGAssistant:
    RETRIEVAL_POOL_SIZE = 10

    def __init__(
        self,
        retriever: HybridRetriever,
        answer_service: AnswerService,
        context_selector: ContextSelector | None = None,
        context_builder: ContextBuilder | None = None,
    ):
        self.retriever = retriever
        self.answer_service = answer_service
        self.context_selector = context_selector or ContextSelector(retrieval_pool_size=self.RETRIEVAL_POOL_SIZE)
        self.context_builder = context_builder or ContextBuilder()

    def ask(self, query: str, k: int = 5) -> AnswerResult:
        intent = detect_query_intent(query)
        pool_size = self._retrieval_pool_size(intent)
        log_stage("query_processing", query=query, intent=intent.value, pool_size=pool_size)
        retrieved_chunks = self.retriever.retrieve(query, k=pool_size)
        log_ranked_chunks("retriever_output", retrieved_chunks)
        selected_chunks = self.context_selector.select(query, retrieved_chunks, pool_size=pool_size)
        log_ranked_chunks("context_selector_output", selected_chunks)
        context = self.context_builder.build(selected_chunks, query=query)
        log_stage("prompt_context", length=len(context))
        answer = self._generate_answer(query, context)
        sources = dedupe_sources(self.context_builder.build_sources(selected_chunks))
        return AnswerResult(question=query, answer=answer, sources=sources)

    @staticmethod
    def _retrieval_pool_size(intent: QueryIntent) -> int:
        if intent == QueryIntent.GENERAL_CONCEPT_QUERY:
            return 15
        if intent == QueryIntent.ATTACK_TACTIC_LOOKUP:
            return 15
        return RAGAssistant.RETRIEVAL_POOL_SIZE

    def _generate_answer(self, query: str, context: str) -> str:
        if self._should_use_deterministic_answer(query, context):
            return DeterministicAnswerService().generate(query, context)
        return clean_answer_text(self.answer_service.generate(query, context), context)

    @staticmethod
    def _should_use_deterministic_answer(query: str, context: str) -> bool:
        intent = detect_query_intent(query)
        if intent in ATTACK_INTENTS:
            return True
        if intent in CONCEPT_INTENTS:
            return True
        if intent in ADVISORY_INTENTS and "Supporting Advisories" in context:
            return True
        if (extract_cves(query) or extract_cwes(query)) and "Supporting Advisories" in context:
            return True
        return False
