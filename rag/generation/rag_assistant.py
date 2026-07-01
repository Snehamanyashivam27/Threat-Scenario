from __future__ import annotations

from rag.generation.answer_cleanup import clean_answer_text, strip_embedded_sources
from rag.generation.answer_service import AnswerService
from rag.generation.context_builder import ContextBuilder
from rag.models.answer import AnswerResult, dedupe_sources
from rag.retrieval.context_selector import ContextSelector
from rag.retrieval.hybrid_retriever import HybridRetriever


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
        retrieved_chunks = self.retriever.retrieve(query, k=self.RETRIEVAL_POOL_SIZE)
        selected_chunks = self.context_selector.select(query, retrieved_chunks)
        context = self.context_builder.build(selected_chunks, query=query)
        answer = clean_answer_text(self.answer_service.generate(query, context))
        sources = dedupe_sources(self.context_builder.build_sources(selected_chunks))
        return AnswerResult(question=query, answer=answer, sources=sources)
