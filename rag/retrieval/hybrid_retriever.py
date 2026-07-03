from __future__ import annotations

import re

from rag.models.document import RetrievedChunk
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.identifier_lookup import lookup_by_identifiers
from rag.retrieval.query_understanding import expand_query_for_retrieval, has_security_concept
from rag.retrieval.retrieval_debug import log_ranked_chunks, log_stage
from rag.retrieval.rrf import reciprocal_rank_fusion
from rag.retrieval.vector_retriever import VectorRetriever


class HybridRetriever:
    def __init__(self, vector_retriever: VectorRetriever, bm25_retriever: BM25Retriever, rrf_k: int = 60):
        self.vector_retriever = vector_retriever
        self.bm25_retriever = bm25_retriever
        self.rrf_k = rrf_k

    def retrieve(self, query: str, k: int = 5, candidate_k: int | None = None) -> list[RetrievedChunk]:
        from rag.retrieval.context_selector import QueryIntent, detect_query_intent

        intent = detect_query_intent(query)
        identifier_results = self._lookup_by_identifiers(query)
        if identifier_results:
            log_stage("identifier_lookup", query=query, matches=len(identifier_results))
            log_ranked_chunks("identifier results", identifier_results)
            return identifier_results[:k]

        candidate_k = self._candidate_pool_size(intent, candidate_k)
        retrieval_query = expand_query_for_retrieval(query)
        log_stage(
            "hybrid_retrieval",
            query=query,
            intent=intent.value,
            expanded_query=retrieval_query,
            candidate_k=candidate_k,
        )

        vector_results = self.vector_retriever.retrieve(retrieval_query, k=candidate_k)
        bm25_results = self.bm25_retriever.retrieve(retrieval_query, k=candidate_k)
        log_ranked_chunks("vector results", vector_results)
        log_ranked_chunks("bm25 results", bm25_results)

        fused = reciprocal_rank_fusion(
            [vector_results, bm25_results],
            k=self.rrf_k,
            weights=self._rrf_weights(intent),
        )
        ranked = self._apply_query_source_bias(query, self._apply_exact_name_bias(query, fused))
        log_ranked_chunks("rrf results", ranked)
        return ranked[:k]

    def retrieve_with_debug(self, query: str, k: int = 5, candidate_k: int | None = None) -> tuple[list[RetrievedChunk], list[RetrievedChunk], list[RetrievedChunk]]:
        from rag.retrieval.context_selector import detect_query_intent

        intent = detect_query_intent(query)
        identifier_results = self._lookup_by_identifiers(query)
        if identifier_results:
            log_stage("identifier_lookup", query=query, matches=len(identifier_results))
            return [], [], identifier_results[:k]

        candidate_k = self._candidate_pool_size(intent, candidate_k)
        retrieval_query = expand_query_for_retrieval(query)
        log_stage("hybrid_retrieval", query=query, intent=intent.value, expanded_query=retrieval_query)

        vector_results = self.vector_retriever.retrieve(retrieval_query, k=candidate_k)
        bm25_results = self.bm25_retriever.retrieve(retrieval_query, k=candidate_k)
        fused = self._apply_query_source_bias(
            query,
            self._apply_exact_name_bias(
                query,
                reciprocal_rank_fusion(
                    [vector_results, bm25_results],
                    k=self.rrf_k,
                    weights=self._rrf_weights(intent),
                ),
            ),
        )[:k]
        return vector_results, bm25_results, fused

    @staticmethod
    def _candidate_pool_size(intent, candidate_k: int | None) -> int:
        from rag.retrieval.context_selector import QueryIntent

        if candidate_k is not None:
            return candidate_k
        if intent == QueryIntent.GENERAL_CONCEPT_QUERY:
            return 30
        if intent == QueryIntent.ATTACK_TACTIC_LOOKUP:
            return 25
        return 20

    @staticmethod
    def _rrf_weights(intent) -> list[float] | None:
        from rag.retrieval.context_selector import QueryIntent

        if intent == QueryIntent.GENERAL_CONCEPT_QUERY:
            return [0.9, 1.2]
        return None

    def _lookup_by_identifiers(self, query: str) -> list[RetrievedChunk]:
        chunks = getattr(self.bm25_retriever, "chunks", None)
        if not chunks:
            return []
        return lookup_by_identifiers(chunks, query)

    @staticmethod
    def _apply_exact_name_bias(query: str, results: list[RetrievedChunk]) -> list[RetrievedChunk]:
        normalized_query = HybridRetriever._normalize(query)

        def boosted_score(item: RetrievedChunk) -> float:
            title = HybridRetriever._extract_title(item)
            normalized_title = HybridRetriever._normalize(title)
            boost = 0.0
            if normalized_title == normalized_query:
                boost = 1.0
            elif normalized_title and normalized_title in normalized_query:
                boost = 0.5
            return item.score + boost

        boosted_results = [
            RetrievedChunk(
                chunk_id=item.chunk_id,
                score=boosted_score(item),
                source=item.source,
                document_id=item.document_id,
                metadata={**dict(item.metadata), "rrf_score": item.score},
                text=item.text,
                contextual_text=item.contextual_text,
            )
            for item in results
        ]
        return sorted(boosted_results, key=lambda item: (-item.score, -float(item.metadata.get("rrf_score", 0.0)), item.chunk_id))

    @staticmethod
    def _apply_query_source_bias(query: str, results: list[RetrievedChunk]) -> list[RetrievedChunk]:
        advisory_intent = HybridRetriever._has_advisory_intent(query)
        attack_intent = HybridRetriever._has_attack_intent(query, results)

        reranked: list[RetrievedChunk] = []
        for item in results:
            source_group = HybridRetriever._source_group(item)
            bias = 0.0
            if attack_intent and source_group in {"enterprise", "ics"}:
                bias += 0.25
            if not advisory_intent and source_group == "cisa":
                bias -= 0.15
            if advisory_intent and source_group == "cisa":
                bias += 0.2
            reranked.append(
                RetrievedChunk(
                    chunk_id=item.chunk_id,
                    score=max(item.score + bias, 0.0),
                    source=item.source,
                    document_id=item.document_id,
                    metadata={**dict(item.metadata), "source_bias": bias},
                    text=item.text,
                    contextual_text=item.contextual_text,
                )
            )
        return sorted(reranked, key=lambda item: (-item.score, -float(item.metadata.get("rrf_score", 0.0)), item.chunk_id))

    @staticmethod
    def _has_attack_intent(query: str, results: list[RetrievedChunk]) -> bool:
        normalized_query = HybridRetriever._normalize(query)
        if re.search(r"\bT\d{4}(?:\.\d{3})?\b", query, flags=re.IGNORECASE):
            return True
        if has_security_concept(query):
            return True
        for item in results:
            if HybridRetriever._source_group(item) not in {"enterprise", "ics"}:
                continue
            title = HybridRetriever._normalize(HybridRetriever._extract_title(item))
            if title and (title in normalized_query or normalized_query in title):
                return True
        return False

    @staticmethod
    def _has_advisory_intent(query: str) -> bool:
        tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        advisory_terms = {"advisory", "advisories", "cisa", "cve", "cves", "vendor", "vendors", "vulnerability", "vulnerabilities", "product", "products"}
        return bool(tokens & advisory_terms) or bool(re.search(r"\bCVE-\d{4}-\d+\b", query, flags=re.IGNORECASE))

    @staticmethod
    def _source_group(item: RetrievedChunk) -> str:
        source = str(item.source or item.metadata.get("source") or item.metadata.get("meta_source_type") or "").lower()
        if "enterprise-attack" in source:
            return "enterprise"
        if "ics-attack" in source:
            return "ics"
        if "cisa" in source or "ics_adv" in source:
            return "cisa"
        return "other"

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()

    @staticmethod
    def _extract_title(item: RetrievedChunk) -> str:
        title = str(item.metadata.get("title") or "")
        if title:
            return title
        if not item.text:
            return ""
        first_line = item.text.splitlines()[0].strip()
        first_line = re.sub(r"^(Technique Name|Technique|Advisory|Title)\s*:\s*", "", first_line, flags=re.IGNORECASE)
        first_line = re.split(r"\s+(ATT&CK ID|Tactic|Platforms?|Description)\s*:", first_line, maxsplit=1, flags=re.IGNORECASE)[0]
        return first_line.strip()
