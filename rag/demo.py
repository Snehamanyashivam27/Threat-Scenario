from __future__ import annotations

from pathlib import Path

from rag.pipeline import KnowledgeBasePipeline
from rag.generation.rag_assistant import RAGAssistant
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.vector_retriever import VectorRetriever
from rag.runtime import create_answer_service, create_context_generator, create_embedding_service, default_persist_directory


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    embedding_service = create_embedding_service()
    pipeline = KnowledgeBasePipeline(
        embedding_service=embedding_service,
        persist_directory=default_persist_directory(root),
        context_generator=create_context_generator(root=root),
    )

    chunks = pipeline.build_chunks(
        root / "enterprise-attack.json",
        root / "ics-attack.json",
        root / "CISA_ICS_ADV_Master.csv",
    )
    pipeline.index(chunks[:200])

    bm25 = BM25Retriever(chunks[:200])
    vector = VectorRetriever(pipeline.store)
    hybrid = HybridRetriever(vector, bm25)
    assistant = RAGAssistant(hybrid, create_answer_service(use_deterministic=True))

    query = "unauthorized remote code execution in industrial control systems"
    result = assistant.ask(query, k=5)
    print(f"Question:\n{result.question}\n")
    print(f"Answer:\n{result.answer}\n")
    print("Sources")
    for source in result.sources:
        if source.attack_id:
            print(f"* {source.document_source} {source.attack_id}")
        else:
            print(f"* {source.document_source}")


if __name__ == "__main__":
    main()
