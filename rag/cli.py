from __future__ import annotations

import argparse
import os
from pathlib import Path

from rag.generation.answer_cleanup import clean_answer_text, strip_embedded_sources
from rag.generation.rag_assistant import RAGAssistant
from rag.models.answer import SourceReference, dedupe_sources
from rag.models.document import RetrievedChunk
from rag.pipeline import KnowledgeBasePipeline
from rag.retrieval.bm25_retriever import BM25Retriever
from rag.retrieval.hybrid_retriever import HybridRetriever
from rag.retrieval.vector_retriever import VectorRetriever
from rag.runtime import create_answer_service, create_context_generator, create_embedding_service, default_persist_directory, chroma_collection_name


def build_retriever(root: Path, deterministic: bool = False, reindex: bool = False) -> HybridRetriever:
    embedding_service = create_embedding_service(use_deterministic=deterministic)
    pipeline = KnowledgeBasePipeline(
        embedding_service=embedding_service,
        persist_directory=default_persist_directory(root),
        context_generator=create_context_generator(root=root),
        collection_name=chroma_collection_name(embedding_service),
    )

    chunks = pipeline.build_chunks(
        root / "enterprise-attack.json",
        root / "ics-attack.json",
        root / "CISA_ICS_ADV_Master.csv",
    )
    if reindex or not pipeline.store.has_indexed_chunks():
        print(f"Indexing {len(chunks)} chunks into '{pipeline.store.collection_name}'...", flush=True)
        pipeline.index(chunks)
    else:
        print(f"Using existing Chroma index '{pipeline.store.collection_name}' ({pipeline.store.chunk_count()} chunks). Pass --reindex to rebuild.", flush=True)

    bm25 = BM25Retriever(chunks)
    vector = VectorRetriever(pipeline.store)
    return HybridRetriever(vector, bm25)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive RAG retrieval CLI")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Project root containing the knowledge base files")
    parser.add_argument("--top-k", type=int, default=5, help="Legacy retrieval setting; post-retrieval selection keeps the top 2-3 documents")
    parser.add_argument("--deterministic", action="store_true", help="Use deterministic local embeddings instead of Ollama")
    parser.add_argument("--reindex", action="store_true", help="Force a full Chroma re-index even if an index already exists")
    parser.add_argument("--debug-retrieval", action="store_true", default=os.getenv("DEBUG", "").lower() == "true", help="Print vector, BM25, and RRF results separately")
    return parser.parse_args()


def _print_ranked_results(title: str, results: list[RetrievedChunk]) -> None:
    print(f"\n===== {title} =====\n")
    if not results:
        print("No results\n")
        return
    for index, item in enumerate(results, start=1):
        print(f"Rank {index} | Score {item.score:.4f} | Document {item.document_id} | Source {item.source}")
        print(f"Chunk: {item.chunk_id}")
        print(f"Text: {item.text[:350]}")
        if item.contextual_text:
            print(f"Context: {item.contextual_text[:350]}")
        print()


def _print_sources(sources: list[SourceReference]) -> None:
    sources = dedupe_sources(sources)
    print("Sources")
    if not sources:
        print("None")
        print()
        return
    for source in sources:
        if source.attack_id:
            print(f"* {source.document_source} {source.attack_id}")
        else:
            print(f"* {source.document_source}")
    print()


def main() -> None:
    args = parse_args()
    retriever = build_retriever(args.root, deterministic=args.deterministic, reindex=args.reindex)
    answer_service = create_answer_service(use_deterministic=args.deterministic)
    assistant = RAGAssistant(retriever, answer_service)

    print("RAG Retrieval CLI")
    print("Enter a question to retrieve top chunks. Press Enter on an empty line to exit.\n")

    while True:
        try:
            query = input("Query: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not query:
            break

        if args.debug_retrieval:
            debug_k = min(max(args.top_k, 3), 5)
            vector_results, bm25_results, fused_results = retriever.retrieve_with_debug(query, k=debug_k)
            _print_ranked_results("Vector Results", vector_results)
            _print_ranked_results("BM25 Results", bm25_results)
            _print_ranked_results("RRF Results", fused_results)

        result = assistant.ask(query, k=args.top_k)
        answer = clean_answer_text(result.answer)
        print(f"\nQuestion:\n{result.question}\n")
        print(f"Answer:\n{answer}\n")
        _print_sources(result.sources)


if __name__ == "__main__":
    main()
