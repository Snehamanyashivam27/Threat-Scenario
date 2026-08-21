from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from rag.cli import build_retriever
from rag.generation.rag_assistant import RAGAssistant
from rag.retrieval.retrieval_debug import is_retrieval_debug_enabled
from rag.runtime import create_answer_service
from rag.scenario.narrative_generator import ScenarioNarrativeGenerator
from rag.scenario.evidence_format import format_evidence_trace
from rag.scenario.synthesizer import ScenarioNarrativeSynthesizer, ScenarioSynthesisAnswerService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a deterministic threat scenario narrative")
    parser.add_argument(
        "--scenario",
        type=Path,
        required=True,
        help="Folder containing scenario.json and attack_path.json",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Project root containing the knowledge base files",
    )
    parser.add_argument("--top-k", type=int, default=5, help="Retrieval pool size hint for each step query")
    parser.add_argument("--deterministic", action="store_true", help="Use deterministic local embeddings and answer formatting")
    parser.add_argument("--reindex", action="store_true", help="Force a full Chroma re-index even if an index already exists")
    parser.add_argument(
        "--debug-retrieval",
        action="store_true",
        default=is_retrieval_debug_enabled(),
        help="Print retrieval pipeline debug output for each step query",
    )
    parser.add_argument(
        "--show-evidence",
        action="store_true",
        help="Print structured per-step retrieval and applicability evidence after the narrative",
    )
    parser.add_argument(
        "--show-defenses",
        action="store_true",
        help="Print evidence-backed remediations and D3FEND-style controls after the narrative",
    )
    return parser.parse_args()


def _print_narrative(narrative: str) -> None:
    print(narrative.strip())
    print()


def main() -> None:
    args = parse_args()

    if args.debug_retrieval:
        os.environ["RAG_DEBUG_RETRIEVAL"] = "1"

    retriever = build_retriever(args.root, deterministic=args.deterministic, reindex=args.reindex)
    answer_service = create_answer_service(use_deterministic=args.deterministic)
    assistant = RAGAssistant(retriever, answer_service)

    def on_query(query: str) -> None:
        if args.debug_retrieval:
            print(f"Query: {query}", file=sys.stderr, flush=True)

    generator = ScenarioNarrativeGenerator(
        assistant=assistant,
        synthesizer=ScenarioNarrativeSynthesizer(
            answer_service=ScenarioSynthesisAnswerService(base_service=answer_service),
        ),
        top_k=args.top_k,
        on_query=on_query,
    )

    result = generator.generate(args.scenario)
    _print_narrative(result.narrative)
    if args.show_evidence:
        print("Evidence trace:")
        print(format_evidence_trace(result.evidence))
        print("Evidence JSON:")
        print(json.dumps([item.to_dict() for item in result.evidence], indent=2, default=str))
    if args.show_defenses:
        from rag.defense.report_pipeline import (
            build_d3fend_control_text,
            build_defense_recommendation_text,
            default_advisory_dir,
            default_attack_sources,
            default_csaf_dir,
        )

        print(
            build_defense_recommendation_text(
                result,
                scenario_dir=args.scenario,
                csaf_dir=default_csaf_dir(args.root),
                attack_sources=default_attack_sources(args.root),
                advisory_dir=default_advisory_dir(args.root),
            )
        )
        print()
        print(
            build_d3fend_control_text(
                result,
                scenario_dir=args.scenario,
                csaf_dir=default_csaf_dir(args.root),
                attack_sources=default_attack_sources(args.root),
                advisory_dir=default_advisory_dir(args.root),
            )
        )


if __name__ == "__main__":
    main()
