from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SourceReference:
    attack_id: str
    document_source: str


@dataclass(slots=True)
class AnswerResult:
    question: str
    answer: str
    sources: list[SourceReference] = field(default_factory=list)


def dedupe_sources(sources: list[SourceReference]) -> list[SourceReference]:
    # Preserve one entry per (framework, identifier) so multi-technique context stays aligned.
    seen: set[tuple[str, str]] = set()
    deduped: list[SourceReference] = []
    for source in sources:
        key = (source.document_source, source.attack_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(source)
    return deduped
