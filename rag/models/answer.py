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
    by_source: dict[str, SourceReference] = {}
    for source in sources:
        existing = by_source.get(source.document_source)
        if existing is None:
            by_source[source.document_source] = source
        elif source.attack_id and not existing.attack_id:
            by_source[source.document_source] = source
    return list(by_source.values())
