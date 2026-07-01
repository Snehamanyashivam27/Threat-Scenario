from __future__ import annotations

import hashlib
import re
from typing import Iterable, TypeVar

T = TypeVar("T")

_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def strip_markdown_links(text: str) -> str:
    return _MARKDOWN_LINK_RE.sub(r"\1", text)


def clean_text(text: str | None) -> str:
    if not text:
        return ""
    normalized = re.sub(r"\s+", " ", text.replace("\u00a0", " ")).strip()
    return strip_markdown_links(normalized)


def dedupe_preserve_order(values: Iterable[T]) -> list[T]:
    seen: set[T] = set()
    result: list[T] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
