from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from rag.utils.text import clean_text, dedupe_preserve_order

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
ADVISORY_RE = re.compile(r"\b(?:ICSA|ICSMA|ICSALERT)-\d{2}-\d{3}-\d{2}\b", re.IGNORECASE)
_SKIP_TAGS = frozenset({"script", "style", "noscript"})
_VENDOR_HEADING = re.compile(
    r"vendor\s+(?:mitigation|workaround|remediation|fix)|recommended\s+update",
    flags=re.IGNORECASE,
)
_WORKAROUND_HEADING = re.compile(r"workaround", flags=re.IGNORECASE)
_MITIGATION_HEADING = re.compile(r"mitigation|remediation", flags=re.IGNORECASE)
_CISA_BOILERPLATE_HEADING = re.compile(
    r"cisa\s+recommend|defensive\s+measure|organizations\s+should",
    flags=re.IGNORECASE,
)
_CISA_BOILERPLATE_BODY = re.compile(
    r"cisa\s+recommends|minimize\s+network\s+exposure|isolate\s+ics\s+networks|"
    r"defense[- ]in[- ]depth",
    flags=re.IGNORECASE,
)
_UPDATE_HINT = re.compile(
    r"\b(?:update|upgrade|patch|firmware|fixed in|apply)\b",
    flags=re.IGNORECASE,
)


@dataclass(slots=True)
class AdvisoryDetail:
    advisory_id: str
    cve_ids: list[str] = field(default_factory=list)
    title: str = ""
    remediations: list[dict[str, Any]] = field(default_factory=list)
    cve_descriptions: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    source_type: str = "cisa_ics_advisory_detail"
    source_url: str = ""
    field_provenance: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "cve_ids": list(self.cve_ids),
            "title": self.title,
            "remediations": list(self.remediations),
            "cve_descriptions": dict(self.cve_descriptions),
            "references": list(self.references),
            "source_type": self.source_type,
            "source_url": self.source_url,
            "field_provenance": dict(self.field_provenance),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AdvisoryDetail:
        payload = data or {}
        return cls(
            advisory_id=str(payload.get("advisory_id") or "").upper(),
            cve_ids=[str(item).upper() for item in payload.get("cve_ids") or []],
            title=str(payload.get("title") or ""),
            remediations=list(payload.get("remediations") or []),
            cve_descriptions={
                str(key).upper(): str(value)
                for key, value in (payload.get("cve_descriptions") or {}).items()
            },
            references=list(payload.get("references") or []),
            source_type=str(payload.get("source_type") or "cisa_ics_advisory_detail"),
            source_url=str(payload.get("source_url") or ""),
            field_provenance=dict(payload.get("field_provenance") or {}),
        )


def parse_cisa_advisory_html(
    html: str,
    *,
    advisory_id: str = "",
    source_url: str = "",
) -> AdvisoryDetail:
    blocks = _HeadingCollector().collect(html)
    title = next((text for heading, text in blocks if heading.lower() in {"title", "h1"}), "")
    cves = dedupe_preserve_order(item.upper() for item in CVE_RE.findall(html))
    resolved_advisory = (advisory_id or "").upper()
    if not resolved_advisory:
        match = ADVISORY_RE.search(html)
        resolved_advisory = match.group(0).upper() if match else ""
    remediations: list[dict[str, Any]] = []
    descriptions: dict[str, str] = {}
    for heading, text in blocks:
        heading_clean = clean_text(heading)
        body = clean_text(text)
        if not body:
            continue
        if _is_description_heading(heading_clean):
            bound = _explicit_cve_binding(heading_clean, body, cves)
            if len(bound) == 1:
                descriptions.setdefault(bound[0], body)
            continue
        if not _is_remediation_heading(heading_clean):
            continue
        if _CISA_BOILERPLATE_HEADING.search(heading_clean) or _CISA_BOILERPLATE_BODY.search(body):
            continue
        category = _category_from_heading(heading_clean, body)
        for paragraph in _split_paragraphs(text):
            details = clean_text(paragraph)
            if len(details) < 24:
                continue
            if _CISA_BOILERPLATE_BODY.search(details):
                continue
            bound = _explicit_cve_binding(heading_clean, details, cves)
            if len(bound) == 1:
                scope = "cve_specific"
                scoped_cves = bound
            else:
                # Product/version wording alone is not an explicit binding.
                scope = "advisory_level"
                scoped_cves = []
            remediations.append(
                {
                    "category": category,
                    "details": details,
                    "scope": scope,
                    "cve_ids": scoped_cves,
                    "product_ids": [],
                    "urls": [],
                    "provenance": f"{resolved_advisory}:{scope}:{heading_clean}",
                }
            )
    return AdvisoryDetail(
        advisory_id=resolved_advisory,
        cve_ids=cves,
        title=clean_text(title),
        remediations=_dedupe_remediations(remediations),
        cve_descriptions=descriptions,
        source_url=source_url,
        field_provenance={
            "remediations": "cisa_ics_advisory_detail" if remediations else "",
            "cve_descriptions": "cisa_ics_advisory_detail" if descriptions else "",
        },
    )


def _is_remediation_heading(heading: str) -> bool:
    return bool(
        _VENDOR_HEADING.search(heading)
        or _WORKAROUND_HEADING.search(heading)
        or _MITIGATION_HEADING.search(heading)
    )


def _is_description_heading(heading: str) -> bool:
    lowered = heading.lower()
    return "vulnerability" in lowered or lowered.startswith("cve-") or "overview" in lowered


def _category_from_heading(heading: str, body: str) -> str:
    if _WORKAROUND_HEADING.search(heading) and not _UPDATE_HINT.search(body):
        return "workaround"
    if _UPDATE_HINT.search(heading) or _UPDATE_HINT.search(body) or _VENDOR_HEADING.search(heading):
        return "vendor_fix"
    return "mitigation"


def _explicit_cve_binding(heading: str, body: str, known: list[str]) -> list[str]:
    found = dedupe_preserve_order(item.upper() for item in CVE_RE.findall(f"{heading} {body}"))
    known_set = {item.upper() for item in known}
    if known_set:
        found = [item for item in found if item in known_set]
    return found


def _split_paragraphs(text: str) -> list[str]:
    parts = re.split(r"\n\s*\n+|•|\n-\s+", text)
    return [part.strip() for part in parts if part.strip()]


def _dedupe_remediations(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        key = (str(item.get("category") or ""), str(item.get("details") or ""), str(item.get("scope") or ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


class _HeadingCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._heading_tag = ""
        self._heading_parts: list[str] = []
        self._body_parts: list[str] = []
        self.blocks: list[tuple[str, str]] = []
        self._current_heading = "body"

    def collect(self, html: str) -> list[tuple[str, str]]:
        self.feed(html or "")
        self.close()
        self._flush()
        return self.blocks

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        if self._skip:
            return
        if tag in {"h1", "h2", "h3", "h4"}:
            self._flush()
            self._heading_tag = tag
            self._heading_parts = []
        elif tag in {"p", "li", "br", "div"}:
            self._body_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip:
            self._skip -= 1
            return
        if self._heading_tag and tag == self._heading_tag:
            self._current_heading = clean_text(" ".join(self._heading_parts)) or tag
            self._heading_tag = ""
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._heading_tag:
            self._heading_parts.append(data)
        else:
            self._body_parts.append(data)

    def _flush(self) -> None:
        text = "".join(self._body_parts).strip()
        if text:
            self.blocks.append((self._current_heading, text))
        self._body_parts = []
