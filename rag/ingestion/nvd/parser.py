from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rag.ingestion.csaf.models import CveDetailRecord, CvePrerequisites
from rag.scenario.affected_product_clauses import is_discrete_identity_token
from rag.scenario.product_evidence import (
    ORIGIN_VULNERABILITY_LOCAL,
    POLARITY_POSITIVE,
    SCOPE_CVE_SPECIFIC,
    STRONG_IDENTITY,
    WEAK_DISCOVERY,
    ProductEvidence,
    source_rank,
)
from rag.utils.text import clean_text, dedupe_preserve_order

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CPE_PATTERN = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*)",
    flags=re.IGNORECASE,
)
_FAMILY_WORDS = frozenset(
    {
        "series",
        "platform",
        "firmware",
        "linux",
        "windows",
        "android",
        "ios",
        "unix",
        "kernel",
    }
)


class NvdParseError(ValueError):
    """Raised when an NVD CVE document cannot be parsed."""


@dataclass(frozen=True, slots=True)
class CpeMatch:
    criteria: str
    part: str
    vendor: str
    product: str
    version: str
    vulnerable: bool = True
    version_start_including: str = ""
    version_start_excluding: str = ""
    version_end_including: str = ""
    version_end_excluding: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "criteria": self.criteria,
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "vulnerable": self.vulnerable,
            "versionStartIncluding": self.version_start_including,
            "versionStartExcluding": self.version_start_excluding,
            "versionEndIncluding": self.version_end_including,
            "versionEndExcluding": self.version_end_excluding,
        }


def parse_nvd_cve_file(path: str | Path) -> CveDetailRecord | None:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return parse_nvd_cve_document(data)
    except NvdParseError:
        return None


def parse_nvd_cve_document(data: dict[str, Any]) -> CveDetailRecord:
    if not isinstance(data, dict):
        raise NvdParseError("NVD document root must be an object")
    if str(data.get("document_type") or "") == "cve_detail" or (
        data.get("cve_id") and data.get("source_type") in {"nvd", "nvd_cve"}
    ):
        record = CveDetailRecord.from_dict(data)
        if record.source_type not in {"nvd", "nvd_cve"}:
            record.source_type = "nvd"
        if not record.cve_id:
            raise NvdParseError("Normalized NVD record is missing cve_id")
        return record
    cve = _extract_cve_object(data)
    cve_id = str(cve.get("id") or "").upper()
    if not CVE_PATTERN.fullmatch(cve_id):
        raise NvdParseError("NVD document is missing a CVE id")
    description = _english_description(cve.get("descriptions") or [])
    cwe_ids = _cwe_ids(cve.get("weaknesses") or [])
    cvss_score, severity = _cvss(cve.get("metrics") or {})
    references = [
        str(item.get("url") or "").strip()
        for item in cve.get("references") or []
        if isinstance(item, dict) and item.get("url")
    ]
    matches = [
        item
        for item in _cpe_matches(cve.get("configurations") or [])
        if item.vulnerable
    ]
    evidence = [_evidence_from_cpe(cve_id, item) for item in matches]
    products = dedupe_preserve_order(item.product_name for item in evidence if item.product_name)
    constraints = [
        {
            "product": item.product_name,
            "version": item.version_constraint,
            "part_number": item.part_number,
        }
        for item in evidence
        if item.version_constraint
    ]
    family = next((item.family for item in evidence if item.family), "")
    model = next((item.model for item in evidence if item.model), "")
    vendor = next((item.vendor for item in evidence if item.vendor), "")
    versions = dedupe_preserve_order(item.version_constraint for item in evidence if item.version_constraint)
    provenance = {
        "description": "nvd" if description else "",
        "cwe_ids": "nvd" if cwe_ids else "",
        "cvss_score": "nvd" if cvss_score is not None else "",
        "references": "nvd" if references else "",
        "cpe_matches": "nvd" if matches else "",
        "affected_products": "nvd" if products else "",
        "affected_versions": "nvd" if versions else "",
    }
    return CveDetailRecord(
        document_type="cve_detail",
        source_type="nvd",
        cve_id=cve_id,
        vendor=vendor or None,
        product=products[0] if products else None,
        product_family=family or None,
        model=model or None,
        affected_versions=versions,
        affected_products=products,
        affected_product_constraints=constraints,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        severity=severity,
        title=cve_id,
        description=description or None,
        prerequisites=CvePrerequisites(),
        references=dedupe_preserve_order(references),
        product_evidence=[item.to_dict() for item in evidence],
        field_provenance={key: value for key, value in provenance.items() if value},
        cpe_matches=[item.to_dict() for item in matches],
    )


def version_constraint_from_cpe(match: CpeMatch) -> str:
    parts: list[str] = []
    if match.version_start_including:
        parts.append(f">= {match.version_start_including}")
    elif match.version_start_excluding:
        parts.append(f"> {match.version_start_excluding}")
    if match.version_end_excluding:
        parts.append(f"prior to {match.version_end_excluding}")
    elif match.version_end_including:
        parts.append(f"{match.version_end_including} and prior")
    if parts:
        return " ".join(parts)
    if match.version and match.version not in {"*", "-", ""}:
        return f"version {match.version}"
    return ""


def classify_cpe_identity(part: str, product: str) -> tuple[str, str, str]:
    """Return (identity_kind, evidence_strength, display_name)."""
    display = _display_product(product)
    if (part or "").lower() == "o":
        return "family", WEAK_DISCOVERY, display
    if not display or display in {"*", "-"}:
        return "vendor", WEAK_DISCOVERY, ""
    tokens = set(re.findall(r"[a-z0-9]+", display.lower()))
    if tokens & _FAMILY_WORDS:
        return "family", WEAK_DISCOVERY, display
    compact = display.replace(" ", "-")
    if is_discrete_identity_token(compact):
        return "model", STRONG_IDENTITY, compact
    return "product", WEAK_DISCOVERY, display


def _evidence_from_cpe(cve_id: str, match: CpeMatch) -> ProductEvidence:
    kind, strength, display = classify_cpe_identity(match.part, match.product)
    if kind == "vendor":
        strength = WEAK_DISCOVERY
    constraint = version_constraint_from_cpe(match)
    notes = ["nvd_cpe"]
    if match.part:
        notes.append(f"cpe_part:{match.part}")
    if kind == "family":
        notes.append("family_or_platform_cpe")
        strength = WEAK_DISCOVERY
    return ProductEvidence(
        cve_id=cve_id,
        product_name=display or _display_product(match.vendor),
        vendor=_display_product(match.vendor),
        family=display if kind == "family" else "",
        model=display if kind == "model" else "",
        identity_kind=kind,
        source="nvd",
        provenance=cve_id,
        identity_origin=ORIGIN_VULNERABILITY_LOCAL,
        evidence_strength=strength,
        polarity=POLARITY_POSITIVE,
        version_constraint=constraint,
        scope=SCOPE_CVE_SPECIFIC,
        specificity_notes=notes,
        source_rank=source_rank("nvd"),
        applicability_dimension="firmware_version" if constraint else "",
        source_field="configurations",
    )


def _extract_cve_object(data: dict[str, Any]) -> dict[str, Any]:
    if isinstance(data.get("cve"), dict) and data["cve"].get("id"):
        return data["cve"]
    vulnerabilities = data.get("vulnerabilities") or []
    if isinstance(vulnerabilities, list) and vulnerabilities:
        first = vulnerabilities[0] or {}
        if isinstance(first, dict) and isinstance(first.get("cve"), dict):
            return first["cve"]
    if data.get("id") and (data.get("descriptions") is not None or data.get("metrics") is not None):
        return data
    raise NvdParseError("Unrecognized NVD CVE JSON shape")


def _english_description(items: list[Any]) -> str:
    english = ""
    fallback = ""
    for item in items:
        if not isinstance(item, dict):
            continue
        value = clean_text(str(item.get("value") or ""))
        if not value:
            continue
        lang = str(item.get("lang") or "").lower()
        if lang in {"en", "en-us"}:
            english = value
            break
        if not fallback:
            fallback = value
    return english or fallback


def _cwe_ids(items: list[Any]) -> list[str]:
    found: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for description in item.get("description") or []:
            if not isinstance(description, dict):
                continue
            found.extend(CWE_PATTERN.findall(str(description.get("value") or "")))
    return dedupe_preserve_order(item.upper() for item in found)


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0] if isinstance(entries[0], dict) else {}
        data = first.get("cvssData") if isinstance(first.get("cvssData"), dict) else first
        score = data.get("baseScore")
        severity = str(data.get("baseSeverity") or first.get("baseSeverity") or "") or None
        try:
            return float(score), severity
        except (TypeError, ValueError):
            return None, severity
    return None, None


def _cpe_matches(configurations: list[Any]) -> list[CpeMatch]:
    matches: list[CpeMatch] = []
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = list(configuration.get("nodes") or [])
        for node in nodes:
            matches.extend(_cpe_matches_from_node(node))
    return matches


def _cpe_matches_from_node(node: Any) -> list[CpeMatch]:
    if not isinstance(node, dict):
        return []
    found: list[CpeMatch] = []
    for item in node.get("cpeMatch") or []:
        parsed = _parse_cpe_match(item)
        if parsed is not None:
            found.append(parsed)
    for child in node.get("children") or []:
        found.extend(_cpe_matches_from_node(child))
    return found


def _parse_cpe_match(item: Any) -> CpeMatch | None:
    if not isinstance(item, dict):
        return None
    criteria = str(item.get("criteria") or item.get("cpe23Uri") or "")
    match = CPE_PATTERN.match(criteria)
    if not match:
        return None
    return CpeMatch(
        criteria=criteria,
        part=match.group("part").lower(),
        vendor=match.group("vendor"),
        product=match.group("product"),
        version=match.group("version"),
        vulnerable=bool(item.get("vulnerable", True)),
        version_start_including=str(item.get("versionStartIncluding") or ""),
        version_start_excluding=str(item.get("versionStartExcluding") or ""),
        version_end_including=str(item.get("versionEndIncluding") or ""),
        version_end_excluding=str(item.get("versionEndExcluding") or ""),
    )


def _display_product(value: str) -> str:
    text = (value or "").strip()
    if not text or text in {"*", "-"}:
        return ""
    return text.replace("_", " ")
