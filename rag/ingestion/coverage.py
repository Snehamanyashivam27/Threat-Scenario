from __future__ import annotations

import csv
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from rag.defense.csaf_remediation import load_csaf_remediation_records
from rag.ingestion.csaf.parser import CsafParseError, parse_csaf_file
from rag.ingestion.nvd.parser import parse_nvd_cve_file
from rag.utils.text import clean_text

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
ADVISORY_RE = re.compile(r"\b(?:ICSA|ICSMA|ICSALERT)-\d{2}-\d{3}-\d{2}\b", re.IGNORECASE)

_BOILERPLATE_PHRASES = (
    "see the advisory",
    "see advisory",
    "refer to the advisory",
    "no description",
    "not available",
    "description unavailable",
    "n/a",
)
_MIN_DESCRIPTION_CHARS = 40
_MIN_ALPHA_CHARS = 24


def is_sufficient_cve_description(text: str | None) -> bool:
    """True only for usable CVE-local technical description text."""
    cleaned = clean_text(text)
    if len(cleaned) < _MIN_DESCRIPTION_CHARS:
        return False
    lowered = cleaned.lower().strip()
    if lowered in {"n/a", "na", "none", "unknown", "see advisory."}:
        return False
    if any(phrase in lowered for phrase in _BOILERPLATE_PHRASES) and len(cleaned) < 160:
        return False
    stripped = CVE_RE.sub(" ", cleaned)
    stripped = re.sub(r"\bCWE-\d+\b", " ", stripped, flags=re.IGNORECASE)
    letters = re.sub(r"[^A-Za-z]+", "", stripped)
    return len(letters) >= _MIN_ALPHA_CHARS


@dataclass(slots=True)
class CveCoverage:
    cve_id: str
    advisory_ids: list[str] = field(default_factory=list)
    identity: bool = False
    applicability: bool = False
    effect_description: bool = False
    remediation: bool = False
    csaf_detail: bool = False
    nvd_detail: bool = False
    csaf_remediation: bool = False
    advisory_remediation: bool = False
    non_affected: bool = False
    sources: list[str] = field(default_factory=list)

    def has_all_required(self) -> bool:
        return bool(
            self.effect_description and self.identity and self.applicability and self.remediation
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["all_required"] = self.has_all_required()
        return payload


@dataclass(slots=True)
class CoverageSummary:
    discovered_cves: int = 0
    csv_cves: int = 0
    complete_evidence: int = 0
    csaf_canonical_detail: int = 0
    nvd_fallback_detail: int = 0
    missing_effect_description: int = 0
    missing_identity: int = 0
    missing_applicability: int = 0
    missing_remediation: int = 0
    non_affected: int = 0
    identity_coverage: int = 0
    applicability_coverage: int = 0
    advisories_with_csaf_remediation: int = 0
    advisories_with_advisory_remediation: int = 0
    advisories_without_defense: int = 0
    csaf_advisories_to_acquire: int = 0
    nvd_cves_to_acquire: int = 0
    newly_acquired: int = 0
    failed_acquisitions: int = 0
    still_missing_effect_description: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_csv_cves(csv_path: str | Path) -> dict[str, set[str]]:
    """Map CVE ID -> advisory IDs from the CISA master CSV."""
    path = Path(csv_path)
    mapping: dict[str, set[str]] = {}
    if not path.is_file():
        return mapping
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            advisory = _advisory_from_row(row)
            for cve in CVE_RE.findall(row.get("CVE_Number") or ""):
                mapping.setdefault(cve.upper(), set())
                if advisory:
                    mapping[cve.upper()].add(advisory)
    return mapping


def assess_corpus_coverage(
    *,
    csv_path: str | Path,
    csaf_dir: str | Path,
    nvd_dir: str | Path,
    advisory_dir: str | Path | None = None,
    cve_ids: Iterable[str] | None = None,
) -> dict[str, CveCoverage]:
    wanted = {item.upper() for item in cve_ids} if cve_ids else None
    by_cve: dict[str, CveCoverage] = {}

    csv_map = discover_csv_cves(csv_path)
    for cve_id, advisories in csv_map.items():
        if wanted and cve_id not in wanted:
            continue
        row = by_cve.setdefault(cve_id, CveCoverage(cve_id=cve_id))
        row.advisory_ids = sorted(set(row.advisory_ids) | advisories)
        if "cisa_csv" not in row.sources:
            row.sources.append("cisa_csv")

    for path in sorted(Path(csaf_dir).glob("*.json")) if Path(csaf_dir).exists() else []:
        try:
            records = parse_csaf_file(path)
        except CsafParseError:
            continue
        remediations = load_csaf_remediation_records(path)
        remed_by_cve = {item.cve_id: item for item in remediations}
        for record in records:
            cve_id = record.cve_id.upper()
            if wanted and cve_id not in wanted:
                continue
            row = by_cve.setdefault(cve_id, CveCoverage(cve_id=cve_id))
            if record.advisory_id and record.advisory_id not in row.advisory_ids:
                row.advisory_ids.append(record.advisory_id)
            row.csaf_detail = True
            if "cisa_csaf" not in row.sources:
                row.sources.append("cisa_csaf")
            if _record_has_identity(record):
                row.identity = True
            if _record_has_applicability(record):
                row.applicability = True
            if _record_has_non_affected(record):
                row.non_affected = True
            if is_sufficient_cve_description(record.description):
                row.effect_description = True
            remed = remed_by_cve.get(cve_id)
            if remed is not None and remed.has_remediation_evidence():
                row.remediation = True
                row.csaf_remediation = True

    nvd_root = Path(nvd_dir)
    if nvd_root.exists():
        for path in sorted(nvd_root.glob("CVE-*.json")):
            record = parse_nvd_cve_file(path)
            if record is None:
                continue
            cve_id = record.cve_id.upper()
            if wanted and cve_id not in wanted:
                continue
            row = by_cve.setdefault(cve_id, CveCoverage(cve_id=cve_id))
            row.nvd_detail = True
            if "nvd" not in row.sources:
                row.sources.append("nvd")
            if _record_has_identity(record):
                row.identity = True
            if _record_has_applicability(record):
                row.applicability = True
            if _record_has_non_affected(record):
                row.non_affected = True
            if is_sufficient_cve_description(record.description):
                row.effect_description = True

    if advisory_dir:
        from rag.ingestion.cisa_advisory.store import AdvisoryDetailStore

        store = AdvisoryDetailStore(advisory_dir)
        for detail in store.all_records():
            if wanted:
                cves = [item for item in detail.cve_ids if item in wanted]
            else:
                cves = list(detail.cve_ids)
            has_remediation = any(item.get("details") for item in detail.remediations)
            for cve_id in cves:
                row = by_cve.setdefault(cve_id, CveCoverage(cve_id=cve_id))
                if detail.advisory_id and detail.advisory_id not in row.advisory_ids:
                    row.advisory_ids.append(detail.advisory_id)
                if "cisa_ics_advisory_detail" not in row.sources:
                    row.sources.append("cisa_ics_advisory_detail")
                if has_remediation:
                    row.advisory_remediation = True
                    row.remediation = True
                if is_sufficient_cve_description(detail.cve_descriptions.get(cve_id) or ""):
                    row.effect_description = True

    return dict(sorted(by_cve.items()))


def summarize_coverage(
    rows: dict[str, CveCoverage],
    *,
    newly_acquired: int = 0,
    failed_acquisitions: int = 0,
    csv_advisories: set[str] | None = None,
    csv_cve_ids: Iterable[str] | None = None,
    csaf_dir: str | Path | None = None,
    nvd_dir: str | Path | None = None,
    refresh: bool = False,
) -> CoverageSummary:
    csv_ids = {item.upper() for item in csv_cve_ids} if csv_cve_ids is not None else None
    scoped = {key: value for key, value in rows.items() if key in csv_ids} if csv_ids is not None else rows
    advisories_csaf: set[str] = set()
    advisories_html: set[str] = set()
    all_advisories: set[str] = set(csv_advisories or [])
    for row in scoped.values():
        all_advisories.update(row.advisory_ids)
        if row.csaf_remediation:
            advisories_csaf.update(row.advisory_ids)
        if row.advisory_remediation:
            advisories_html.update(row.advisory_ids)
    missing_effect = sum(1 for row in scoped.values() if not row.effect_description)
    nvd_root = Path(nvd_dir) if nvd_dir else None
    nvd_to_acquire = 0
    for row in scoped.values():
        if row.effect_description:
            continue
        if nvd_root is not None and (nvd_root / f"{row.cve_id}.json").exists():
            continue
        nvd_to_acquire += 1
    return CoverageSummary(
        discovered_cves=len(rows),
        csv_cves=len(csv_ids) if csv_ids is not None else len(scoped),
        complete_evidence=sum(1 for row in scoped.values() if row.has_all_required()),
        csaf_canonical_detail=sum(1 for row in scoped.values() if row.csaf_detail and row.effect_description),
        nvd_fallback_detail=sum(
            1 for row in scoped.values() if row.nvd_detail and row.effect_description and not row.csaf_detail
        ),
        missing_effect_description=missing_effect,
        missing_identity=sum(1 for row in scoped.values() if not row.identity),
        missing_applicability=sum(1 for row in scoped.values() if not row.applicability),
        missing_remediation=sum(1 for row in scoped.values() if not row.remediation),
        non_affected=sum(1 for row in scoped.values() if row.non_affected),
        identity_coverage=sum(1 for row in scoped.values() if row.identity),
        applicability_coverage=sum(1 for row in scoped.values() if row.applicability),
        advisories_with_csaf_remediation=len(advisories_csaf),
        advisories_with_advisory_remediation=len(advisories_html - advisories_csaf),
        advisories_without_defense=len(all_advisories - advisories_csaf - advisories_html),
        csaf_advisories_to_acquire=_csaf_gap_count(scoped, csv_advisories, csaf_dir, refresh),
        nvd_cves_to_acquire=nvd_to_acquire,
        newly_acquired=newly_acquired,
        failed_acquisitions=failed_acquisitions,
        still_missing_effect_description=missing_effect,
    )


def _advisory_from_row(row: dict[str, str]) -> str:
    for key in ("ICS-CERT_Number", "icsad_ID", "ICS-CERT_Advisory_Title"):
        match = ADVISORY_RE.search(row.get(key) or "")
        if match:
            return match.group(0).upper()
    return ""


def _record_has_identity(record: Any) -> bool:
    if getattr(record, "model", None) or getattr(record, "part_number", None):
        return True
    if getattr(record, "affected_products", None):
        return True
    if getattr(record, "product_evidence", None):
        return True
    if getattr(record, "cpe_matches", None):
        return True
    product = str(getattr(record, "product", "") or "")
    return bool(product.strip())


def _record_has_applicability(record: Any) -> bool:
    if getattr(record, "affected_versions", None):
        return True
    if getattr(record, "affected_product_constraints", None):
        return True
    evidence = getattr(record, "product_evidence", None) or []
    return any(
        (item.get("version_constraint") if isinstance(item, dict) else getattr(item, "version_constraint", ""))
        for item in evidence
    )


def _record_has_non_affected(record: Any) -> bool:
    """True when canonical evidence lists a product as known_not_affected."""
    evidence = getattr(record, "product_evidence", None) or []
    for item in evidence:
        if isinstance(item, dict):
            polarity = str(item.get("polarity") or "")
            provenance = str(item.get("provenance") or "")
        else:
            polarity = str(getattr(item, "polarity", "") or "")
            provenance = str(getattr(item, "provenance", "") or "")
        if polarity.upper() == "NEGATIVE":
            return True
        if "known_not_affected" in provenance.lower().replace("-", "_"):
            return True
    return False


def _csaf_gap_count(
    rows: dict[str, CveCoverage],
    csv_advisories: set[str] | None,
    csaf_dir: str | Path | None,
    refresh: bool,
) -> int:
    advisories = {*(csv_advisories or []), *(adv for row in rows.values() for adv in row.advisory_ids)}
    if csaf_dir is None:
        return len(advisories) if advisories else sum(1 for row in rows.values() if not row.csaf_detail)
    root = Path(csaf_dir)
    missing = 0
    for advisory_id in advisories:
        path = root / f"{advisory_id}.json"
        if refresh or not path.exists():
            missing += 1
    return missing
