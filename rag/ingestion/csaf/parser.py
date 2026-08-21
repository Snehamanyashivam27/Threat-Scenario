from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from rag.ingestion.csaf.models import CveDetailRecord, CvePrerequisites
from rag.scenario.product_evidence import (
    NEGATIVE,
    NOTE_VECTOR_SHARED,
    POLARITY_NEGATIVE,
    POLARITY_POSITIVE,
    SOURCE_MEMBERSHIP,
    evidence_from_csaf_product,
)
from rag.utils.text import clean_text, dedupe_preserve_order

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
PART_NUMBER_PATTERN = re.compile(r"\b\d[A-Z0-9]{5,}(?:-\d[A-Z0-9]+)+\b", re.IGNORECASE)


class CsafParseError(ValueError):
    """Raised when a CSAF document cannot be parsed into vulnerability records."""


def load_csaf_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise CsafParseError(f"CSAF root must be an object: {path}")
    return data


def parse_csaf_file(path: str | Path) -> list[CveDetailRecord]:
    try:
        data = load_csaf_json(path)
    except json.JSONDecodeError as exc:
        raise CsafParseError(f"Malformed CSAF JSON in {path}: {exc}") from exc
    return parse_csaf_document(data, source_path=str(path))


def parse_csaf_document(data: dict[str, Any], source_path: str | None = None) -> list[CveDetailRecord]:
    if "document" not in data:
        raise CsafParseError(f"Missing CSAF document object{f' in {source_path}' if source_path else ''}")

    document = data.get("document") or {}
    advisory_id = _advisory_id(document)
    product_index = _index_products(data.get("product_tree") or {})
    references = _document_references(document)

    records: list[CveDetailRecord] = []
    seen_cves: set[str] = set()
    status_vectors: list[frozenset[str]] = []
    for vulnerability in data.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        record, vector = _parse_vulnerability(
            vulnerability,
            advisory_id=advisory_id,
            product_index=product_index,
            document_references=references,
        )
        if record is None:
            continue
        # Deduplicate identical CVE entries within one advisory.
        key = record.cve_id.upper()
        if key in seen_cves:
            continue
        seen_cves.add(key)
        records.append(record)
        status_vectors.append(vector)
    _annotate_shared_product_status_vectors(records, status_vectors)
    return records


def parse_csaf_directory(
    directory: str | Path,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[CveDetailRecord]:
    root = Path(directory)
    if not root.exists():
        return []
    paths = sorted(root.glob("*.json"))
    total = len(paths)
    if on_progress is not None:
        on_progress(0, total)
    records: list[CveDetailRecord] = []
    for index, path in enumerate(paths, start=1):
        try:
            records.extend(parse_csaf_file(path))
        except CsafParseError:
            continue
        if on_progress is not None:
            on_progress(index, total)
    return records


def index_product_tree(product_tree: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Resolve CSAF product_ids to source-stated catalog/model/part/version identity."""
    if not isinstance(product_tree, dict):
        return {}
    return _index_products(product_tree)


def _advisory_id(document: dict[str, Any]) -> str:
    tracking = document.get("tracking") or {}
    tracking_id = clean_text(str(tracking.get("id") or ""))
    if tracking_id:
        return tracking_id.upper()
    title = clean_text(str(document.get("title") or ""))
    match = re.search(r"\b(?:ICSA|ICSMA|ICSALERT)-[\dA-Z-]+\b", title, flags=re.IGNORECASE)
    return match.group(0).upper() if match else ""


def _document_references(document: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in document.get("references") or []:
        url = clean_text(str(item.get("url") or ""))
        if url:
            refs.append(url)
    return dedupe_preserve_order(refs)


def _index_products(product_tree: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    def walk(branches: list[dict[str, Any]] | None, path: list[tuple[str, str]]) -> None:
        for branch in branches or []:
            if not isinstance(branch, dict):
                continue
            category = clean_text(str(branch.get("category") or ""))
            name = clean_text(str(branch.get("name") or ""))
            next_path = path + [(category, name)] if name else path
            product = branch.get("product")
            if isinstance(product, dict):
                product_id = clean_text(str(product.get("product_id") or ""))
                product_name = clean_text(str(product.get("name") or name))
                helper = product.get("product_identification_helper") or {}
                source_stated_part = None
                source_stated_model = None
                if isinstance(helper, dict):
                    source_stated_part = (
                        clean_text(str(helper.get("model_number") or ""))
                        or clean_text(str(helper.get("sku") or ""))
                        or clean_text(str(helper.get("serial_number") or ""))
                        or None
                    )
                    model_numbers = helper.get("model_numbers") or []
                    if isinstance(model_numbers, list) and model_numbers:
                        source_stated_model = clean_text(str(model_numbers[0])) or None
                    if not source_stated_model:
                        source_stated_model = clean_text(str(helper.get("model_number") or "")) or None
                inferred_part = None
                if not source_stated_part:
                    match = PART_NUMBER_PATTERN.search(product_name)
                    inferred_part = match.group(0) if match else None

                vendor = _path_value(next_path, {"vendor"})
                product_family = _path_value(next_path, {"product_family"})
                product_label = _path_value(next_path, {"product_name", "product_family"}) or product_name
                inferred_model = _infer_model(product_label, product_family)
                version_label = _path_value(next_path, {"product_version"}) or _version_from_name(product_name)

                if product_id:
                    index[product_id] = {
                        "product_id": product_id,
                        "name": product_name,
                        "vendor": vendor,
                        "product": product_label,
                        "product_family": product_family,
                        "model": source_stated_model or inferred_model,
                        "part_number": source_stated_part or inferred_part,
                        "source_stated_model": source_stated_model,
                        "source_stated_part": source_stated_part,
                        "version": version_label,
                        "relationship_type": "",
                    }
            walk(branch.get("branches"), next_path)

    walk(product_tree.get("branches"), [])

    # CSAF relationships bind firmware/version nodes to the controller or
    # application on which they are installed. Vulnerability product_status
    # commonly references the relationship product ID rather than either leaf.
    for relationship in product_tree.get("relationships") or []:
        if not isinstance(relationship, dict):
            continue
        full_product = relationship.get("full_product_name") or {}
        if not isinstance(full_product, dict):
            continue
        product_id = clean_text(str(full_product.get("product_id") or ""))
        if not product_id:
            continue
        source = index.get(clean_text(str(relationship.get("product_reference") or "")), {})
        target = index.get(
            clean_text(str(relationship.get("relates_to_product_reference") or "")),
            {},
        )
        full_name = clean_text(str(full_product.get("name") or ""))
        helper = full_product.get("product_identification_helper") or {}
        model_numbers = helper.get("model_numbers") or [] if isinstance(helper, dict) else []
        source_stated_part = (
            clean_text(str(model_numbers[0]))
            if isinstance(model_numbers, list) and model_numbers
            else source.get("source_stated_part") or target.get("source_stated_part")
        )
        source_stated_model = (
            source.get("source_stated_model")
            or target.get("source_stated_model")
            or (clean_text(str(model_numbers[0])) if isinstance(model_numbers, list) and model_numbers else None)
        )
        product = target.get("product") or source.get("product") or full_name
        product_family = target.get("product_family") or source.get("product_family")
        category = clean_text(str(relationship.get("category") or relationship.get("relationship_type") or ""))
        index[product_id] = {
            "product_id": product_id,
            "name": full_name or product,
            "vendor": target.get("vendor") or source.get("vendor"),
            "product": product,
            "product_family": product_family,
            "model": source_stated_model or target.get("model") or source.get("model"),
            "part_number": source_stated_part or source.get("part_number") or target.get("part_number"),
            "source_stated_model": source_stated_model,
            "source_stated_part": source_stated_part,
            "version": source.get("version") or _version_from_name(full_name),
            "relationship_type": category,
        }
    return index


def _path_value(path: list[tuple[str, str]], categories: set[str]) -> str | None:
    for category, name in reversed(path):
        if category in categories and name:
            return name
    return None


def _infer_model(product: str | None, product_family: str | None) -> str | None:
    if not product:
        return None
    cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", product).strip() or product
    if product_family and cleaned.upper().startswith(product_family.upper()):
        remainder = cleaned[len(product_family) :].strip(" -_")
        return remainder or None
    tokens = cleaned.split()
    if len(tokens) >= 2 and re.search(r"[A-Za-z]*\d", tokens[-1]):
        return tokens[-1]
    return None


def _version_from_name(name: str) -> str | None:
    cleaned = clean_text(name)
    if not cleaned:
        return None
    generic = re.fullmatch(
        r"vers:(?:generic|semver)/(.+)",
        cleaned,
        flags=re.IGNORECASE,
    )
    if generic:
        expression = generic.group(1)
        range_match = re.fullmatch(
            r">=?\s*(V?\d+(?:\.\d+)*)\s*\|\s*<\s*(V?\d+(?:\.\d+)*)",
            expression,
            flags=re.IGNORECASE,
        )
        if range_match:
            return f"since {range_match.group(1)} and prior to {range_match.group(2)}"
        if expression.startswith("<"):
            return f"prior to {expression.lstrip('<=').strip()}"
        return expression
    if re.fullmatch(r"vers:all/\*", cleaned, flags=re.IGNORECASE):
        return "all versions"
    # CSAF product-tree nodes often use compact constraints such as "<V5.30".
    compact = re.fullmatch(r"([<>]=?|=)?\s*(V?\d+(?:\.\d+)*)", cleaned, flags=re.IGNORECASE)
    if compact:
        op = compact.group(1) or ""
        version = compact.group(2)
        if op.startswith("<"):
            return f"prior to {version}"
        if op.startswith(">"):
            return f"{op}{version}"
        return version

    lowered = cleaned.lower()
    range_match = re.search(
        r"versions?\s+since\s+(V?\d+(?:\.\d+)*)\s+and\s+prior to\s+(V?\d+(?:\.\d+)*)",
        cleaned,
        flags=re.IGNORECASE,
    )
    if range_match:
        return f"since {range_match.group(1)} and prior to {range_match.group(2)}"
    for marker in ("versions ", "version ", "vers:"):
        if marker in lowered:
            return cleaned[lowered.index(marker) :].strip()
    if re.search(r"\bV?\d+(?:\.\d+)+\b", cleaned, flags=re.IGNORECASE):
        match = re.search(
            r"(?:all versions\s+)?(?:prior to|before|earlier than|>=?|<=?|<)\s*V?\d+(?:\.\d+)+",
            cleaned,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(0).strip()
        match = re.search(r"V?\d+(?:\.\d+)+", cleaned, flags=re.IGNORECASE)
        return match.group(0).strip() if match else None
    return None


def _parse_vulnerability(
    vulnerability: dict[str, Any],
    advisory_id: str,
    product_index: dict[str, dict[str, Any]],
    document_references: list[str],
) -> tuple[CveDetailRecord, frozenset[str]] | tuple[None, frozenset[str]]:
    cve_id = clean_text(str(vulnerability.get("cve") or "")).upper()
    if not cve_id:
        # Some CSAF entries use ids/title without explicit cve field.
        title = clean_text(str(vulnerability.get("title") or ""))
        match = CVE_PATTERN.search(title)
        cve_id = match.group(0).upper() if match else ""
    if not cve_id or not CVE_PATTERN.fullmatch(cve_id):
        return None, frozenset()

    # CRITICAL: bind only per-vulnerability CWE values, never advisory aggregates.
    cwe_ids = _extract_cwes(vulnerability)
    description = _extract_description(vulnerability)
    title = clean_text(str(vulnerability.get("title") or "")) or cve_id
    effects = _extract_effects(vulnerability, description)
    cvss_score, severity, prerequisites = _extract_cvss(vulnerability)

    membership_ids = _status_product_ids(vulnerability, ("known_affected", "first_affected", "last_affected"))
    negative_ids = _status_product_ids(vulnerability, ("known_not_affected",))
    affected_ids = membership_ids
    products = [dict(product_index[pid]) for pid in affected_ids if pid in product_index]
    generic_remediation_constraints: list[str] = []
    for remediation in vulnerability.get("remediations") or []:
        if not isinstance(remediation, dict):
            continue
        details = clean_text(str(remediation.get("details") or ""))
        match = re.search(r"update to\s+(V?\d+(?:\.\d+)*)", details, flags=re.IGNORECASE)
        if not match:
            continue
        constraint = f"prior to {match.group(1)}"
        product_ids = {
            clean_text(str(item))
            for item in remediation.get("product_ids") or []
            if item
        }
        if product_ids:
            for item in products:
                if item.get("product_id") in product_ids and not item.get("version"):
                    item["version"] = constraint
        else:
            generic_remediation_constraints.append(constraint)
    vendor = _common_or_first(products, "vendor")
    product = _common_or_first(products, "product")
    product_family = _common_or_first(products, "product_family")
    model = _common_or_first(products, "model")
    part_number = _common_or_first(products, "part_number")
    affected_versions = dedupe_preserve_order(
        [
            clean_text(str(item.get("version") or ""))
            for item in products
            if item.get("version")
        ]
    )
    affected_products = dedupe_preserve_order(
        [clean_text(str(item.get("name") or item.get("product") or "")) for item in products]
    )
    affected_product_constraints = [
        {
            "product": clean_text(str(item.get("name") or item.get("product") or "")),
            "version": clean_text(str(item.get("version") or "")),
            "part_number": clean_text(str(item.get("part_number") or "")),
        }
        for item in products
        if item.get("name") or item.get("product")
    ]
    # Fall back to product names only when no explicit version constraints were found.
    if not affected_versions:
        affected_versions = dedupe_preserve_order(
            [clean_text(str(item.get("name") or "")) for item in products if item.get("name")]
        )

    for constraint in generic_remediation_constraints:
        if constraint not in affected_versions:
            affected_versions.append(constraint)

    vuln_refs = []
    for item in vulnerability.get("references") or []:
        url = clean_text(str(item.get("url") or ""))
        if url:
            vuln_refs.append(url)

    product_evidence = []
    seen_positive: set[str] = set()
    for status_key in ("known_affected", "first_affected", "last_affected"):
        for pid in _status_product_ids(vulnerability, (status_key,)):
            if pid in seen_positive:
                continue
            item = product_index.get(pid)
            if not item:
                continue
            seen_positive.add(pid)
            product_evidence.append(
                evidence_from_csaf_product(
                    cve_id=cve_id,
                    advisory_id=advisory_id,
                    product=item,
                    polarity=POLARITY_POSITIVE,
                    strength=SOURCE_MEMBERSHIP,
                    relationship_type=str(item.get("relationship_type") or ""),
                    version_constraint=str(item.get("version") or ""),
                    status_key=status_key,
                ).to_dict()
            )
    for pid in negative_ids:
        item = product_index.get(pid)
        if not item:
            continue
        product_evidence.append(
            evidence_from_csaf_product(
                cve_id=cve_id,
                advisory_id=advisory_id,
                product=item,
                polarity=POLARITY_NEGATIVE,
                strength=NEGATIVE,
                relationship_type=str(item.get("relationship_type") or ""),
                version_constraint=str(item.get("version") or ""),
                status_key="known_not_affected",
            ).to_dict()
        )

    return CveDetailRecord(
        advisory_id=advisory_id,
        cve_id=cve_id,
        vendor=vendor,
        product=product,
        product_family=product_family,
        model=model,
        part_number=part_number,
        affected_versions=affected_versions,
        affected_products=affected_products,
        affected_product_constraints=affected_product_constraints,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        severity=severity,
        title=title,
        description=description,
        prerequisites=prerequisites,
        effects=effects,
        references=dedupe_preserve_order(vuln_refs + document_references),
        raw_product_ids=affected_ids,
        product_evidence=product_evidence,
    ), frozenset(membership_ids)


def _extract_cwes(vulnerability: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    cwe = vulnerability.get("cwe")
    if isinstance(cwe, dict):
        cwe_id = clean_text(str(cwe.get("id") or "")).upper()
        if CWE_PATTERN.fullmatch(cwe_id):
            cwes.append(cwe_id)
    elif isinstance(cwe, list):
        for item in cwe:
            if isinstance(item, dict):
                cwe_id = clean_text(str(item.get("id") or "")).upper()
                if CWE_PATTERN.fullmatch(cwe_id):
                    cwes.append(cwe_id)
            else:
                cwes.extend(sorted(CWE_PATTERN.findall(str(item).upper())))
    # Do not scrape CWEs from advisory-level notes or shared text.
    return dedupe_preserve_order(cwes)


def _extract_description(vulnerability: dict[str, Any]) -> str | None:
    notes = vulnerability.get("notes") or []
    preferred_categories = {"description", "summary", "details"}
    texts: list[str] = []
    for note in notes:
        if not isinstance(note, dict):
            continue
        category = clean_text(str(note.get("category") or "")).lower()
        text = clean_text(str(note.get("text") or ""))
        if text and category in preferred_categories:
            texts.append(text)
    if texts:
        return clean_text(" ".join(texts))
    title = clean_text(str(vulnerability.get("title") or ""))
    return title or None


def _extract_effects(vulnerability: dict[str, Any], description: str | None) -> list[str]:
    effects: list[str] = []
    for threat in vulnerability.get("threats") or []:
        if not isinstance(threat, dict):
            continue
        details = clean_text(str(threat.get("details") or ""))
        if details:
            effects.append(details)
    # Do not invent structured effect labels from free text.
    return dedupe_preserve_order(effects)


def _extract_cvss(vulnerability: dict[str, Any]) -> tuple[float | None, str | None, CvePrerequisites]:
    prerequisites = CvePrerequisites()
    best_score: float | None = None
    severity: str | None = None
    best_metrics: dict[str, Any] | None = None

    for score in vulnerability.get("scores") or []:
        if not isinstance(score, dict):
            continue
        metrics = score.get("cvss_v3") or score.get("cvss_v2") or score.get("cvss_v4")
        if not isinstance(metrics, dict):
            continue
        raw_score = metrics.get("baseScore")
        try:
            value = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            value = None
        if value is None:
            continue
        if best_score is None or value > best_score:
            best_score = value
            severity = clean_text(str(metrics.get("baseSeverity") or "")) or None
            best_metrics = metrics

    if best_metrics:
        attack_vector = clean_text(str(best_metrics.get("attackVector") or "")).upper() or None
        privileges = clean_text(str(best_metrics.get("privilegesRequired") or "")).upper() or None
        user_interaction = clean_text(str(best_metrics.get("userInteraction") or "")).upper() or None

        if attack_vector == "NETWORK":
            prerequisites.network_access = "remote"
            prerequisites.physical_access = False
        elif attack_vector == "ADJACENT_NETWORK":
            prerequisites.network_access = "adjacent"
            prerequisites.physical_access = False
        elif attack_vector == "LOCAL":
            prerequisites.network_access = "local"
            prerequisites.physical_access = False
        elif attack_vector == "PHYSICAL":
            prerequisites.network_access = "physical"
            prerequisites.physical_access = True

        if privileges:
            prerequisites.privileges_required = privileges.lower()
            prerequisites.authentication_required = privileges != "NONE"
        if user_interaction:
            prerequisites.user_interaction = user_interaction.lower()

    return best_score, severity, prerequisites


def _status_product_ids(vulnerability: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    status = vulnerability.get("product_status") or {}
    ids: list[str] = []
    for key in keys:
        values = status.get(key) or []
        if isinstance(values, list):
            ids.extend(clean_text(str(item)) for item in values if item)
    return dedupe_preserve_order(ids)


def _affected_product_ids(vulnerability: dict[str, Any]) -> list[str]:
    """Positive membership IDs only. `fixed` is remediation, never affected evidence."""
    return _status_product_ids(vulnerability, ("known_affected", "first_affected", "last_affected"))


def _annotate_shared_product_status_vectors(
    records: list[CveDetailRecord],
    status_vectors: list[frozenset[str]],
) -> None:
    counts: dict[frozenset[str], int] = {}
    for vector in status_vectors:
        if vector:
            counts[vector] = counts.get(vector, 0) + 1
    for record, vector in zip(records, status_vectors):
        if not vector or counts.get(vector, 0) <= 1:
            continue
        for item in record.product_evidence:
            notes = list(item.get("specificity_notes") or [])
            if NOTE_VECTOR_SHARED not in notes:
                notes.append(NOTE_VECTOR_SHARED)
            item["specificity_notes"] = notes


def _common_or_first(products: list[dict[str, Any]], key: str) -> str | None:
    values = dedupe_preserve_order([clean_text(str(item.get(key) or "")) for item in products if item.get(key)])
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    # Prefer shortest shared label when products diverge.
    return values[0]
