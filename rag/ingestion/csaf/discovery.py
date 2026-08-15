from __future__ import annotations

import csv
import re
from pathlib import Path

ADVISORY_ID_PATTERN = re.compile(r"\b(?:ICSA|ICSMA|ICSALERT)-\d{2}-\d{3}-\d{2}\b", re.IGNORECASE)


def discover_advisory_ids_from_master_csv(
    csv_path: str | Path,
    vendor: str | None = None,
    product: str | None = None,
    year: int | None = None,
    limit: int | None = None,
) -> list[str]:
    """Derive unique CISA advisory IDs from the master CSV with optional filters."""

    path = Path(csv_path)
    vendor_filter = vendor.lower().strip() if vendor else None
    product_filter = product.lower().strip() if product else None
    ids: list[str] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if year is not None:
                row_year = str(row.get("Year") or "").strip()
                if row_year and row_year != str(year):
                    continue
            if vendor_filter:
                haystack = " ".join(
                    [
                        str(row.get("Vendor") or ""),
                        str(row.get("Company_Headquarters") or ""),
                        str(row.get("ICS-CERT_Advisory_Title") or ""),
                    ]
                ).lower()
                if vendor_filter not in haystack:
                    continue
            if product_filter:
                haystack = " ".join(
                    [
                        str(row.get("Product") or ""),
                        str(row.get("Products_Affected") or ""),
                        str(row.get("ICS-CERT_Advisory_Title") or ""),
                    ]
                ).lower()
                if product_filter not in haystack:
                    continue

            candidates = [
                str(row.get("ICS-CERT_Number") or ""),
                str(row.get("icsad_ID") or ""),
                str(row.get("ICS-CERT_Advisory_Title") or ""),
            ]
            advisory_id = None
            for value in candidates:
                match = ADVISORY_ID_PATTERN.search(value)
                if match:
                    advisory_id = match.group(0).upper()
                    break
            if not advisory_id or advisory_id in seen:
                continue
            seen.add(advisory_id)
            ids.append(advisory_id)
            if limit is not None and len(ids) >= limit:
                break
    return ids
