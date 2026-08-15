from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rag.cli import build_retriever
from rag.ingestion.csaf.discovery import discover_advisory_ids_from_master_csv
from rag.ingestion.csaf.documents import cve_detail_to_source_document
from rag.ingestion.csaf.downloader import CsafDownloader
from rag.ingestion.csaf.parser import CsafParseError, parse_csaf_file


def default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download and ingest CISA ICS CSAF advisories as per-CVE knowledge-base documents",
    )
    parser.add_argument("--root", type=Path, default=default_root(), help="Project root")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Local CSAF cache directory (default: <root>/data/cisa_csaf)",
    )
    parser.add_argument(
        "--advisory",
        action="append",
        default=[],
        help="Advisory ID to download (repeatable), e.g. ICSA-24-326-03",
    )
    parser.add_argument(
        "--from-master-csv",
        action="store_true",
        help="Discover advisory IDs from CISA_ICS_ADV_Master.csv",
    )
    parser.add_argument("--vendor", type=str, default=None, help="Filter master CSV by vendor text")
    parser.add_argument("--product", type=str, default=None, help="Filter master CSV by product text")
    parser.add_argument("--year", type=int, default=None, help="Filter master CSV by year")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of advisories from master CSV")
    parser.add_argument("--refresh", action="store_true", help="Re-download even if cached")
    parser.add_argument("--dry-run", action="store_true", help="Resolve advisory IDs and parse cache without indexing")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--reindex", action="store_true", help="Rebuild the Chroma index after download")
    parser.add_argument("--deterministic", action="store_true", help="Use deterministic embeddings when reindexing")
    return parser.parse_args(argv)


def resolve_advisory_ids(args: argparse.Namespace) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for advisory_id in args.advisory:
        normalized = advisory_id.strip().upper()
        if normalized and normalized not in seen:
            seen.add(normalized)
            ids.append(normalized)

    if args.from_master_csv:
        csv_path = args.root / "CISA_ICS_ADV_Master.csv"
        discovered = discover_advisory_ids_from_master_csv(
            csv_path,
            vendor=args.vendor,
            product=args.product,
            year=args.year,
            limit=args.limit,
        )
        for advisory_id in discovered:
            if advisory_id not in seen:
                seen.add(advisory_id)
                ids.append(advisory_id)
    return ids


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    logger = logging.getLogger("rag.ingest_cisa_csaf")

    cache_dir = args.cache_dir or (args.root / "data" / "cisa_csaf")
    cache_dir.mkdir(parents=True, exist_ok=True)

    advisory_ids = resolve_advisory_ids(args)
    if not advisory_ids:
        logger.error("No advisory IDs provided. Use --advisory and/or --from-master-csv.")
        return 2

    logger.info("Resolved %d advisory ID(s)", len(advisory_ids))
    downloader = CsafDownloader(cache_dir=cache_dir)
    results = downloader.download_many(advisory_ids, refresh=args.refresh)

    downloaded = [item for item in results if item.status in {"downloaded", "cached"} and item.path]
    unavailable = [item for item in results if item.status == "unavailable"]

    for item in results:
        logger.info("%s: %s (%s)", item.advisory_id, item.status, item.message)

    parsed_count = 0
    for item in downloaded:
        try:
            records = parse_csaf_file(item.path)  # type: ignore[arg-type]
        except CsafParseError as exc:
            logger.warning("Failed to parse %s: %s", item.advisory_id, exc)
            continue
        parsed_count += len(records)
        if args.verbose or args.dry_run:
            for record in records:
                document = cve_detail_to_source_document(record)
                logger.info(
                    "Parsed %s / %s (CWE=%s, product=%s)",
                    record.advisory_id,
                    record.cve_id,
                    ",".join(record.cwe_ids) or "-",
                    record.product or "-",
                )
                if args.dry_run:
                    print(document.text[:500])
                    print("---")

    logger.info(
        "Download summary: available=%d unavailable=%d parsed_cves=%d cache_dir=%s",
        len(downloaded),
        len(unavailable),
        parsed_count,
        cache_dir,
    )

    if args.dry_run:
        return 0 if downloaded else 1

    if args.reindex:
        logger.info("Reindexing knowledge base with CSAF enrichment from %s", cache_dir)
        build_retriever(args.root, deterministic=args.deterministic, reindex=True)
        logger.info("Reindex complete")

    return 0 if downloaded else 1


if __name__ == "__main__":
    sys.exit(main())
