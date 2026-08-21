from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from rag.ingestion.nvd.downloader import NvdCveDownloader
from rag.ingestion.nvd.parser import NvdParseError, parse_nvd_cve_file
from rag.ingestion.nvd.store import NvdCveStore, default_nvd_store_dir


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download or import NVD CVE JSON into a local exact-lookup store (offline at runtime)",
    )
    parser.add_argument(
        "--store-dir",
        type=Path,
        default=None,
        help="Local NVD CVE store (default: <root>/data/nvd_cve or RAG_NVD_CVE_DIR)",
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        help="CVE ID to download from NVD (repeatable). Not used during scenario runtime.",
    )
    parser.add_argument(
        "--from-file",
        action="append",
        default=[],
        type=Path,
        help="Import an already-downloaded NVD JSON file (repeatable)",
    )
    parser.add_argument("--refresh", action="store_true", help="Re-download even if cached")
    parser.add_argument("--dry-run", action="store_true", help="Parse without writing the store")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    logger = logging.getLogger("rag.ingest_nvd_cve")
    store = NvdCveStore(args.store_dir or default_nvd_store_dir())
    logger.info("NVD CVE store: %s", store.store_dir)

    records = []
    failures = 0

    if args.from_file:
        for path in args.from_file:
            record = parse_nvd_cve_file(path)
            if record is None:
                logger.error("Failed to parse %s", path)
                failures += 1
                continue
            records.append(record)
            logger.info("Parsed %s from %s", record.cve_id, path)

    if args.cve:
        downloader = NvdCveDownloader(cache_dir=store.store_dir)
        for cve_id in args.cve:
            result = downloader.download(cve_id, refresh=args.refresh)
            logger.info("%s: %s (%s)", result.cve_id, result.status, result.message)
            if result.status == "unavailable" or result.path is None:
                failures += 1
                continue
            record = parse_nvd_cve_file(result.path)
            if record is None:
                logger.error("Downloaded %s but failed to parse", result.cve_id)
                failures += 1
                continue
            records.append(record)

    if not args.from_file and not args.cve:
        logger.error("Provide --cve and/or --from-file.")
        return 2

    if args.dry_run:
        for record in records:
            print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        return 0 if records and not failures else 1

    written = 0
    for record in records:
        try:
            path = store.write(record, refresh=args.refresh)
        except (OSError, NvdParseError) as exc:
            logger.error("Failed to write %s: %s", record.cve_id, exc)
            failures += 1
            continue
        written += 1
        logger.info("Stored %s at %s", record.cve_id, path)

    logger.info("Wrote %d NVD CVE record(s); failures=%d", written, failures)
    return 0 if written and not failures else 1


if __name__ == "__main__":
    sys.exit(main())
