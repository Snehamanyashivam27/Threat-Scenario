from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from rag.ingestion.cisa_advisory.downloader import CisaAdvisoryDownloader
from rag.ingestion.cisa_advisory.parser import parse_cisa_advisory_html
from rag.ingestion.cisa_advisory.store import AdvisoryDetailStore, default_advisory_store_dir
from rag.ingestion.coverage import (
    CoverageSummary,
    CveCoverage,
    assess_corpus_coverage,
    discover_csv_cves,
    summarize_coverage,
)
from rag.ingestion.csaf.downloader import CsafDownloader
from rag.ingestion.nvd.downloader import NvdCveDownloader
from rag.ingestion.nvd.parser import parse_nvd_cve_file
from rag.ingestion.nvd.store import NvdCveStore, default_nvd_store_dir


def default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Offline synchronization of canonical CVE detail and advisory remediation stores. "
            "Never invoked by scenario runtime."
        )
    )
    parser.add_argument("--root", type=Path, default=default_root())
    parser.add_argument("--csv", type=Path, default=None)
    parser.add_argument("--csaf-dir", type=Path, default=None)
    parser.add_argument("--nvd-dir", type=Path, default=None)
    parser.add_argument("--advisory-dir", type=Path, default=None)
    parser.add_argument("--cve", action="append", default=[], help="Limit to one or more CVE IDs")
    parser.add_argument("--limit", type=int, default=None, help="Max acquisitions per source phase")
    parser.add_argument("--dry-run", action="store_true", help="Report gaps without writing or fetching")
    parser.add_argument(
        "--missing-only",
        action="store_true",
        help="Acquire only missing files (default unless --refresh)",
    )
    parser.add_argument("--no-network", action="store_true", help="Do not fetch CSAF, NVD, or CISA HTML")
    parser.add_argument("--refresh", action="store_true", help="Overwrite existing local files")
    parser.add_argument("--skip-csaf", action="store_true")
    parser.add_argument("--skip-nvd", action="store_true")
    parser.add_argument("--skip-advisory-html", action="store_true")
    parser.add_argument("--from-nvd-file", action="append", default=[], type=Path)
    parser.add_argument("--from-advisory-file", action="append", default=[], type=Path)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    logger = logging.getLogger("rag.sync_cve_coverage")
    root = args.root
    csv_path = args.csv or (root / "CISA_ICS_ADV_Master.csv")
    csaf_dir = args.csaf_dir or (root / "data" / "cisa_csaf")
    nvd_dir = args.nvd_dir or default_nvd_store_dir()
    advisory_dir = args.advisory_dir or default_advisory_store_dir()
    wanted = [item.strip().upper() for item in args.cve if item.strip()] or None
    refresh = bool(args.refresh) and not args.missing_only
    newly = 0
    failed = 0

    newly, failed = _import_local_files(args, nvd_dir, advisory_dir, logger, newly, failed)

    coverage = _assess(csv_path, csaf_dir, nvd_dir, advisory_dir, wanted)
    csv_map = discover_csv_cves(csv_path)
    csv_advisories = {adv for advisories in csv_map.values() for adv in advisories}

    if args.dry_run or args.no_network:
        summary = _summary_for(coverage, newly, failed, csv_advisories, wanted, csv_map, csaf_dir, nvd_dir, refresh)
        _print_summary(summary)
        if args.dry_run:
            seed = list(dict.fromkeys((wanted or list(coverage.keys())) + _cves_to_acquire(coverage, csv_map, wanted)))
            advisories = _csaf_targets(seed, coverage, csv_map, csaf_dir, refresh)
            if args.limit is not None:
                advisories = advisories[: args.limit]
            print(
                json.dumps(
                    {
                        "complete_evidence": summary.complete_evidence,
                        "missing_effect_description": summary.missing_effect_description,
                        "missing_identity": summary.missing_identity,
                        "missing_applicability": summary.missing_applicability,
                        "missing_remediation": summary.missing_remediation,
                        "non_affected": summary.non_affected,
                        "csaf_advisories_to_acquire": len(advisories),
                    },
                    indent=2,
                )
            )
        return 0 if not failed else 1

    acquire_cves = _cves_to_acquire(coverage, csv_map, wanted)
    csaf_seed = list(dict.fromkeys((wanted or list(coverage.keys())) + acquire_cves))
    if args.limit is not None:
        acquire_cves = acquire_cves[: args.limit]

    if not args.skip_csaf:
        advisories = _csaf_targets(csaf_seed, coverage, csv_map, csaf_dir, refresh)
        if args.limit is not None:
            advisories = advisories[: args.limit]
        downloader = CsafDownloader(cache_dir=csaf_dir)
        for advisory_id in advisories:
            result = downloader.download(advisory_id, refresh=refresh)
            logger.info("CSAF %s: %s (%s)", advisory_id, result.status, result.message)
            if result.status == "downloaded":
                newly += 1
            elif result.status == "unavailable":
                failed += 1

    if not args.skip_nvd:
        coverage = _assess(csv_path, csaf_dir, nvd_dir, advisory_dir, wanted or acquire_cves)
        remaining = [
            cve_id
            for cve_id in acquire_cves
            if not coverage.get(cve_id) or not coverage[cve_id].effect_description
        ]
        nvd_interval = 0.6 if os.environ.get("NVD_API_KEY", "").strip() else 6.0
        nvd = NvdCveDownloader(cache_dir=nvd_dir, min_interval_seconds=nvd_interval)
        store = NvdCveStore(nvd_dir)
        for cve_id in remaining:
            result = nvd.download(cve_id, refresh=refresh)
            logger.info("NVD %s: %s (%s)", cve_id, result.status, result.message)
            if result.status == "unavailable" or result.path is None:
                failed += 1
                continue
            record = parse_nvd_cve_file(result.path)
            if record is None:
                failed += 1
                continue
            store.write(record, refresh=refresh)
            if result.status == "downloaded":
                newly += 1

    if not args.skip_advisory_html:
        coverage = _assess(csv_path, csaf_dir, nvd_dir, advisory_dir, wanted)
        missing_defense = _html_targets(coverage, advisory_dir, refresh)
        if args.limit is not None:
            missing_defense = missing_defense[: args.limit]
        html_downloader = CisaAdvisoryDownloader(cache_dir=advisory_dir)
        for advisory_id in missing_defense:
            result = html_downloader.download(advisory_id, refresh=refresh)
            logger.info("Advisory %s: %s (%s)", advisory_id, result.status, result.message)
            if result.status == "downloaded":
                newly += 1
            elif result.status == "unavailable":
                failed += 1

    coverage = _assess(csv_path, csaf_dir, nvd_dir, advisory_dir, wanted)
    summary = _summary_for(coverage, newly, failed, csv_advisories, wanted, csv_map, csaf_dir, nvd_dir, refresh)
    _print_summary(summary)
    return 0 if failed == 0 else 1


def _import_local_files(
    args: argparse.Namespace,
    nvd_dir: Path,
    advisory_dir: Path,
    logger: logging.Logger,
    newly: int,
    failed: int,
) -> tuple[int, int]:
    refresh = bool(args.refresh) and not args.missing_only
    if args.from_nvd_file:
        store = NvdCveStore(nvd_dir)
        for path in args.from_nvd_file:
            record = parse_nvd_cve_file(path)
            if record is None:
                logger.error("Failed to parse NVD file %s", path)
                failed += 1
                continue
            if not args.dry_run:
                store.write(record, refresh=refresh)
            newly += 1
    if args.from_advisory_file:
        store = AdvisoryDetailStore(advisory_dir)
        for path in args.from_advisory_file:
            html = path.read_text(encoding="utf-8")
            record = parse_cisa_advisory_html(html, source_url=str(path))
            if not record.advisory_id:
                logger.error("Advisory HTML missing advisory ID: %s", path)
                failed += 1
                continue
            if not args.dry_run:
                store.write(record, refresh=refresh)
            newly += 1
    return newly, failed


def _assess(
    csv_path: Path,
    csaf_dir: Path,
    nvd_dir: Path,
    advisory_dir: Path,
    wanted: list[str] | None,
) -> dict[str, CveCoverage]:
    return assess_corpus_coverage(
        csv_path=csv_path,
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
        advisory_dir=advisory_dir,
        cve_ids=wanted,
    )


def _cves_to_acquire(
    coverage: dict[str, CveCoverage],
    csv_map: dict[str, set[str]],
    wanted: list[str] | None,
) -> list[str]:
    missing = [row.cve_id for row in coverage.values() if not row.effect_description]
    if wanted:
        wanted_set = set(wanted)
        ordered = [item for item in wanted if item in wanted_set]
        extra = [item for item in ordered if item not in coverage or not coverage[item].effect_description]
        for item in missing:
            if item in wanted_set and item not in extra:
                extra.append(item)
        return extra
    return missing or sorted(csv_map)


def _csaf_targets(
    acquire_cves: list[str],
    coverage: dict[str, CveCoverage],
    csv_map: dict[str, set[str]],
    csaf_dir: Path,
    refresh: bool,
) -> list[str]:
    advisories: list[str] = []
    seen: set[str] = set()
    seed = list(acquire_cves)
    for cve_id, row in coverage.items():
        if not row.csaf_detail and cve_id not in seed:
            seed.append(cve_id)
    for cve_id in seed:
        row = coverage.get(cve_id)
        ids = list(row.advisory_ids) if row else []
        ids.extend(sorted(csv_map.get(cve_id, set())))
        for advisory_id in ids:
            if advisory_id in seen:
                continue
            seen.add(advisory_id)
            path = Path(csaf_dir) / f"{advisory_id}.json"
            if path.exists() and not refresh:
                continue
            advisories.append(advisory_id)
    return advisories


def _html_targets(
    coverage: dict[str, CveCoverage],
    advisory_dir: Path,
    refresh: bool,
) -> list[str]:
    advisories: list[str] = []
    seen: set[str] = set()
    for row in coverage.values():
        if row.csaf_remediation:
            continue
        for advisory_id in row.advisory_ids:
            if advisory_id in seen:
                continue
            seen.add(advisory_id)
            path = Path(advisory_dir) / f"{advisory_id}.json"
            if path.exists() and not refresh and row.advisory_remediation:
                continue
            if path.exists() and not refresh:
                continue
            advisories.append(advisory_id)
    return sorted(advisories)


def _summary_for(
    coverage: dict[str, CveCoverage],
    newly: int,
    failed: int,
    csv_advisories: set[str],
    wanted: list[str] | None,
    csv_map: dict[str, set[str]],
    csaf_dir: Path,
    nvd_dir: Path,
    refresh: bool,
) -> CoverageSummary:
    scoped = csv_advisories if wanted is None else {adv for row in coverage.values() for adv in row.advisory_ids}
    csv_cve_ids = set(wanted) if wanted else set(csv_map)
    return summarize_coverage(
        coverage,
        newly_acquired=newly,
        failed_acquisitions=failed,
        csv_advisories=scoped,
        csv_cve_ids=csv_cve_ids,
        csaf_dir=csaf_dir,
        nvd_dir=nvd_dir,
        refresh=refresh,
    )


def _print_summary(summary: CoverageSummary) -> None:
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
