"""Command line interface for the carved-file triage toolkit."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from . import __version__
from .organize import apply_plan, build_plan, summarise
from .scan import read_index, scan_tree, write_index
from .formats import validate


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.source)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    out = Path(args.output)
    print(f"Scanning {root}...", file=sys.stderr)
    count = write_index(scan_tree(root, want_hash=not args.no_hash), out)
    print(f"Wrote {count} records to {out}", file=sys.stderr)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    index = Path(args.index)
    if not index.is_file():
        print(f"error: {index} not found (run 'scan' first)", file=sys.stderr)
        return 2
    records = list(read_index(index))
    plan = build_plan(records)
    print(summarise(plan))

    if args.csv:
        with Path(args.csv).open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["path", "kind", "verdict", "size", "good_bytes", "detail",
                 "date", "title", "author", "camera", "sha256"]
            )
            for record in records:
                writer.writerow([
                    record.path, record.kind, record.verdict, record.size,
                    record.good_bytes, record.detail,
                    record.meta.get("date", ""), record.meta.get("title", ""),
                    record.meta.get("author", ""), record.meta.get("camera", ""),
                    record.sha256 or "",
                ])
        print(f"\nPer-file detail written to {args.csv}")
    return 0


def _cmd_organize(args: argparse.Namespace) -> int:
    index = Path(args.index)
    if not index.is_file():
        print(f"error: {index} not found (run 'scan' first)", file=sys.stderr)
        return 2
    records = list(read_index(index))
    plan = build_plan(records, keep_duplicates=args.keep_duplicates)
    print(summarise(plan))

    try:
        applied, errors = apply_plan(
            plan,
            source_root=Path(args.source),
            dest_root=Path(args.dest),
            move=args.move,
            dry_run=not args.execute,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    verb = "would place" if not args.execute else ("moved" if args.move else "copied")
    print(f"\n{verb} {applied} files into {args.dest}")
    if errors:
        print(f"{len(errors)} failures:", file=sys.stderr)
        for src, message in errors[:20]:
            print(f"  {src}: {message}", file=sys.stderr)
    if not args.execute:
        print("\nThis was a dry run. Re-run with --execute to write files.")
    return 1 if errors else 0


def _cmd_check(args: argparse.Namespace) -> int:
    worst = 0
    for name in args.paths:
        path = Path(name)
        if not path.is_file():
            print(f"{name}: not a file", file=sys.stderr)
            worst = 2
            continue
        result = validate(path)
        extra = f" - {result.detail}" if result.detail else ""
        print(f"{name}: {result.kind} / {result.verdict}{extra}")
        if result.verdict != "ok":
            worst = max(worst, 1)
    return worst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtriage",
        description="Triage files recovered by R-Studio, photorec or foremost.",
    )
    parser.add_argument("--version", action="version", version=f"rtriage {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="validate and index a recovery output directory"
    )
    scan_parser.add_argument("source", help="directory of recovered files")
    scan_parser.add_argument(
        "-o", "--output", default="rtriage-index.jsonl", help="index file to write"
    )
    scan_parser.add_argument(
        "--no-hash", action="store_true", help="skip SHA-256 (faster, disables dedupe)"
    )
    scan_parser.set_defaults(func=_cmd_scan)

    report_parser = subparsers.add_parser("report", help="summarise an index")
    report_parser.add_argument("index", nargs="?", default="rtriage-index.jsonl")
    report_parser.add_argument("--csv", help="also write per-file detail as CSV")
    report_parser.set_defaults(func=_cmd_report)

    org_parser = subparsers.add_parser(
        "organize", help="file recovered data into a sorted tree"
    )
    org_parser.add_argument("index", nargs="?", default="rtriage-index.jsonl")
    org_parser.add_argument("--source", required=True, help="directory the index describes")
    org_parser.add_argument("--dest", required=True, help="output directory (must be outside source)")
    org_parser.add_argument(
        "--move", action="store_true", help="move instead of copy (halves disk need)"
    )
    org_parser.add_argument(
        "--keep-duplicates", action="store_true", help="retain redundant copies under duplicates/"
    )
    org_parser.add_argument(
        "--execute", action="store_true", help="actually write; omit for a dry run"
    )
    org_parser.set_defaults(func=_cmd_organize)

    check_parser = subparsers.add_parser("check", help="validate individual files")
    check_parser.add_argument("paths", nargs="+")
    check_parser.set_defaults(func=_cmd_check)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
