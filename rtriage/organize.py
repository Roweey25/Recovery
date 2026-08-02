"""Turn a scan index into a navigable directory tree.

Two jobs. First, collapse duplicates: carving the same disk region twice, or
carving both a file and its thumbnail cache copy, produces the same bytes many
times over. Second, file what is left by how usable it is, because "which of
these 40,000 files can I actually open" is the only question that matters when
you are staring at a carver's output directory.
"""

from __future__ import annotations

import re
import shutil
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .formats import VERDICT_RANK
from .scan import Record

# The carver's extension comes from the signature it matched, which is usually
# right but not always. Content sniffing wins.
_EXTENSIONS = {
    "jpeg": ".jpg",
    "png": ".png",
    "gif": ".gif",
    "tiff": ".tif",
    "bmp": ".bmp",
    "webp": ".webp",
    "heic": ".heic",
    "pdf": ".pdf",
    "docx": ".docx",
    "xlsx": ".xlsx",
    "pptx": ".pptx",
    "odf": ".odf",
    "jar": ".jar",
    "zip": ".zip",
    "mp4": ".mp4",
    "mov": ".mov",
    "isobmff": ".mp4",
    "wav": ".wav",
    "avi": ".avi",
    "riff": ".riff",
    "mp3": ".mp3",
    "ogg": ".ogg",
    "flac": ".flac",
    "sqlite": ".sqlite",
    "ole2": ".ole",
    "gzip": ".gz",
    "7z": ".7z",
    "rar": ".rar",
    "postscript": ".ps",
}

_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
MAX_STEM = 80


def safe_stem(raw: str, fallback: str = "file") -> str:
    """Make a filename component safe on Windows, macOS and Linux alike."""
    cleaned = _UNSAFE.sub("_", raw).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > MAX_STEM:
        cleaned = cleaned[:MAX_STEM].rstrip()
    if not cleaned or cleaned.upper() in _RESERVED:
        return fallback
    return cleaned


@dataclass
class Move:
    """One planned relocation."""

    src: str
    dest: str
    reason: str


@dataclass
class Plan:
    moves: List[Move]
    duplicates: Dict[str, List[str]]  # kept path -> paths judged redundant
    counts: Dict[str, int]


def _quality(record: Record) -> tuple:
    """Sort key picking the best copy among identical-hash files.

    Better verdict first, then more recoverable content, then the shallowest
    and shortest path as a stable tie-break.
    """
    return (
        VERDICT_RANK.get(record.verdict, 99),
        -record.good_bytes,
        record.path.count("/") + record.path.count("\\"),
        len(record.path),
    )


def dedupe(records: Iterable[Record]) -> tuple:
    """Split records into keepers and redundant copies, grouped by content."""
    by_hash: Dict[str, List[Record]] = defaultdict(list)
    keepers: List[Record] = []
    for record in records:
        # Unhashed files (empty, or --no-hash) cannot be compared by content.
        if record.sha256:
            by_hash[record.sha256].append(record)
        else:
            keepers.append(record)

    duplicates: Dict[str, List[str]] = {}
    for group in by_hash.values():
        group.sort(key=_quality)
        best = group[0]
        keepers.append(best)
        if len(group) > 1:
            duplicates[best.path] = [r.path for r in group[1:]]
    return keepers, duplicates


def _target_name(record: Record, ext: str) -> str:
    """Prefer a name carrying real information over the carver's counter."""
    title = record.meta.get("title")
    date = record.meta.get("date")
    original = Path(record.path).stem

    if title:
        stem = safe_stem(title, fallback=original)
    else:
        stem = safe_stem(original, fallback="file")
    if date and not stem.startswith(date):
        stem = f"{date}_{stem}"
    # A short hash slice keeps names unique without a global counter, so the
    # same input always plans the same output.
    if record.sha256:
        stem = f"{stem}_{record.sha256[:8]}"
    return stem + ext


def build_plan(records: Iterable[Record], keep_duplicates: bool = False) -> Plan:
    """Decide where every kept file should land."""
    keepers, duplicates = dedupe(records)
    counts: Dict[str, int] = defaultdict(int)
    moves: List[Move] = []
    used: set = set()

    for record in keepers:
        ext = _EXTENSIONS.get(record.kind, Path(record.path).suffix or ".bin")
        bucket = record.verdict
        date = record.meta.get("date")
        parts = [bucket, record.kind]
        if date:
            parts.append(date[:7])  # group by month; day-level is too granular
        name = _target_name(record, ext)
        dest = "/".join(parts + [name])
        # Distinct files can still collide once names are sanitised.
        suffix = 1
        base = dest
        while dest in used:
            suffix += 1
            stem, _, extension = base.rpartition(".")
            dest = f"{stem}~{suffix}.{extension}"
        used.add(dest)
        moves.append(Move(src=record.path, dest=dest, reason=record.verdict))
        counts[record.verdict] += 1
        counts[f"kind:{record.kind}"] += 1

    if keep_duplicates:
        for kept, dupes in duplicates.items():
            for dupe in dupes:
                name = Path(dupe).name
                dest = f"duplicates/{Path(kept).stem}/{name}"
                moves.append(Move(src=dupe, dest=dest, reason="duplicate"))

    counts["duplicate_groups"] = len(duplicates)
    counts["duplicate_files"] = sum(len(v) for v in duplicates.values())
    return Plan(moves=moves, duplicates=duplicates, counts=dict(counts))


def apply_plan(
    plan: Plan,
    source_root: Path,
    dest_root: Path,
    move: bool = False,
    dry_run: bool = True,
) -> tuple:
    """Execute a plan. Returns (applied, [(src, error), ...])."""
    source_root = source_root.resolve()
    dest_root = dest_root.resolve()
    # Writing into the tree we are reading would corrupt the scan mid-run, and
    # on a recovery job the source is often the only copy of the evidence.
    if dest_root == source_root or source_root in dest_root.parents:
        raise ValueError(
            f"destination {dest_root} is inside source {source_root}; "
            "choose an output directory on a different path"
        )

    applied = 0
    errors: List[tuple] = []
    for entry in plan.moves:
        src = source_root / entry.src
        dest = dest_root / entry.dest
        if dry_run:
            applied += 1
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if move:
                shutil.move(str(src), str(dest))
            else:
                shutil.copy2(str(src), str(dest))
            applied += 1
        except (OSError, shutil.Error) as exc:
            errors.append((entry.src, str(exc)))
    return applied, errors


def summarise(plan: Plan, records: Optional[List[Record]] = None) -> str:
    """Human-readable rundown of what the plan does."""
    lines = ["", "Triage summary", "=" * 40]
    order = ["ok", "truncated", "corrupt", "unknown", "empty"]
    total = sum(plan.counts.get(v, 0) for v in order)
    for verdict in order:
        count = plan.counts.get(verdict, 0)
        if count:
            pct = 100.0 * count / total if total else 0.0
            lines.append(f"  {verdict:<10} {count:>7}  ({pct:4.1f}%)")
    lines.append(f"  {'TOTAL':<10} {total:>7}")

    kinds = sorted(
        ((k[5:], v) for k, v in plan.counts.items() if k.startswith("kind:")),
        key=lambda kv: -kv[1],
    )
    if kinds:
        lines += ["", "By type", "-" * 40]
        for kind, count in kinds[:15]:
            lines.append(f"  {kind:<12} {count:>7}")

    dup_files = plan.counts.get("duplicate_files", 0)
    if dup_files:
        lines += [
            "",
            f"Duplicates: {dup_files} redundant copies across "
            f"{plan.counts.get('duplicate_groups', 0)} groups",
        ]
    return "\n".join(lines)
