"""Walk a carver's output directory and build an index of what is in it.

Scanning is kept separate from organising on purpose: hashing and validating a
few hundred thousand carved files takes a while, and you will want to try more
than one filing scheme without paying that cost again. The index is JSON Lines,
so it streams and stays greppable.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

from . import formats, meta as meta_mod

CHUNK = 1 << 20  # 1 MiB


@dataclass
class Record:
    """One carved file, as far as we can characterise it."""

    path: str
    size: int
    kind: str
    verdict: str
    detail: str = ""
    good_bytes: int = 0
    sha256: Optional[str] = None
    meta: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(line: str) -> "Record":
        return Record(**json.loads(line))


def sha256_of(path: Path) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(CHUNK), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every regular file under root, skipping symlinks.

    Recovered trees are untrusted input; following links could walk us out of
    the directory entirely.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_file() and not full.is_symlink():
                yield full


def examine(path: Path, root: Path, want_hash: bool = True) -> Record:
    """Validate one file and pull its metadata."""
    result = formats.validate(path)
    extracted = meta_mod.extract(path, result.kind)
    combined = dict(result.meta)
    combined.update(extracted.as_dict())
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return Record(
        path=str(path.relative_to(root)),
        size=size,
        kind=result.kind,
        verdict=result.verdict,
        detail=result.detail,
        good_bytes=result.good_bytes,
        # Hashing empty files is pointless and they all collide anyway.
        sha256=sha256_of(path) if (want_hash and size) else None,
        meta=combined,
    )


def scan_tree(
    root: Path,
    want_hash: bool = True,
    progress_every: int = 500,
    stream: Optional[object] = None,
) -> Iterator[Record]:
    """Examine every file under root, reporting progress to stderr."""
    handle = stream if stream is not None else sys.stderr
    count = 0
    for path in iter_files(root):
        yield examine(path, root, want_hash=want_hash)
        count += 1
        if progress_every and count % progress_every == 0:
            print(f"  scanned {count} files...", file=handle, flush=True)
    if progress_every and count:
        print(f"  scanned {count} files total", file=handle, flush=True)


def write_index(records: Iterable[Record], out_path: Path) -> int:
    """Persist records as JSON Lines. Returns the number written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(record.to_json() + "\n")
            written += 1
    return written


def read_index(path: Path) -> Iterator[Record]:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield Record.from_json(line)
