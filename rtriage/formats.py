"""Structural validation of carved files.

Carving tools (R-Studio's "known file types" scan, photorec, foremost) recover
files by matching magic bytes at the start of a run of sectors. They cannot tell
where the file *ends*, so their output is a mix of intact files, files truncated
mid-stream, and files whose interior was overwritten by unrelated data.

The functions here parse each format's container structure far enough to tell
those cases apart. Everything is stdlib-only and streams where it can, so this
runs unmodified next to R-Studio on Windows with nothing but Python installed.
"""

from __future__ import annotations

import binascii
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Verdicts, ordered from best to worst outcome.
OK = "ok"
TRUNCATED = "truncated"
CORRUPT = "corrupt"
UNKNOWN = "unknown"
EMPTY = "empty"

VERDICT_RANK = {OK: 0, TRUNCATED: 1, CORRUPT: 2, UNKNOWN: 3, EMPTY: 4}


@dataclass
class Result:
    """Outcome of validating one file."""

    kind: str = "unknown"
    verdict: str = UNKNOWN
    detail: str = ""
    # Bytes of real content we could account for. For a truncated file this is
    # how much survived; recovering the tail means re-carving from here on.
    good_bytes: int = 0
    meta: dict = field(default_factory=dict)


def _read(path: Path, size: int, offset: int = 0) -> bytes:
    with path.open("rb") as fh:
        if offset:
            fh.seek(offset)
        return fh.read(size)


def _tail(path: Path, size: int) -> bytes:
    with path.open("rb") as fh:
        fh.seek(0, 2)
        end = fh.tell()
        fh.seek(max(0, end - size))
        return fh.read(size)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

_MAGIC = [
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),  # empty archive
    (b"II\x2a\x00", "tiff"),
    (b"MM\x00\x2a", "tiff"),
    (b"BM", "bmp"),
    (b"RIFF", "riff"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (b"ID3", "mp3"),
    (b"OggS", "ogg"),
    (b"fLaC", "flac"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x25\x21PS", "postscript"),
]


def sniff(path: Path) -> str:
    """Identify a file by content, ignoring its (carver-invented) extension."""
    head = _read(path, 32)
    if not head:
        return "empty"
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    # ISO-BMFF (mp4/mov/heic) carries its magic at offset 4, not 0.
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "isobmff"
    # Bare MP3 frame sync, for files carved without an ID3 tag.
    if len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        return "mp3"
    return "unknown"


# --------------------------------------------------------------------------
# Per-format validators
# --------------------------------------------------------------------------


def _validate_jpeg(path: Path, size: int) -> Result:
    res = Result(kind="jpeg")
    with path.open("rb") as fh:
        if fh.read(2) != b"\xff\xd8":
            res.verdict = CORRUPT
            res.detail = "missing SOI"
            return res
        # Walk marker segments up to the scan. A carved JPEG that dies inside
        # the header is corrupt; one that dies inside entropy data is truncated.
        while True:
            marker = fh.read(2)
            if len(marker) < 2:
                res.verdict = TRUNCATED
                res.detail = "ended inside segment headers"
                res.good_bytes = fh.tell()
                return res
            if marker[0] != 0xFF:
                res.verdict = CORRUPT
                res.detail = f"bad marker at offset {fh.tell() - 2}"
                res.good_bytes = fh.tell() - 2
                return res
            code = marker[1]
            if code == 0xD9:  # EOI before any scan: valid but empty
                break
            if code == 0xDA:  # SOS - entropy-coded data follows
                res.good_bytes = fh.tell()
                break
            length_raw = fh.read(2)
            if len(length_raw) < 2:
                res.verdict = TRUNCATED
                res.detail = "ended inside segment length"
                res.good_bytes = fh.tell()
                return res
            (length,) = struct.unpack(">H", length_raw)
            if length < 2:
                res.verdict = CORRUPT
                res.detail = "invalid segment length"
                return res
            payload = fh.read(length - 2)
            if len(payload) < length - 2:
                res.verdict = TRUNCATED
                res.detail = "ended inside segment payload"
                res.good_bytes = fh.tell()
                return res
            if code == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                res.meta["exif_offset"] = fh.tell() - len(payload) + 6

    # A complete JPEG ends with EOI. Carvers often pad to a sector boundary, so
    # tolerate trailing NUL/0xFF fill rather than calling a good file truncated.
    tail = _tail(path, 4096).rstrip(b"\x00\xff")
    if tail.endswith(b"\xff\xd9"):
        res.verdict = OK
        res.good_bytes = size
    else:
        res.verdict = TRUNCATED
        res.detail = "no EOI marker"
        res.good_bytes = res.good_bytes or size
    return res


def _validate_png(path: Path, size: int) -> Result:
    res = Result(kind="png")
    with path.open("rb") as fh:
        fh.seek(8)  # past signature
        first = True
        while True:
            header = fh.read(8)
            if len(header) < 8:
                res.verdict = TRUNCATED
                res.detail = "ended between chunks"
                return res
            length, ctype = struct.unpack(">I4s", header)
            if first and ctype != b"IHDR":
                res.verdict = CORRUPT
                res.detail = "first chunk is not IHDR"
                return res
            if length > size:
                res.verdict = CORRUPT
                res.detail = f"chunk {ctype.decode('ascii', 'replace')} length exceeds file"
                return res
            data = fh.read(length)
            if len(data) < length:
                res.verdict = TRUNCATED
                res.detail = f"ended inside {ctype.decode('ascii', 'replace')} chunk"
                res.good_bytes = fh.tell()
                return res
            crc_raw = fh.read(4)
            if len(crc_raw) < 4:
                res.verdict = TRUNCATED
                res.detail = "ended before chunk CRC"
                res.good_bytes = fh.tell()
                return res
            (want,) = struct.unpack(">I", crc_raw)
            # CRC mismatch means the bytes are present but wrong: this is the
            # signature of an interior overwrite, not a truncation.
            if binascii.crc32(ctype + data) & 0xFFFFFFFF != want:
                res.verdict = CORRUPT
                res.detail = f"CRC mismatch in {ctype.decode('ascii', 'replace')}"
                res.good_bytes = fh.tell() - length - 12
                return res
            if first:
                if length >= 8:
                    w, h = struct.unpack(">II", data[:8])
                    res.meta["width"], res.meta["height"] = w, h
                first = False
            if ctype == b"IEND":
                res.verdict = OK
                res.good_bytes = fh.tell()
                return res


def _validate_gif(path: Path, size: int) -> Result:
    res = Result(kind="gif")
    head = _read(path, 10)
    if len(head) >= 10:
        w, h = struct.unpack("<HH", head[6:10])
        res.meta["width"], res.meta["height"] = w, h
    tail = _tail(path, 4096).rstrip(b"\x00")
    if tail.endswith(b"\x3b"):
        res.verdict = OK
        res.good_bytes = size
    else:
        res.verdict = TRUNCATED
        res.detail = "no trailer byte"
        res.good_bytes = size
    return res


def _validate_pdf(path: Path, size: int) -> Result:
    res = Result(kind="pdf")
    head = _read(path, 1024)
    if b"%PDF-" in head:
        idx = head.index(b"%PDF-")
        res.meta["version"] = head[idx + 5 : idx + 8].decode("ascii", "replace")
    # A well-formed PDF ends with "startxref / <offset> / %%EOF", so both live
    # in the last few hundred bytes. The window is far wider than that to
    # absorb carver padding and oversized trailer dictionaries.
    tail = _tail(path, 65536)
    if b"%%EOF" not in tail:
        res.verdict = TRUNCATED
        res.detail = "no %%EOF trailer"
        res.good_bytes = size
        return res
    if b"startxref" not in tail:
        # Trailer present but the cross-reference pointer is gone: readers will
        # need to rebuild the xref table before this opens.
        res.verdict = CORRUPT
        res.detail = "%%EOF without startxref (xref table lost)"
        res.good_bytes = size
        return res
    res.verdict = OK
    res.good_bytes = size
    return res


# Distinguish the OOXML family from plain zips by their internal layout.
_OOXML_HINTS = {
    "word/document.xml": "docx",
    "xl/workbook.xml": "xlsx",
    "ppt/presentation.xml": "pptx",
}


def _validate_zip(path: Path, size: int) -> Result:
    res = Result(kind="zip")
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            # testzip() decompresses every member and checks its CRC. This is
            # the strongest signal available for any zip-based format.
            bad = zf.testzip()
            if bad is not None:
                res.verdict = CORRUPT
                res.detail = f"CRC failure in member {bad!r}"
                return res
            for hint, kind in _OOXML_HINTS.items():
                if hint in names:
                    res.kind = kind
                    break
            else:
                if "META-INF/MANIFEST.MF" in names:
                    res.kind = "jar"
                elif any(n.startswith("META-INF/") and n.endswith(".xml") for n in names):
                    res.kind = "odf"
            res.meta["members"] = len(names)
            res.verdict = OK
            res.good_bytes = size
    except zipfile.BadZipFile as exc:
        # BadZipFile's message is not a reliable discriminator, so look for the
        # end-of-central-directory signature ourselves. Its absence is the
        # classic shape of a zip whose tail was never recovered; if it is there
        # and the archive still will not open, the damage is interior.
        # EOCD lives in the last 22 bytes plus up to 64 KiB of comment.
        if b"PK\x05\x06" not in _tail(path, 65536 + 22):
            res.verdict = TRUNCATED
            res.detail = "no end-of-central-directory record"
        else:
            res.verdict = CORRUPT
            res.detail = str(exc)[:120]
    except (OSError, RuntimeError, NotImplementedError) as exc:
        res.verdict = CORRUPT
        res.detail = f"{type(exc).__name__}: {exc}"[:120]
    return res


def _validate_isobmff(path: Path, size: int) -> Result:
    """MP4/MOV/HEIC: a flat sequence of length-prefixed boxes."""
    res = Result(kind="isobmff")
    brand = _read(path, 12, 8)[:4]
    res.meta["brand"] = brand.decode("ascii", "replace").strip()
    if brand[:3] in (b"qt ", b"qt"):
        res.kind = "mov"
    elif brand.startswith(b"heic") or brand.startswith(b"heix"):
        res.kind = "heic"
    else:
        res.kind = "mp4"

    seen = set()
    offset = 0
    with path.open("rb") as fh:
        while offset < size:
            fh.seek(offset)
            header = fh.read(8)
            if len(header) < 8:
                res.verdict = TRUNCATED
                res.detail = "ended between boxes"
                res.good_bytes = offset
                break
            box_size, box_type = struct.unpack(">I4s", header)
            hdr_len = 8
            if box_size == 1:  # 64-bit extended size
                ext = fh.read(8)
                if len(ext) < 8:
                    res.verdict = TRUNCATED
                    res.detail = "ended inside 64-bit box size"
                    res.good_bytes = offset
                    break
                (box_size,) = struct.unpack(">Q", ext)
                hdr_len = 16
            elif box_size == 0:  # extends to end of file
                box_size = size - offset
            if box_size < hdr_len:
                res.verdict = CORRUPT
                res.detail = f"invalid box size at offset {offset}"
                res.good_bytes = offset
                break
            seen.add(box_type)
            if offset + box_size > size:
                res.verdict = TRUNCATED
                res.detail = (
                    f"box {box_type.decode('ascii', 'replace')} runs "
                    f"{offset + box_size - size} bytes past EOF"
                )
                res.good_bytes = offset
                break
            offset += box_size
        else:
            res.verdict = OK
            res.good_bytes = size

    res.meta["boxes"] = ",".join(sorted(b.decode("ascii", "replace") for b in seen))
    # Without moov there is no index, so players cannot open the file even if
    # every byte of media data survived.
    if res.verdict == OK and b"moov" not in seen:
        res.verdict = CORRUPT
        res.detail = "no moov box (unplayable without index)"
    return res


def _validate_riff(path: Path, size: int) -> Result:
    res = Result(kind="riff")
    head = _read(path, 12)
    if len(head) < 12:
        res.verdict = TRUNCATED
        res.detail = "shorter than RIFF header"
        return res
    (declared,) = struct.unpack("<I", head[4:8])
    form = head[8:12]
    res.kind = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(form, "riff")
    expected = declared + 8
    if expected > size:
        res.verdict = TRUNCATED
        res.detail = f"declared {expected} bytes, file holds {size}"
        res.good_bytes = size
    else:
        res.verdict = OK
        res.good_bytes = expected
        if expected < size:
            res.detail = f"{size - expected} trailing bytes (carver padding)"
    return res


def _validate_tiff(path: Path, size: int) -> Result:
    res = Result(kind="tiff")
    head = _read(path, 8)
    endian = "<" if head[:2] == b"II" else ">"
    (ifd_offset,) = struct.unpack(endian + "I", head[4:8])
    if ifd_offset >= size:
        res.verdict = TRUNCATED
        res.detail = "first IFD lies beyond EOF"
        res.good_bytes = size
        return res
    res.meta["endian"] = "little" if endian == "<" else "big"
    res.verdict = OK
    res.good_bytes = size
    return res


def _validate_sqlite(path: Path, size: int) -> Result:
    res = Result(kind="sqlite")
    head = _read(path, 32)
    if len(head) < 32:
        res.verdict = TRUNCATED
        res.detail = "shorter than header"
        return res
    (page_size,) = struct.unpack(">H", head[16:18])
    if page_size == 1:
        page_size = 65536
    (page_count,) = struct.unpack(">I", head[28:32])
    res.meta["page_size"] = page_size
    res.meta["page_count"] = page_count
    expected = page_size * page_count
    if page_count and expected > size:
        res.verdict = TRUNCATED
        res.detail = f"header declares {expected} bytes, file holds {size}"
        res.good_bytes = size
    elif size % page_size:
        res.verdict = CORRUPT
        res.detail = "size is not a whole number of pages"
        res.good_bytes = size - (size % page_size)
    else:
        res.verdict = OK
        res.good_bytes = size
    return res


def _validate_opaque(kind: str):
    """Formats we can identify but not structurally verify."""

    def _inner(path: Path, size: int) -> Result:
        return Result(kind=kind, verdict=UNKNOWN, detail="no structural check", good_bytes=size)

    return _inner


_VALIDATORS = {
    "jpeg": _validate_jpeg,
    "png": _validate_png,
    "gif": _validate_gif,
    "pdf": _validate_pdf,
    "zip": _validate_zip,
    "isobmff": _validate_isobmff,
    "riff": _validate_riff,
    "tiff": _validate_tiff,
    "sqlite": _validate_sqlite,
    "ole2": _validate_opaque("ole2"),
    "mp3": _validate_opaque("mp3"),
    "ogg": _validate_opaque("ogg"),
    "flac": _validate_opaque("flac"),
    "gzip": _validate_opaque("gzip"),
    "7z": _validate_opaque("7z"),
    "rar": _validate_opaque("rar"),
    "bmp": _validate_opaque("bmp"),
    "postscript": _validate_opaque("postscript"),
}


def validate(path: Path) -> Result:
    """Identify and structurally validate a single carved file."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return Result(verdict=CORRUPT, detail=f"stat failed: {exc}")
    if size == 0:
        return Result(kind="empty", verdict=EMPTY, detail="zero bytes")

    kind = sniff(path)
    if kind in ("unknown", "empty"):
        return Result(kind="unknown", verdict=UNKNOWN, detail="unrecognised magic", good_bytes=size)

    validator = _VALIDATORS.get(kind)
    if validator is None:
        return Result(kind=kind, verdict=UNKNOWN, detail="no validator", good_bytes=size)
    try:
        return validator(path, size)
    except (OSError, struct.error, ValueError) as exc:
        return Result(kind=kind, verdict=CORRUPT, detail=f"{type(exc).__name__}: {exc}"[:120])
