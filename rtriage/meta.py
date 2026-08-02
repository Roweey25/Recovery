"""Recover meaningful names and dates from inside recovered files.

Carvers name their output by sequence number, so the filesystem tells you
nothing. Most of what was lost is still sitting in the file's own metadata:
capture dates in EXIF, authorship and titles in OOXML and PDF. This module digs
that out so files can be sorted into something navigable.
"""

from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# EXIF/TIFF tags worth surfacing.
_TAG_MAKE = 0x010F
_TAG_MODEL = 0x0110
_TAG_DATETIME = 0x0132
_TAG_EXIF_IFD = 0x8769
_TAG_DATETIME_ORIGINAL = 0x9003

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

_DATE_RE = re.compile(r"(\d{4})[:\-](\d{2})[:\-](\d{2})")


@dataclass
class Meta:
    """Whatever identifying detail we could pull out of a file."""

    date: Optional[str] = None  # YYYY-MM-DD
    title: Optional[str] = None
    author: Optional[str] = None
    camera: Optional[str] = None

    def as_dict(self) -> dict:
        return {k: v for k, v in vars(self).items() if v}


def _norm_date(raw: str) -> Optional[str]:
    match = _DATE_RE.search(raw)
    if not match:
        return None
    year, month, day = match.groups()
    if not (1900 <= int(year) <= 2100 and 1 <= int(month) <= 12 and 1 <= int(day) <= 31):
        return None
    return f"{year}-{month}-{day}"


def _clean(raw: bytes) -> Optional[str]:
    text = raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
    return text or None


def _read_ifd(data: bytes, offset: int, endian: str, out: dict, depth: int = 0) -> None:
    """Walk one TIFF IFD, following the Exif sub-IFD pointer once."""
    if depth > 2 or offset + 2 > len(data):
        return
    (count,) = struct.unpack_from(endian + "H", data, offset)
    pos = offset + 2
    for _ in range(count):
        if pos + 12 > len(data):
            return
        tag, typ, num = struct.unpack_from(endian + "HHI", data, pos)
        value_field = pos + 8
        size = _TYPE_SIZES.get(typ, 0) * num
        if size == 0:
            pos += 12
            continue
        if size > 4:
            (value_offset,) = struct.unpack_from(endian + "I", data, value_field)
        else:
            value_offset = value_field
        if value_offset + size <= len(data):
            if tag == _TAG_EXIF_IFD and typ == 4:
                (sub,) = struct.unpack_from(endian + "I", data, value_field)
                _read_ifd(data, sub, endian, out, depth + 1)
            elif tag in (_TAG_MAKE, _TAG_MODEL, _TAG_DATETIME, _TAG_DATETIME_ORIGINAL):
                out[tag] = data[value_offset : value_offset + size]
        pos += 12


def _jpeg_exif(path: Path) -> Meta:
    """Locate the APP1 segment and parse its embedded TIFF block."""
    meta = Meta()
    with path.open("rb") as fh:
        if fh.read(2) != b"\xff\xd8":
            return meta
        while True:
            marker = fh.read(2)
            if len(marker) < 2 or marker[0] != 0xFF:
                return meta
            code = marker[1]
            if code in (0xDA, 0xD9):  # scan or end: no more metadata segments
                return meta
            length_raw = fh.read(2)
            if len(length_raw) < 2:
                return meta
            (length,) = struct.unpack(">H", length_raw)
            if length < 2:
                return meta
            payload = fh.read(length - 2)
            if code == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                break
        tiff = payload[6:]

    if len(tiff) < 8:
        return meta
    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        (ifd_offset,) = struct.unpack_from(endian + "I", tiff, 4)
        tags: dict = {}
        _read_ifd(tiff, ifd_offset, endian, tags)
    except struct.error:
        return meta

    # DateTimeOriginal is when the shutter fired; DateTime may be an edit date.
    for tag in (_TAG_DATETIME_ORIGINAL, _TAG_DATETIME):
        if tag in tags:
            date = _norm_date(tags[tag].decode("ascii", "replace"))
            if date:
                meta.date = date
                break
    make = _clean(tags.get(_TAG_MAKE, b""))
    model = _clean(tags.get(_TAG_MODEL, b""))
    if make and model:
        # Camera makers often repeat the brand in the model string.
        meta.camera = model if model.lower().startswith(make.lower()) else f"{make} {model}"
    else:
        meta.camera = model or make
    return meta


_CORE_FIELDS = {
    "title": re.compile(rb"<dc:title>(.*?)</dc:title>", re.S),
    "author": re.compile(rb"<dc:creator>(.*?)</dc:creator>", re.S),
    "created": re.compile(rb"<dcterms:created[^>]*>(.*?)</dcterms:created>", re.S),
    "modified": re.compile(rb"<dcterms:modified[^>]*>(.*?)</dcterms:modified>", re.S),
}


def _ooxml_meta(path: Path) -> Meta:
    """Read docProps/core.xml out of a Word/Excel/PowerPoint file."""
    meta = Meta()
    try:
        with zipfile.ZipFile(path) as zf:
            if "docProps/core.xml" not in zf.namelist():
                return meta
            blob = zf.read("docProps/core.xml")
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return meta

    found = {}
    for name, pattern in _CORE_FIELDS.items():
        match = pattern.search(blob)
        if match:
            found[name] = match.group(1).decode("utf-8", "replace").strip()
    meta.title = found.get("title") or None
    meta.author = found.get("author") or None
    for key in ("created", "modified"):
        if key in found:
            date = _norm_date(found[key])
            if date:
                meta.date = date
                break
    return meta


_PDF_TITLE = re.compile(rb"/Title\s*\(([^)]{1,200})\)")
_PDF_AUTHOR = re.compile(rb"/Author\s*\(([^)]{1,200})\)")
_PDF_DATE = re.compile(rb"/CreationDate\s*\(D:(\d{8})")


def _pdf_meta(path: Path) -> Meta:
    """Scan the document info dictionary.

    PDF metadata may sit at either end of the file, so both are sampled rather
    than parsing the object graph — which a carved file often cannot support.
    """
    meta = Meta()
    with path.open("rb") as fh:
        head = fh.read(65536)
        fh.seek(0, 2)
        end = fh.tell()
        fh.seek(max(0, end - 65536))
        blob = head + fh.read(65536)

    match = _PDF_TITLE.search(blob)
    if match:
        meta.title = match.group(1).decode("utf-8", "replace").strip() or None
    match = _PDF_AUTHOR.search(blob)
    if match:
        meta.author = match.group(1).decode("utf-8", "replace").strip() or None
    match = _PDF_DATE.search(blob)
    if match:
        raw = match.group(1).decode("ascii", "replace")
        meta.date = _norm_date(f"{raw[0:4]}:{raw[4:6]}:{raw[6:8]}")
    return meta


def extract(path: Path, kind: str) -> Meta:
    """Pull identifying metadata appropriate to the detected file type."""
    try:
        if kind == "jpeg":
            return _jpeg_exif(path)
        if kind in ("docx", "xlsx", "pptx"):
            return _ooxml_meta(path)
        if kind == "pdf":
            return _pdf_meta(path)
    except (OSError, struct.error, ValueError):
        return Meta()
    return Meta()
