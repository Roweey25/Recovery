"""Tests built on synthetic files with known damage.

Every fixture is generated in-process rather than checked in, so the expected
verdict is derivable from how the bytes were constructed.
"""

from __future__ import annotations

import binascii
import io
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rtriage import meta as meta_mod  # noqa: E402
from rtriage.formats import CORRUPT, EMPTY, OK, TRUNCATED, UNKNOWN, sniff, validate  # noqa: E402
from rtriage.organize import build_plan, safe_stem  # noqa: E402
from rtriage.scan import Record, examine, iter_files  # noqa: E402


# ---------------------------------------------------------------- builders


def make_exif(date: str = "2019:07:04 14:30:22") -> bytes:
    """A minimal little-endian TIFF block holding DateTimeOriginal."""
    stamp = date.encode("ascii") + b"\x00"
    tiff = bytearray()
    tiff += b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    # IFD0: one entry pointing at the Exif sub-IFD, which starts at 26.
    tiff += struct.pack("<H", 1)
    tiff += struct.pack("<HHII", 0x8769, 4, 1, 26)
    tiff += struct.pack("<I", 0)
    # Exif IFD: DateTimeOriginal, whose value is too long to inline.
    tiff += struct.pack("<H", 1)
    tiff += struct.pack("<HHII", 0x9003, 2, len(stamp), 44)
    tiff += struct.pack("<I", 0)
    assert len(tiff) == 44, len(tiff)
    tiff += stamp
    return bytes(tiff)


def make_jpeg(with_exif: bool = False, complete: bool = True) -> bytes:
    out = bytearray(b"\xff\xd8")
    jfif = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xe0" + struct.pack(">H", len(jfif) + 2) + jfif
    if with_exif:
        payload = b"Exif\x00\x00" + make_exif()
        out += b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    sos = b"\x01\x01\x00\x00\x3f\x00"
    out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos
    out += b"\x12\x34\x56\x78" * 32  # stand-in for entropy-coded data
    if complete:
        out += b"\xff\xd9"
    return bytes(out)


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + ctype
        + data
        + struct.pack(">I", binascii.crc32(ctype + data) & 0xFFFFFFFF)
    )


def make_png(complete: bool = True, break_crc: bool = False) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    chunk = _png_chunk(b"IHDR", ihdr)
    if break_crc:
        chunk = chunk[:-1] + bytes([chunk[-1] ^ 0xFF])
    out += chunk
    out += _png_chunk(b"IDAT", zlib.compress(b"\x00" + b"\xff\x00\x00" * 8))
    if complete:
        out += _png_chunk(b"IEND", b"")
    return bytes(out)


def make_docx(title: str = "Quarterly Report", author: str = "R Yadin") -> bytes:
    core = (
        '<?xml version="1.0"?><cp:coreProperties '
        'xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z">'
        f"<dc:title>{title}</dc:title><dc:creator>{author}</dc:creator>"
        "<dcterms:created>2021-03-15T09:00:00Z</dcterms:created>"
        "</cp:coreProperties>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document><body>text</body></document>")
        zf.writestr("docProps/core.xml", core)
    return buf.getvalue()


def make_mp4(complete: bool = True) -> bytes:
    ftyp = struct.pack(">I", 16) + b"ftyp" + b"isom" + b"\x00\x00\x00\x00"
    body = b"\x00" * 24
    declared = 8 + len(body) + (0 if complete else 64)
    moov = struct.pack(">I", declared) + b"moov" + body
    return ftyp + moov


def make_riff(complete: bool = True) -> bytes:
    payload = b"fmt " + b"\x00" * 16 + b"data" + b"\x01\x02" * 16
    declared = 4 + len(payload) + (0 if complete else 128)
    return b"RIFF" + struct.pack("<I", declared) + b"WAVE" + payload


def make_pdf(complete: bool = True, with_xref: bool = True) -> bytes:
    out = b"%PDF-1.4\n1 0 obj\n<< /Title (Recovered Notes) >>\nendobj\n"
    out += b"trailer\n<< /Root 1 0 R >>\n"
    if with_xref:
        out += b"startxref\n9\n"
    if complete:
        out += b"%%EOF\n"
    return out


def make_sqlite(pages: int = 2, page_size: int = 512, complete: bool = True) -> bytes:
    header = bytearray(b"SQLite format 3\x00")
    header += struct.pack(">H", page_size)
    header += b"\x00" * (28 - len(header))
    header += struct.pack(">I", pages)
    body = bytes(header) + b"\x00" * (page_size * pages - len(header))
    return body if complete else body[: page_size + 100]


# ---------------------------------------------------------------- helpers


class FixtureCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


# ---------------------------------------------------------------- detection


class TestSniff(FixtureCase):
    def test_identifies_by_content_not_extension(self):
        # A carver that guessed wrong should not fool us.
        path = self.write("f0001.txt", make_png())
        self.assertEqual(sniff(path), "png")

    def test_isobmff_magic_at_offset_four(self):
        self.assertEqual(sniff(self.write("v.mp4", make_mp4())), "isobmff")

    def test_unknown_for_arbitrary_bytes(self):
        self.assertEqual(sniff(self.write("x.bin", b"\x99" * 64)), "unknown")

    def test_empty_file(self):
        self.assertEqual(sniff(self.write("z.bin", b"")), "empty")


# ---------------------------------------------------------------- validators


class TestJpeg(FixtureCase):
    def test_complete(self):
        result = validate(self.write("a.jpg", make_jpeg()))
        self.assertEqual((result.kind, result.verdict), ("jpeg", OK))

    def test_missing_eoi_is_truncated(self):
        result = validate(self.write("b.jpg", make_jpeg(complete=False)))
        self.assertEqual(result.verdict, TRUNCATED)
        self.assertIn("EOI", result.detail)

    def test_sector_padding_still_counts_as_complete(self):
        # Carvers commonly pad to a sector boundary; that is not damage.
        result = validate(self.write("c.jpg", make_jpeg() + b"\x00" * 512))
        self.assertEqual(result.verdict, OK)

    def test_header_cut_short(self):
        data = make_jpeg()[:6]
        result = validate(self.write("d.jpg", data))
        self.assertEqual(result.verdict, TRUNCATED)


class TestPng(FixtureCase):
    def test_complete(self):
        result = validate(self.write("a.png", make_png()))
        self.assertEqual((result.kind, result.verdict), ("png", OK))
        self.assertEqual(result.meta.get("width"), 8)

    def test_missing_iend_is_truncated(self):
        result = validate(self.write("b.png", make_png(complete=False)))
        self.assertEqual(result.verdict, TRUNCATED)

    def test_crc_mismatch_is_corrupt_not_truncated(self):
        # Bytes present but wrong means an interior overwrite.
        result = validate(self.write("c.png", make_png(break_crc=True)))
        self.assertEqual(result.verdict, CORRUPT)
        self.assertIn("CRC", result.detail)


class TestZip(FixtureCase):
    def test_docx_recognised_from_internal_layout(self):
        result = validate(self.write("a.zip", make_docx()))
        self.assertEqual((result.kind, result.verdict), ("docx", OK))

    def test_chopped_tail_is_truncated(self):
        blob = make_docx()
        result = validate(self.write("b.docx", blob[: len(blob) // 2]))
        self.assertEqual(result.verdict, TRUNCATED)
        self.assertIn("central-directory", result.detail)


class TestIsoBmff(FixtureCase):
    def test_complete(self):
        result = validate(self.write("a.mp4", make_mp4()))
        self.assertEqual((result.kind, result.verdict), ("mp4", OK))
        self.assertIn("moov", result.meta["boxes"])

    def test_box_running_past_eof(self):
        result = validate(self.write("b.mp4", make_mp4(complete=False)))
        self.assertEqual(result.verdict, TRUNCATED)
        self.assertIn("past EOF", result.detail)

    def test_missing_moov_is_unplayable(self):
        ftyp = struct.pack(">I", 16) + b"ftyp" + b"isom" + b"\x00\x00\x00\x00"
        mdat = struct.pack(">I", 16) + b"mdat" + b"\x00" * 8
        result = validate(self.write("c.mp4", ftyp + mdat))
        self.assertEqual(result.verdict, CORRUPT)
        self.assertIn("moov", result.detail)


class TestOtherFormats(FixtureCase):
    def test_riff_complete_and_short(self):
        self.assertEqual(validate(self.write("a.wav", make_riff())).verdict, OK)
        short = validate(self.write("b.wav", make_riff(complete=False)))
        self.assertEqual(short.verdict, TRUNCATED)

    def test_riff_kind_from_form_type(self):
        self.assertEqual(validate(self.write("c.wav", make_riff())).kind, "wav")

    def test_pdf_variants(self):
        self.assertEqual(validate(self.write("a.pdf", make_pdf())).verdict, OK)
        self.assertEqual(
            validate(self.write("b.pdf", make_pdf(complete=False))).verdict, TRUNCATED
        )
        lost_xref = validate(self.write("c.pdf", make_pdf(with_xref=False)))
        self.assertEqual(lost_xref.verdict, CORRUPT)
        self.assertIn("startxref", lost_xref.detail)

    def test_sqlite_page_accounting(self):
        self.assertEqual(validate(self.write("a.db", make_sqlite())).verdict, OK)
        short = validate(self.write("b.db", make_sqlite(complete=False)))
        self.assertEqual(short.verdict, TRUNCATED)

    def test_gif_trailer(self):
        gif = b"GIF89a" + struct.pack("<HH", 4, 4) + b"\x00" * 8
        self.assertEqual(validate(self.write("a.gif", gif + b"\x3b")).verdict, OK)
        self.assertEqual(validate(self.write("b.gif", gif)).verdict, TRUNCATED)

    def test_empty_and_unknown(self):
        self.assertEqual(validate(self.write("a.bin", b"")).verdict, EMPTY)
        self.assertEqual(validate(self.write("b.bin", b"\x99" * 40)).verdict, UNKNOWN)


# ---------------------------------------------------------------- metadata


class TestMetadata(FixtureCase):
    def test_exif_date_from_jpeg(self):
        path = self.write("a.jpg", make_jpeg(with_exif=True))
        extracted = meta_mod.extract(path, "jpeg")
        self.assertEqual(extracted.date, "2019-07-04")

    def test_jpeg_without_exif_yields_nothing(self):
        path = self.write("b.jpg", make_jpeg())
        self.assertIsNone(meta_mod.extract(path, "jpeg").date)

    def test_ooxml_core_properties(self):
        path = self.write("a.docx", make_docx())
        extracted = meta_mod.extract(path, "docx")
        self.assertEqual(extracted.title, "Quarterly Report")
        self.assertEqual(extracted.author, "R Yadin")
        self.assertEqual(extracted.date, "2021-03-15")

    def test_pdf_title(self):
        path = self.write("a.pdf", make_pdf())
        self.assertEqual(meta_mod.extract(path, "pdf").title, "Recovered Notes")

    def test_malformed_input_does_not_raise(self):
        path = self.write("bad.jpg", b"\xff\xd8\xff\xe1\x00\x08Exif")
        self.assertIsNone(meta_mod.extract(path, "jpeg").date)


# ---------------------------------------------------------------- organising


class TestOrganize(FixtureCase):
    def _records(self):
        return [
            Record(path="f1.jpg", size=100, kind="jpeg", verdict=OK,
                   good_bytes=100, sha256="a" * 64, meta={"date": "2019-07-04"}),
            # Same bytes, worse condition: must lose to the intact copy.
            Record(path="sub/f2.jpg", size=100, kind="jpeg", verdict=TRUNCATED,
                   good_bytes=60, sha256="a" * 64, meta={}),
            Record(path="f3.pdf", size=200, kind="pdf", verdict=OK,
                   good_bytes=200, sha256="b" * 64, meta={"title": "Notes"}),
        ]

    def test_dedupe_keeps_the_healthiest_copy(self):
        plan = build_plan(self._records())
        self.assertEqual(plan.counts["duplicate_files"], 1)
        sources = {m.src for m in plan.moves}
        self.assertIn("f1.jpg", sources)
        self.assertNotIn("sub/f2.jpg", sources)

    def test_destination_encodes_verdict_kind_and_month(self):
        plan = build_plan(self._records())
        dest = next(m.dest for m in plan.moves if m.src == "f1.jpg")
        self.assertTrue(dest.startswith("ok/jpeg/2019-07/"))

    def test_title_becomes_the_filename(self):
        plan = build_plan(self._records())
        dest = next(m.dest for m in plan.moves if m.src == "f3.pdf")
        self.assertIn("Notes", dest)
        self.assertTrue(dest.endswith(".pdf"))

    def test_keep_duplicates_retains_them(self):
        plan = build_plan(self._records(), keep_duplicates=True)
        self.assertTrue(any(m.reason == "duplicate" for m in plan.moves))

    def test_extension_follows_content_not_original_name(self):
        record = Record(path="f0001.txt", size=10, kind="png", verdict=OK,
                        good_bytes=10, sha256="c" * 64)
        plan = build_plan([record])
        self.assertTrue(plan.moves[0].dest.endswith(".png"))

    def test_unhashed_records_survive(self):
        record = Record(path="x.bin", size=0, kind="empty", verdict=EMPTY, sha256=None)
        self.assertEqual(len(build_plan([record]).moves), 1)


class TestSafeStem(unittest.TestCase):
    def test_strips_path_and_control_characters(self):
        self.assertNotIn("/", safe_stem("a/b\\c"))
        self.assertNotIn("\x00", safe_stem("a\x00b"))

    def test_reserved_windows_names_fall_back(self):
        self.assertEqual(safe_stem("CON", fallback="fb"), "fb")

    def test_length_is_capped(self):
        self.assertLessEqual(len(safe_stem("x" * 500)), 80)

    def test_empty_input_falls_back(self):
        self.assertEqual(safe_stem("   ", fallback="fb"), "fb")


class TestScanning(FixtureCase):
    def test_examine_produces_a_relative_path(self):
        self.write("nested/dir/a.png", make_png())
        record = examine(self.root / "nested/dir/a.png", self.root)
        self.assertEqual(record.path.replace("\\", "/"), "nested/dir/a.png")
        self.assertEqual(record.verdict, OK)
        self.assertIsNotNone(record.sha256)

    def test_index_round_trip(self):
        self.write("a.png", make_png())
        record = examine(self.root / "a.png", self.root)
        self.assertEqual(Record.from_json(record.to_json()), record)

    def test_walk_finds_nested_files_and_skips_symlinks(self):
        self.write("a/b/c.png", make_png())
        self.write("d.png", make_png())
        try:
            (self.root / "link.png").symlink_to(self.root / "d.png")
        except (OSError, NotImplementedError):
            pass  # unprivileged Windows cannot create symlinks
        names = {p.name for p in iter_files(self.root)}
        self.assertIn("c.png", names)
        self.assertNotIn("link.png", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
