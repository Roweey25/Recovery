# rtriage

Make sense of what a file carver spat out.

R-Studio, photorec and foremost recover files by matching magic bytes at the
start of a run of sectors. They cannot see where a file *ends*, so their output
is a mix of intact files, files truncated mid-stream, files whose interior was
overwritten, and many duplicate copies of the same bytes — all named
`f0015416.png` and dumped in one flat directory.

`rtriage` answers the only question that matters at that point: **which of these
can I actually open?**

It parses each file against its own format's container structure, drops
duplicates, and files the survivors into a tree organised by condition.

## Requirements

Python 3.8 or newer. Nothing else — the whole package is standard library, so it
runs on the Windows machine holding your R-Studio output without installing
anything.

## Usage

Three steps. Scanning is separate from organising because hashing and validating
a few hundred thousand files takes a while, and you will want to try more than
one filing scheme without paying that cost twice.

```bash
# 1. Validate and index everything the carver produced.
python -m rtriage scan /path/to/recovered -o index.jsonl

# 2. See what you actually got.
python -m rtriage report index.jsonl --csv detail.csv

# 3. Preview the sorted tree, then write it.
python -m rtriage organize index.jsonl --source /path/to/recovered --dest /path/to/sorted
python -m rtriage organize index.jsonl --source /path/to/recovered --dest /path/to/sorted --execute
```

`organize` is a dry run unless you pass `--execute`. It refuses to write into the
source tree — on a recovery job that is often the only copy you have.

To check individual files:

```bash
python -m rtriage check suspect.jpg other.pdf
```

### Useful flags

| Flag | Effect |
|---|---|
| `--no-hash` | Skip SHA-256. Much faster, but disables duplicate detection. |
| `--move` | Move instead of copy. Halves the free space you need. |
| `--keep-duplicates` | Retain redundant copies under `duplicates/` instead of dropping them. |

## What the verdicts mean

| Verdict | Meaning | What to do |
|---|---|---|
| `ok` | Structure is complete and internally consistent. | Open it. |
| `truncated` | Header is valid, the file ends early. | Partly recoverable — images often render top-down to the cut. `good_bytes` says how much survived. |
| `corrupt` | Bytes are present but wrong: failed checksum, impossible offsets, missing index. | Something overwrote the interior. Usually unrecoverable, but PDFs with a lost xref can often be repaired. |
| `unknown` | Not a format with a structural check here. | Inspect manually. |
| `empty` | Zero bytes. | Discard. |

The `truncated` / `corrupt` split is the useful one. Truncation means the tail
was never recovered, so re-carving with a larger block size or from a different
scan may get more. Corruption means another file's data landed on top of this
one, and no amount of re-carving will bring it back.

## Output layout

```
sorted/
  ok/
    jpeg/2019-07/2019-07-04_IMG_4471_a1b2c3d4.jpg
    docx/2021-03/2021-03-15_Quarterly Report_65604260.docx
  truncated/
    mp4/f0021184_9e8d7c6b.mp4
  corrupt/
  unknown/
  duplicates/          (only with --keep-duplicates)
```

Files are renamed from whatever identifying metadata survived — EXIF capture
date and camera for photos, `dc:title` for Office documents, `/Title` for PDFs —
falling back to the carver's name. A short hash slice keeps names unique, so the
same input always produces the same output. Extensions come from **content**,
not from the carver's guess.

## Supported formats

Structurally validated:

| Format | How it is checked |
|---|---|
| JPEG | Segment walk to SOS, then EOI presence (tolerating sector padding) |
| PNG | Chunk walk with CRC32 verification, IHDR first and IEND last |
| GIF | Header plus trailer byte |
| TIFF | Byte order, magic, first IFD offset within bounds |
| PDF | `%%EOF` trailer and `startxref` pointer |
| ZIP / DOCX / XLSX / PPTX / ODF / JAR | Full decompress-and-CRC of every member |
| MP4 / MOV / HEIC | Box walk, sizes must not run past EOF, `moov` required |
| WAV / AVI / WEBP | RIFF declared size against actual size |
| SQLite | Page size × page count against actual size |

Identified but not structurally verified: OLE2 (legacy `.doc`/`.xls`/`.ppt`),
MP3, Ogg, FLAC, BMP, gzip, 7z, RAR, PostScript.

Metadata is extracted from JPEG (EXIF), OOXML (`docProps/core.xml`) and PDF
(document info dictionary).

## Limitations

Worth being straight about these:

- **`ok` means structurally sound, not visually correct.** A JPEG can have valid
  markers and a complete EOI while the image is garbage, if the entropy-coded
  data came from another file. Structure is a strong filter, not a guarantee.
- **`unknown` is not a failure.** It means no validator covers that type. The
  file may be perfectly fine.
- **Legacy Office files get no real check.** OLE2 compound documents need
  directory-tree parsing that isn't implemented; they pass through as `unknown`
  quality.
- **Encrypted and DRM-protected files** will read as corrupt or unknown.
- **Duplicate detection is exact-match only.** Two encodings of the same photo
  have different bytes and will both be kept.

## Tests

```bash
python -m unittest discover -s tests -v
```

40 tests, no third-party dependencies. Every fixture is generated in-process
with known damage, so the expected verdict follows from how the bytes were
built. The pipeline has also been checked end to end against real `photorec`
output carved from a deleted ext4 filesystem.

## See also

[`docs/recovery-workflow.md`](docs/recovery-workflow.md) — where this fits in a
recovery job, how to avoid the mistakes that destroy recoverable data, and the
open-source tooling that complements R-Studio.
