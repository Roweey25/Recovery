# Recovery workflow

Where `rtriage` fits, and what to do before you get to it.

## The rules that matter most

Recovery jobs are usually lost before any tool is opened, not during. Three
things account for most of it:

1. **Stop writing to the source.** Every write can land on the blocks holding
   what you want back. If the data is on the system disk, power down and pull
   the drive rather than running recovery from the running OS.
2. **Work from an image, never the original.** Take one copy, verify it, then
   put the original away. Every scan afterwards runs against the image. If a
   tool misbehaves — or the drive is dying and has a limited number of reads
   left — you have lost nothing.
3. **Never recover onto the source.** Writing recovered files back to the drive
   you are recovering from overwrites the very data you have not yet extracted.
   The destination must be a different physical device.

## Imaging first

For a healthy drive, any imager will do. For a failing one — clicking, slow,
throwing read errors — use `ddrescue`, which maps bad sectors and comes back for
them rather than stalling:

```bash
# First pass: grab everything that reads cleanly, skip trouble.
ddrescue -n /dev/sdX disk.img disk.map

# Second pass: retry the gaps, three attempts each.
ddrescue -d -r3 /dev/sdX disk.img disk.map
```

The map file makes the operation resumable. If it stops, rerun the same command
and it picks up where it left off. Keep that file.

`-n` on the first pass matters: it skips the scraping phase, so you capture the
bulk of a dying drive quickly, before it degrades further.

## Two kinds of recovery, and why the order matters

**Metadata recovery** reads the filesystem's own structures — MFT on NTFS,
inodes and directory entries on ext4. When it works you get original filenames,
full directory structure, and timestamps.

**Carving** ignores the filesystem and scans raw sectors for file signatures. It
works when the filesystem is gone, but it cannot recover names, paths, or dates,
and it cannot tell where a file ends.

**Always try metadata recovery first.** Filenames and folder structure are worth
more than the extra files carving finds, and you can always carve afterwards for
whatever metadata recovery missed.

In R-Studio this is the difference between the recognised partition tree (with
real names) and the "Extra Found Files" branch (carved, sequence-numbered). Work
the former before the latter.

## R-Studio notes

- **Scan the whole disk, not the partition**, when the partition table is
  damaged or a partition has vanished. R-Studio will propose recognised
  partitions afterwards, colour-coded by confidence.
- **Multiple overlapping partition candidates** for the same region are normal
  after a repartition. They represent different points in the drive's history.
  Check each; the one with the most plausible directory tree is usually the one
  you want.
- **Custom file signatures.** The built-in known-file-types list misses
  proprietary formats — CAD, camera raw variants, project files, older database
  formats. If a format you need is missing, defining its signature is usually
  the difference between recovering it and not.
- **Save the scan.** A full scan of a large disk takes hours. R-Studio can save
  scan results to a file; do it before you start extracting, so a crash does not
  cost you the whole run.

## Open-source tooling

Useful alongside R-Studio, and free:

| Tool | Use |
|---|---|
| `ddrescue` | Imaging failing media with a resumable bad-sector map |
| `testdisk` | Repairing partition tables, recovering lost partitions, boot sectors |
| `photorec` | Signature carving, ~480 file types, filesystem-independent |
| `fls` / `icat` / `tsk_recover` (Sleuth Kit) | Metadata-level recovery — keeps original filenames |
| `mmls` / `fsstat` | Partition layout and filesystem detail before committing to a scan |
| `foremost` | Carving with configurable signatures |

A Sleuth Kit metadata pass looks like this:

```bash
mmls disk.img                       # find partition offsets
fsstat -o 2048 disk.img             # confirm the filesystem
fls -o 2048 -rd disk.img            # list deleted entries, recursively
icat -o 2048 disk.img 12345 > out   # extract one file by inode
tsk_recover -o 2048 -e disk.img ./recovered/   # bulk extract
```

`-o` is the partition's start offset in sectors, taken from `mmls`.

## Then triage

Whatever route you took, you now have a directory of recovered files — either
with real names from metadata recovery, or sequence-numbered from carving. That
is where `rtriage` starts:

```bash
python -m rtriage scan ./recovered -o index.jsonl
python -m rtriage report index.jsonl --csv detail.csv
python -m rtriage organize index.jsonl --source ./recovered --dest ./sorted --execute
```

Read the report before organising. If almost everything comes back `truncated`,
the carve ended files too early and re-running with different settings will do
more good than sorting what you have. If most files are `corrupt`, the region
was overwritten and no scan configuration will change that — which is worth
knowing before spending another eight hours on it.

## Space planning

Recovery needs roughly three times the source size on hand: one copy for the
image, one for the carver's raw output, one for the sorted result. `organize
--move` removes the third of those, at the cost of not being able to re-run the
organise step against the original output.
