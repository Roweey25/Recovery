"""rtriage - make sense of what a file carver spat out.

R-Studio, photorec and foremost all recover far more files than they recover
*usable* files. This package sorts the difference: it validates each file
against its own format's structure, drops duplicate copies of the same bytes,
and files the survivors into a tree organised by whether you can open them.

Stdlib only, so it runs wherever Python does - including next to R-Studio on
the Windows box holding the recovery output.
"""

__version__ = "0.1.0"

__all__ = ["formats", "meta", "scan", "organize", "cli"]
