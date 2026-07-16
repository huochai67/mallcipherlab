#!/usr/bin/env python3
"""Compatibility entry point for :mod:`vm_bundle`.

Historically this filename contained a second, regex-based VM extractor.  Keep
the command name for existing notes and shell snippets, but route every build
check, lexical scan and artifact write through the canonical implementation.
"""

from __future__ import annotations

from collections.abc import Iterable

try:  # Direct script execution (``python utils/extract_vm_data.py``).
    from vm_bundle import main as _bundle_main
except ImportError:  # Module execution/import from a namespace package.
    from .vm_bundle import main as _bundle_main


def main(argv: Iterable[str] | None = None) -> int:
    """Run the canonical VM bundle extraction CLI."""

    return _bundle_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
