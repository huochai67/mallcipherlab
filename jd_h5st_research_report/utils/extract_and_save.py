#!/usr/bin/env python3
"""Legacy command alias for the build-bound :mod:`vm_bundle` extractor.

The canonical CLI writes the decoded string table, bytecode cells, dispatcher
metadata and manifest together so artifacts from different builds are never
silently combined.
"""

from __future__ import annotations

from collections.abc import Iterable

try:
    from vm_bundle import main as _bundle_main
except ImportError:
    from .vm_bundle import main as _bundle_main


def main(argv: Iterable[str] | None = None) -> int:
    """Run the canonical VM bundle extraction CLI."""

    return _bundle_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
