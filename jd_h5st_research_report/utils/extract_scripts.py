#!/usr/bin/env python3
"""Legacy command alias for the strict :mod:`vm_bundle` extraction CLI.

The previous version scraped one local HTML file for ``script`` tags and did
not extract a reproducible VM bundle.  The filename remains executable for old
workflows while all extraction now uses the source-bound lexical scanner.
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
