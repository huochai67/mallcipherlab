#!/usr/bin/env python3
"""Inspect the string table extracted by the canonical VM bundle scanner.

This is a read-only compatibility view.  Parsing, XOR-43 decoding, delimiter
handling, build identity checks and structural validation all come from
``vm_bundle``; this file intentionally contains no parallel regex extractor.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import json
from pathlib import Path
import sys

try:
    from vm_bundle import BundleError, default_source, extract_bundle
except ImportError:
    from .vm_bundle import BundleError, default_source, extract_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        default=default_source(),
        help="JavaScript source (default: the archived supported build)",
    )
    parser.add_argument(
        "--allow-other-build",
        action="store_true",
        help="skip the source SHA check; structural bundle checks still run",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="include numeric table cells as well as decoded strings",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the selected indexed entries as JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="also write the complete canonical string table as JSON",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """Validate the VM bundle and display its decoded string-table entries."""

    parser = _parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        bundle = extract_bundle(
            args.source.read_bytes(), validate_source=not args.allow_other_build
        )
    except (OSError, UnicodeError, BundleError) as exc:
        parser.error(str(exc))

    table = bundle["strings"]
    selected = [
        {"index": index, "value": value}
        for index, value in enumerate(table)
        if args.all or isinstance(value, str)
    ]

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(table, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    if args.json:
        json.dump(selected, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"Decoded {len(table)} entries "
            f"({len(selected)} {'all entries' if args.all else 'strings'})"
        )
        for entry in selected:
            print(f"  [{entry['index']}] = {entry['value']!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
