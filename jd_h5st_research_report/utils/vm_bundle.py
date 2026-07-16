#!/usr/bin/env python3
"""Extract the build-bound JD h5st VM bundle from its JavaScript source.

The VM opcodes are randomized for every obfuscator build.  Consequently a
bytecode array, string table and the dispatcher ``switch`` statements form one
indivisible bundle.  This module deliberately validates and extracts all three
parts from the same source file.

It is a small lexical extractor rather than a JavaScript parser.  The source
uses a regular, minifier-generated grammar and the scanner still handles quoted
strings, comments and nested braces/brackets so a ``]`` inside an encoded
string never truncates the table (the bug in the original extractor).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Iterator


READABLE_UPSTREAM_URL = "https://github.com/kb-ywl/h5st-.git"
READABLE_UPSTREAM_COMMIT = "cc4cf495fe1047f31ac621d5bb9345853b403f98"
READABLE_UPSTREAM_PATH = "jd_h5st/jd_mod.js"
READABLE_ARCHIVE_PATH = "archives/js_security_v3_0.1.4_cc4cf49.js"
READABLE_SOURCE_SHA256 = (
    "bbe0f7569bc1823dcc90d7f41d9e28e7f5cc839704afb6ea1576a297ce1a3c78"
)
EXPECTED_NORMALIZED_SOURCE_SHA256 = (
    "cbe12977aadb5618ddca2616f4f89295bbc8c20fb4f7684d38a1d5aff81b1eca"
)
OFFICIAL_SNAPSHOT_URL = (
    "https://web.archive.org/web/20260527205706id_/"
    "https://storage.360buyimg.com/webcontainer/js_security_v3_0.1.4.js"
)
OFFICIAL_ARCHIVE_PATH = "archives/js_security_v3_0.1.4_20260527205706.js"
OFFICIAL_SOURCE_SHA256 = (
    "78ff71158c7dc6284a0ab381370be33bc8fb8fd7f25571745330848eb766c331"
)
SUPPORTED_SOURCE_SHA256 = frozenset(
    {READABLE_SOURCE_SHA256, OFFICIAL_SOURCE_SHA256}
)

# Backward-compatible names used by earlier callers/tests.
UPSTREAM_URL = READABLE_UPSTREAM_URL
UPSTREAM_COMMIT = READABLE_UPSTREAM_COMMIT
UPSTREAM_PATH = READABLE_UPSTREAM_PATH
EXPECTED_SOURCE_SHA256 = READABLE_SOURCE_SHA256
EXPECTED_BYTECODE_COUNT = 5209
EXPECTED_STRING_COUNT = 374


class BundleError(ValueError):
    """Raised when source and VM assets do not belong to the expected build."""


@dataclass(frozen=True)
class FunctionSpan:
    start: int
    open_brace: int
    end: int
    name: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class Handler:
    opcode: int
    body: str
    immediate_reads: int
    operand_cells: int
    flow: str
    string_base: int | None


@dataclass(frozen=True)
class Dispatcher:
    entry: int
    name: str
    args: tuple[str, ...]
    array_alias: str
    pc_name: str
    stack_name: str | None
    call_alias: str | None
    source_start: int
    source_end: int
    handlers: tuple[Handler, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _skip_quoted(source: str, pos: int) -> int:
    """Return the first position after a JS quoted/template string."""

    quote = source[pos]
    pos += 1
    while pos < len(source):
        char = source[pos]
        if char == "\\":
            pos += 2
            continue
        pos += 1
        if char == quote:
            return pos
    raise BundleError("unterminated JavaScript string")


def matching_delimiter(source: str, open_pos: int) -> int:
    """Find a matching ``]``, ``}`` or ``)`` while ignoring JS strings/comments."""

    pairs = {"[": "]", "{": "}", "(": ")"}
    opener = source[open_pos]
    try:
        closer = pairs[opener]
    except KeyError as exc:  # pragma: no cover - caller programming error
        raise BundleError(f"unsupported delimiter {opener!r}") from exc

    depth = 1
    pos = open_pos + 1
    while pos < len(source):
        char = source[pos]
        nxt = source[pos + 1] if pos + 1 < len(source) else ""
        if char in "'\"`":
            pos = _skip_quoted(source, pos)
            continue
        if char == "/" and nxt == "/":
            newline = source.find("\n", pos + 2)
            pos = len(source) if newline < 0 else newline + 1
            continue
        if char == "/" and nxt == "*":
            end = source.find("*/", pos + 2)
            if end < 0:
                raise BundleError("unterminated JavaScript comment")
            pos = end + 2
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return pos
        pos += 1
    raise BundleError(f"unterminated {opener!r} at offset {open_pos}")


def extract_array_source(source: str, variable: str) -> str:
    match = re.search(rf"\bvar\s+{re.escape(variable)}\s*=\s*\[", source)
    if not match:
        raise BundleError(f"array {variable!r} was not found")
    open_pos = source.find("[", match.start(), match.end())
    close_pos = matching_delimiter(source, open_pos)
    return source[open_pos + 1 : close_pos]


def decode_xor43(value: str) -> str:
    """Decode the source's ``_4uxrh`` string representation."""

    output: list[str] = []
    pos = 0
    while pos < len(value):
        code = ord(value[pos])
        pos += 1
        if code > 63:
            output.append(chr(code ^ 43))
        elif code == 35:  # '#': quote the following character
            if pos >= len(value):
                raise BundleError("truncated # escape in encoded string")
            output.append(value[pos])
            pos += 1
        else:
            output.append(chr(code))
    return "".join(output)


_JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def parse_string_table(raw: str, decoder: str = "_4uxrh") -> list[str | int]:
    values: list[str | int] = []
    pos = 0
    while pos < len(raw):
        while pos < len(raw) and raw[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(raw):
            break
        prefix = f"{decoder}("
        if raw.startswith(prefix, pos):
            string_match = _JSON_STRING.match(raw, pos + len(prefix))
            if not string_match:
                raise BundleError(f"bad encoded string at table offset {pos}")
            end = string_match.end()
            while end < len(raw) and raw[end].isspace():
                end += 1
            if end >= len(raw) or raw[end] != ")":
                raise BundleError(f"missing decoder close parenthesis at {end}")
            values.append(decode_xor43(json.loads(string_match.group(0))))
            pos = end + 1
            continue
        if raw[pos] == '"':
            string_match = _JSON_STRING.match(raw, pos)
            if not string_match:
                raise BundleError(f"bad plain string at table offset {pos}")
            values.append(json.loads(string_match.group(0)))
            pos = string_match.end()
            continue
        number = re.match(r"-?\d+", raw[pos:])
        if not number:
            raise BundleError(f"unsupported table item at {pos}: {raw[pos:pos+40]!r}")
        values.append(int(number.group(0)))
        pos += number.end()
    return values


def parse_integer_array(raw: str) -> list[int]:
    values: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if not re.fullmatch(r"-?\d+", item):
            raise BundleError(f"non-integer bytecode cell: {item!r}")
        values.append(int(item))
    return values


def _function_spans(source: str) -> list[FunctionSpan]:
    pattern = re.compile(r"\bfunction\s*([$\w]*)\s*\(([^)]*)\)\s*\{")
    spans: list[FunctionSpan] = []
    for match in pattern.finditer(source):
        open_brace = source.find("{", match.start(), match.end())
        end = matching_delimiter(source, open_brace)
        prefix = source[max(0, match.start() - 160) : match.start()]
        assigned = re.search(
            r"([$\w]+(?:\.prototype\.[$\w]+)?)\s*=\s*$", prefix
        )
        name = assigned.group(1) if assigned else (match.group(1) or "<anonymous>")
        args = tuple(arg.strip() for arg in match.group(2).split(",") if arg.strip())
        spans.append(FunctionSpan(match.start(), open_brace, end, name, args))
    return spans


def _top_level_cases(source: str, open_brace: int, close_brace: int) -> list[tuple[int, int]]:
    """Return ``(opcode, colon_position)`` for cases at switch depth zero."""

    result: list[tuple[int, int]] = []
    depth = 0
    pos = open_brace + 1
    while pos < close_brace:
        char = source[pos]
        nxt = source[pos + 1] if pos + 1 < close_brace else ""
        if char in "'\"`":
            pos = _skip_quoted(source, pos)
            continue
        if char == "/" and nxt == "/":
            newline = source.find("\n", pos + 2, close_brace)
            pos = close_brace if newline < 0 else newline + 1
            continue
        if char == "/" and nxt == "*":
            end = source.find("*/", pos + 2, close_brace)
            if end < 0:
                raise BundleError("unterminated comment in switch")
            pos = end + 2
            continue
        if char == "{":
            depth += 1
            pos += 1
            continue
        if char == "}":
            depth -= 1
            pos += 1
            continue
        if depth == 0 and source.startswith("case", pos):
            before = source[pos - 1] if pos else " "
            after = source[pos + 4] if pos + 4 < len(source) else " "
            if not (before.isalnum() or before in "_$") and not (
                after.isalnum() or after in "_$"
            ):
                match = re.match(r"case\s+(-?\d+)\s*:", source[pos:close_brace])
                if match:
                    result.append((int(match.group(1)), pos + match.end()))
                    pos += match.end()
                    continue
        pos += 1
    return result


def _compact_js(body: str) -> str:
    return re.sub(r"\s+", " ", body).strip()


def _without_nested_functions(body: str) -> str:
    """Blank nested function bodies while preserving enclosing case control flow."""

    chars = list(body)
    pattern = re.compile(r"\bfunction\s*[$\w]*\s*\([^)]*\)\s*\{")
    search_from = 0
    while True:
        match = pattern.search(body, search_from)
        if not match:
            break
        open_brace = body.find("{", match.start(), match.end())
        end = matching_delimiter(body, open_brace)
        chars[match.start() : end + 1] = " " * (end + 1 - match.start())
        search_from = end + 1
    return "".join(chars)


def _classify_handler(body: str, array: str, pc: str) -> tuple[int, int, str, int | None]:
    compact = _compact_js(_without_nested_functions(body))
    array_re = re.escape(array)
    pc_re = re.escape(pc)

    # Direct post-increment operand reads.  Repeated occurrences genuinely read
    # repeated cells; string-table reads also use this form.
    immediate_reads = len(re.findall(rf"\b{array_re}\s*\[\s*{pc_re}\+\+\s*\]", compact))
    string_bases = [
        int(value)
        for value in re.findall(
            rf"_1hbrh\s*\[\s*(\d+)\s*\+\s*{array_re}\s*\[\s*{pc_re}\+\+\s*\]\s*\]",
            compact,
        )
    ]
    string_base = string_bases[0] if string_bases and len(set(string_bases)) == 1 else None

    if re.search(r"\breturn(?:\s|;)", compact):
        flow = "return"
    elif re.search(rf"\b{pc_re}\s*\+=\s*{array_re}\s*\[\s*{pc_re}\s*\]", compact):
        flow = "branch" if "if" in compact else "jump"
    elif re.search(rf"\b{pc_re}\s*-=\s*{array_re}\s*\[\s*{pc_re}\s*\]", compact):
        flow = "branch_back" if "if" in compact else "jump_back"
    else:
        flow = "next"

    # Branch offsets are addressed at pc without post-increment and therefore
    # occupy one cell even though immediate_reads is zero.
    operand_cells = immediate_reads
    if flow in {"branch", "jump", "branch_back", "jump_back"}:
        operand_cells = max(operand_cells, 1)

    # VM switch tables: default_delta, count, then count pairs of
    # (string_index, relative_delta).  Their width is data-dependent and is
    # represented as -1 for the CFG decoder.
    if re.search(rf"{array_re}\s*\[\s*{pc_re}\s*\+\s*1\s*\]", compact) and re.search(
        r"continue\s+l\d+", compact
    ):
        flow = "switch"
        operand_cells = -1

    return immediate_reads, operand_cells, flow, string_base


def extract_dispatchers(source: str, bytecode_variable: str = "_2xnrh") -> list[Dispatcher]:
    functions = _function_spans(source)
    switch_pattern = re.compile(
        r"\bswitch\s*\(\s*([$\w]+)\s*\[\s*([$\w]+)\+\+\s*\]\s*\)\s*\{"
    )
    dispatchers: list[Dispatcher] = []
    for switch_match in switch_pattern.finditer(source):
        switch_pos = switch_match.start()
        owners = [span for span in functions if span.start < switch_pos < span.end]
        if not owners:
            continue
        owner = min(owners, key=lambda span: span.end - span.start)
        prefix = source[owner.open_brace + 1 : switch_pos]
        array_alias, pc_name = switch_match.group(1), switch_match.group(2)
        if not re.search(
            rf"\bvar\s+{re.escape(array_alias)}\s*=\s*{re.escape(bytecode_variable)}\s*;",
            prefix,
        ):
            continue
        starts = list(
            re.finditer(rf"\bvar\s+{re.escape(pc_name)}\s*=\s*(\d+)\s*;", prefix)
        )
        if not starts:
            raise BundleError(f"dispatcher at {switch_pos} has no constant entry")
        entry = int(starts[-1].group(1))

        stack_matches = list(re.finditer(r"\bvar\s+([$\w]+)\s*=\s*\[\s*\]\s*;", prefix))
        stack_name = stack_matches[-1].group(1) if stack_matches else None
        call_matches = list(
            re.finditer(r"\bvar\s+([$\w]+)\s*=\s*_3a8rh\s*;", prefix)
        )
        call_alias = call_matches[-1].group(1) if call_matches else None

        switch_open = source.find("{", switch_match.start(), switch_match.end())
        switch_end = matching_delimiter(source, switch_open)
        labels = _top_level_cases(source, switch_open, switch_end)
        handlers: list[Handler] = []
        for index, (opcode, body_start) in enumerate(labels):
            body_end = labels[index + 1][1] if index + 1 < len(labels) else switch_end
            if index + 1 < len(labels):
                # The next label tuple stores its colon position.  Locate the
                # beginning of the textual `case` token so it is not included.
                next_colon = labels[index + 1][1]
                case_start = source.rfind("case", body_start, next_colon)
                body_end = case_start
            body = source[body_start:body_end].strip()
            immediate_reads, operand_cells, flow, string_base = _classify_handler(
                body, array_alias, pc_name
            )
            handlers.append(
                Handler(
                    opcode=opcode,
                    body=body,
                    immediate_reads=immediate_reads,
                    operand_cells=operand_cells,
                    flow=flow,
                    string_base=string_base,
                )
            )

        name = owner.name if owner.name != "<anonymous>" else f"vm_{entry:04d}"
        dispatchers.append(
            Dispatcher(
                entry=entry,
                name=name,
                args=owner.args,
                array_alias=array_alias,
                pc_name=pc_name,
                stack_name=stack_name,
                call_alias=call_alias,
                source_start=owner.start,
                source_end=owner.end,
                handlers=tuple(sorted(handlers, key=lambda handler: handler.opcode)),
            )
        )
    return sorted(dispatchers, key=lambda dispatcher: dispatcher.entry)


def extract_bundle(source_bytes: bytes, *, validate_source: bool = True) -> dict[str, Any]:
    source_hash = sha256_bytes(source_bytes)
    if validate_source and source_hash not in SUPPORTED_SOURCE_SHA256:
        raise BundleError(
            "source build mismatch: expected one of "
            f"{sorted(SUPPORTED_SOURCE_SHA256)}, received {source_hash}"
        )
    source = source_bytes.decode("utf-8")
    normalized_source_hash = sha256_bytes(
        source.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    )
    strings = parse_string_table(extract_array_source(source, "_1hbrh"))
    bytecode = parse_integer_array(extract_array_source(source, "_2xnrh"))
    dispatchers = extract_dispatchers(source)
    if len(strings) != EXPECTED_STRING_COUNT:
        raise BundleError(f"expected {EXPECTED_STRING_COUNT} strings, extracted {len(strings)}")
    if len(bytecode) != EXPECTED_BYTECODE_COUNT:
        raise BundleError(
            f"expected {EXPECTED_BYTECODE_COUNT} bytecode cells, extracted {len(bytecode)}"
        )
    entries = [dispatcher.entry for dispatcher in dispatchers]
    if len(entries) != 34 or entries[-1] != 5134:
        raise BundleError(f"unexpected dispatcher entries: {entries}")

    bytecode_json = json.dumps(bytecode, separators=(",", ":")).encode("ascii")
    strings_json = json.dumps(
        strings, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return {
        "manifest": {
            "schema": 1,
            "official_snapshot_url": OFFICIAL_SNAPSHOT_URL,
            "official_source_sha256": OFFICIAL_SOURCE_SHA256,
            "official_archive_path": OFFICIAL_ARCHIVE_PATH,
            "readable_upstream_url": READABLE_UPSTREAM_URL,
            "readable_upstream_commit": READABLE_UPSTREAM_COMMIT,
            "readable_upstream_path": READABLE_UPSTREAM_PATH,
            "readable_source_sha256": READABLE_SOURCE_SHA256,
            "readable_archive_path": READABLE_ARCHIVE_PATH,
            "extracted_from": (
                "official_snapshot"
                if source_hash == OFFICIAL_SOURCE_SHA256
                else "readable_upstream"
            ),
            "source_sha256": source_hash,
            "normalized_source_sha256": normalized_source_hash,
            "bytecode_count": len(bytecode),
            "bytecode_json_sha256": sha256_bytes(bytecode_json),
            "string_count": len(strings),
            "string_json_sha256": sha256_bytes(strings_json),
            "dispatcher_count": len(dispatchers),
            "dispatcher_entries": entries,
        },
        "strings": strings,
        "bytecode": bytecode,
        "dispatchers": [asdict(dispatcher) for dispatcher in dispatchers],
    }


def write_bundle(bundle: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "h5st_string_table.json").write_text(
        json.dumps(bundle["strings"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "h5st_bytecode.json").write_text(
        json.dumps(bundle["bytecode"], separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (output_dir / "h5st_vm_manifest.json").write_text(
        json.dumps(bundle["manifest"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "h5st_vm_dispatchers.json").write_text(
        json.dumps(bundle["dispatchers"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def default_source() -> Path:
    return Path(__file__).resolve().parents[1] / "archives" / "js_security_v3_0.1.4_cc4cf49.js"


def main(argv: Iterable[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=default_source())
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "archives",
    )
    parser.add_argument(
        "--allow-other-build",
        action="store_true",
        help="skip the source SHA check (structural counts are still checked)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    bundle = extract_bundle(
        args.source.read_bytes(), validate_source=not args.allow_other_build
    )
    write_bundle(bundle, args.output_dir)
    print(
        f"extracted {len(bundle['strings'])} strings, "
        f"{len(bundle['bytecode'])} cells and "
        f"{len(bundle['dispatchers'])} dispatchers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
