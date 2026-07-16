#!/usr/bin/env python3
"""Control-flow disassembler for the build-bound JD h5st stack VM.

The disassembler follows both sides of every conditional branch and all arms
of VM switch tables.  This avoids treating nested-function bytecode/data cells
as opcodes, a common error when the 5,209-cell array is decoded linearly.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class Instruction:
    pc: int
    opcode: int
    operand_pc: int
    operands: tuple[int, ...]
    string_operands: tuple[str | int, ...]
    successors: tuple[int, ...]
    flow: str
    handler_body: str


class DecodeError(ValueError):
    pass


class VmBundle:
    def __init__(
        self,
        strings: list[str | int],
        bytecode: list[int],
        dispatchers: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> None:
        self.strings = strings
        self.bytecode = bytecode
        self.dispatchers = {item["entry"]: item for item in dispatchers}
        self.manifest = manifest

    @classmethod
    def load(cls, archive_dir: Path | None = None) -> "VmBundle":
        if archive_dir is None:
            archive_dir = Path(__file__).resolve().parents[1] / "archives"
        return cls(
            json.loads((archive_dir / "h5st_string_table.json").read_text("utf-8")),
            json.loads((archive_dir / "h5st_bytecode.json").read_text("utf-8")),
            json.loads((archive_dir / "h5st_vm_dispatchers.json").read_text("utf-8")),
            json.loads((archive_dir / "h5st_vm_manifest.json").read_text("utf-8")),
        )

    def dispatcher(self, entry: int) -> dict[str, Any]:
        try:
            return self.dispatchers[entry]
        except KeyError as exc:
            raise DecodeError(f"unknown dispatcher entry {entry}") from exc

    def _cell(self, pc: int) -> int:
        if not 0 <= pc < len(self.bytecode):
            raise DecodeError(f"bytecode address outside array: {pc}")
        return self.bytecode[pc]

    def decode_instruction(self, entry: int, pc: int) -> Instruction:
        dispatcher = self.dispatcher(entry)
        handlers = {handler["opcode"]: handler for handler in dispatcher["handlers"]}
        opcode = self._cell(pc)
        try:
            handler = handlers[opcode]
        except KeyError as exc:
            raise DecodeError(
                f"entry {entry}: cell {pc} contains opcode {opcode}, "
                "which is absent from this dispatcher"
            ) from exc

        operand_pc = pc + 1
        flow = handler["flow"]
        width = handler["operand_cells"]
        operands: tuple[int, ...]
        successors: tuple[int, ...]

        if flow == "switch":
            default_delta = self._cell(operand_pc)
            count = self._cell(operand_pc + 1)
            if count < 0 or count > 256:
                raise DecodeError(
                    f"entry {entry}: implausible switch width {count} at {operand_pc}"
                )
            width = 2 + count * 2
            operands = tuple(self._cell(operand_pc + index) for index in range(width))
            targets = [operand_pc + default_delta]
            targets.extend(
                operand_pc + operands[3 + index * 2] for index in range(count)
            )
            successors = tuple(dict.fromkeys(targets))
        else:
            if width < 0:
                raise DecodeError(f"entry {entry}: bad operand width for opcode {opcode}")
            operands = tuple(self._cell(operand_pc + index) for index in range(width))
            if flow == "return":
                successors = ()
            elif flow == "jump":
                successors = (operand_pc + operands[0],)
            elif flow == "jump_back":
                successors = (operand_pc - operands[0],)
            elif flow == "branch":
                successors = tuple(
                    dict.fromkeys((operand_pc + 1, operand_pc + operands[0]))
                )
            elif flow == "branch_back":
                successors = tuple(
                    dict.fromkeys((operand_pc + 1, operand_pc - operands[0]))
                )
            elif flow == "next":
                successors = (operand_pc + width,)
            else:  # pragma: no cover - corrupt generated metadata
                raise DecodeError(f"entry {entry}: unsupported flow {flow!r}")

        string_base = handler.get("string_base")
        if string_base is None:
            string_operands: tuple[str | int, ...] = ()
        elif flow == "switch":
            count = operands[1]
            resolved: list[str | int] = []
            for index in range(count):
                string_index = string_base + operands[2 + index * 2]
                if not 0 <= string_index < len(self.strings):
                    raise DecodeError(
                        f"entry {entry}: string index {string_index} outside table"
                    )
                resolved.append(self.strings[string_index])
            string_operands = tuple(resolved)
        else:
            resolved = []
            for operand in operands[: handler["immediate_reads"]]:
                string_index = string_base + operand
                if not 0 <= string_index < len(self.strings):
                    raise DecodeError(
                        f"entry {entry}: string index {string_index} outside table"
                    )
                resolved.append(self.strings[string_index])
            string_operands = tuple(resolved)

        return Instruction(
            pc=pc,
            opcode=opcode,
            operand_pc=operand_pc,
            operands=operands,
            string_operands=string_operands,
            successors=successors,
            flow=flow,
            handler_body=handler["body"],
        )

    def decode_dispatcher(self, entry: int, *, limit: int = 20_000) -> list[Instruction]:
        pending = [entry]
        decoded: dict[int, Instruction] = {}
        while pending:
            pc = pending.pop()
            if pc in decoded:
                continue
            if len(decoded) >= limit:
                raise DecodeError(f"entry {entry}: instruction limit {limit} exceeded")
            instruction = self.decode_instruction(entry, pc)
            decoded[pc] = instruction
            for successor in instruction.successors:
                if not 0 <= successor < len(self.bytecode):
                    raise DecodeError(
                        f"entry {entry}: target {successor} from {pc} is outside bytecode"
                    )
                if successor not in decoded:
                    pending.append(successor)
        return [decoded[pc] for pc in sorted(decoded)]

    def validate_all(self) -> dict[int, int]:
        return {
            entry: len(self.decode_dispatcher(entry)) for entry in sorted(self.dispatchers)
        }


def format_instruction(instruction: Instruction, *, include_handler: bool = False) -> str:
    operands = " ".join(str(value) for value in instruction.operands)
    strings = ""
    if instruction.string_operands:
        strings = " ; strings=" + ", ".join(repr(item) for item in instruction.string_operands)
    targets = ""
    if instruction.flow != "next":
        targets = f" ; {instruction.flow} -> {list(instruction.successors)}"
    line = f"{instruction.pc:04d}: op={instruction.opcode:02d}"
    if operands:
        line += f" operands=[{operands}]"
    line += strings + targets
    if include_handler:
        compact = " ".join(instruction.handler_body.split())
        line += f"\n      {compact}"
    return line


def main(argv: Iterable[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entry", nargs="?", type=int)
    parser.add_argument("--handlers", action="store_true")
    parser.add_argument("--validate-all", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    bundle = VmBundle.load()
    if args.validate_all or args.entry is None:
        counts = bundle.validate_all()
        for entry, count in counts.items():
            print(f"{entry:04d}: {count} reachable instructions")
        if args.entry is None:
            return 0
    assert args.entry is not None
    dispatcher = bundle.dispatcher(args.entry)
    print(f"# {dispatcher['name']} entry={args.entry}")
    for instruction in bundle.decode_dispatcher(args.entry):
        print(format_instruction(instruction, include_handler=args.handlers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
