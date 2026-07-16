#!/usr/bin/env python3
"""Executable Python port of the public h5st VM dispatcher (entry 5134).

This module executes the real 75-cell tail of ``_2xnrh`` rather than a
hand-written high-level shortcut.  The dispatcher orchestrates ``_$cps``,
``_$rds``, ``_$clt`` and ``_$ms``; those four build-specific workers are
injected as host methods.  This makes the public VM independently testable and
keeps the remaining port boundary explicit.

The static extractor/disassembler in :mod:`vm_bundle` and
:mod:`vm_decompiler` covers every dispatcher.  Entries before 5134 still need
their CryptoJS/browser host operations to be bound before they can generate a
complete signature in a Python-only process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping

from vm_decompiler import VmBundle


class _Undefined:
    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


UNDEFINED = _Undefined()


@dataclass(frozen=True)
class NativeFunction:
    function: Callable[..., Any]
    receives_this: bool = False

    def call(self, this_value: Any, *args: Any) -> Any:
        if self.receives_this:
            return self.function(this_value, *args)
        return self.function(*args)


def native(function: Callable[..., Any], *, receives_this: bool = False) -> NativeFunction:
    return NativeFunction(function, receives_this)


def js_call(function: Any, this_value: Any, *args: Any) -> Any:
    if isinstance(function, NativeFunction):
        return function.call(this_value, *args)
    if callable(function):
        return function(*args)
    raise TypeError(f"{function!r} is not callable")


def js_string(value: Any) -> str:
    if value is UNDEFINED:
        return "undefined"
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _string_concat(this_value: Any, *values: Any) -> str:
    return js_string(this_value) + "".join(js_string(value) for value in values)


def get_property(value: Any, key: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, UNDEFINED)
    if isinstance(value, str) and key == "concat":
        return native(_string_concat, receives_this=True)
    if isinstance(value, (list, tuple)) and key == "length":
        return len(value)
    try:
        return getattr(value, key)
    except AttributeError:
        return UNDEFINED


def js_loose_equal(left: Any, right: Any) -> bool:
    if (left is None or left is UNDEFINED) and (right is None or right is UNDEFINED):
        return True
    return left == right


def object_assign(target: MutableMapping[str, Any], *sources: Any) -> MutableMapping[str, Any]:
    if target is None or target is UNDEFINED:
        raise TypeError("Cannot convert undefined or null to object")
    for source in sources:
        if source is None or source is UNDEFINED:
            continue
        if isinstance(source, Mapping):
            target.update(source)
        else:
            target.update(vars(source))
    return target


@dataclass
class FinalVmResult:
    value: Any
    trace: list[dict[str, Any]] = field(default_factory=list)
    debug_messages: list[str] = field(default_factory=list)


class FinalDispatcherVm:
    """Interpreter for ``_$fP.prototype._$sdnmd`` at bytecode entry 5134."""

    ENTRY = 5134

    def __init__(self, bundle: VmBundle | None = None) -> None:
        self.bundle = bundle or VmBundle.load()
        dispatcher = self.bundle.dispatcher(self.ENTRY)
        self.handlers = {handler["opcode"] for handler in dispatcher["handlers"]}
        expected = {
            5,
            7,
            9,
            12,
            17,
            19,
            21,
            25,
            31,
            33,
            34,
            37,
            38,
            39,
            41,
            42,
            45,
            47,
            48,
            50,
            52,
            54,
            55,
            59,
            63,
            72,
            74,
            81,
            82,
            88,
            91,
            92,
            96,
        }
        if self.handlers != expected:
            raise ValueError("entry 5134 metadata does not match the pinned build")

    @staticmethod
    def _invoke(stack: list[Any], argument_count: int) -> None:
        function_index = len(stack) - argument_count - 2
        if function_index < 0:
            raise RuntimeError("VM call stack underflow")
        function = stack[function_index]
        this_value = stack[function_index + 1]
        args = stack[function_index + 2 :]
        result = js_call(function, this_value, *args)
        stack[function_index:] = [result]

    def run(
        self,
        argument: Any,
        this_value: Mapping[str, Any] | Any,
        *,
        now_ms: Callable[[], int],
        decoder: Callable[[int], str] | None = None,
        max_steps: int = 1_000,
        collect_trace: bool = False,
    ) -> FinalVmResult:
        bytecode = self.bundle.bytecode
        strings = self.bundle.strings
        stack: list[Any] = []
        pc = self.ENTRY
        trace: list[dict[str, Any]] = []
        debug_messages: list[str] = []

        # Closed-over globals used by this dispatcher in the matching source.
        decoder = decoder or (lambda index: " sign elapsed time!" if index == 677 else f"<{index}>")
        date_object = {"now": native(now_ms)}

        def debug_log(enabled: Any, *messages: Any) -> None:
            if enabled:
                debug_messages.append("[sign] " + "".join(js_string(item) for item in messages))

        def invoke_helper(function: Any, *args: Any) -> Any:
            return js_call(function, UNDEFINED, *args)

        helper_object = {"xaWIQ": native(invoke_helper)}
        assign_function = native(object_assign)
        debug_function = native(debug_log)

        MT: Any = UNDEFINED
        local_fo: Any = UNDEFINED
        local_fG: Any = UNDEFINED
        local_fw: Any = UNDEFINED
        local_fL: Any = UNDEFINED

        for _ in range(max_steps):
            opcode_pc = pc
            opcode = bytecode[pc]
            pc += 1
            if opcode not in self.handlers:
                raise RuntimeError(f"unknown entry-5134 opcode {opcode} at {opcode_pc}")
            if collect_trace:
                trace.append(
                    {
                        "pc": opcode_pc,
                        "opcode": opcode,
                        "stack_depth": len(stack),
                        "stack": [repr(value) for value in stack],
                    }
                )

            if opcode == 5:
                stack.append(argument)
            elif opcode == 7:
                self._invoke(stack, 1)
            elif opcode == 9:
                MT = stack[-1]
            elif opcode == 12:
                stack.append(bytecode[pc])
                pc += 1
            elif opcode == 17:
                right = stack.pop()
                stack[-1] -= right
            elif opcode == 19:
                stack.append({})
            elif opcode == 21:
                local_fG = stack[-1]
            elif opcode == 25:
                stack.append(helper_object)
            elif opcode == 31:
                self._invoke(stack, 4)
            elif opcode == 33:
                right = stack.pop()
                stack[-1] = js_loose_equal(stack[-1], right)
            elif opcode == 34:
                stack.append(assign_function)
            elif opcode == 37:
                stack.append(local_fG)
            elif opcode == 38:
                return FinalVmResult(UNDEFINED, trace, debug_messages)
            elif opcode == 39:
                stack.append(native(decoder))
            elif opcode == 41:
                key = strings[365 + bytecode[pc]]
                pc += 1
                stack.append(get_property(this_value, str(key)))
            elif opcode == 42:
                local_fo = stack[-1]
            elif opcode == 45:
                self._invoke(stack, 0)
            elif opcode == 47:
                stack.append(local_fo)
            elif opcode == 48:
                stack.append(strings[365 + bytecode[pc]])
                pc += 1
            elif opcode == 50:
                return FinalVmResult(stack.pop(), trace, debug_messages)
            elif opcode == 52:
                key = str(strings[365 + bytecode[pc]])
                pc += 1
                receiver = stack[-1]
                stack.append(receiver)
                stack[-2] = get_property(receiver, key)
            elif opcode == 54:
                stack.append(date_object)
            elif opcode == 55:
                condition = bool(stack.pop())
                if condition:
                    pc += 1
                else:
                    pc += bytecode[pc]
            elif opcode == 59:
                stack.append(local_fw)
            elif opcode == 63:
                stack.pop()
            elif opcode == 72:
                stack.append(local_fL)
            elif opcode == 74:
                stack.append(None)
            elif opcode == 81:
                local_fw = stack[-1]
            elif opcode == 82:
                local_fL = stack[-1]
            elif opcode == 88:
                stack.append(this_value)
            elif opcode == 91:
                self._invoke(stack, 2)
            elif opcode == 92:
                stack.append(debug_function)
            elif opcode == 96:
                stack.append(MT)
        raise RuntimeError(f"entry 5134 exceeded {max_steps} steps")


def main() -> int:
    calls: list[list[Any]] = []
    argument = {"alpha": 1, "beta": "two"}
    fixed_now = 1_700_000_000_123

    def cps(value: Any) -> dict[str, str]:
        calls.append(["cps", value])
        return {"cps": "C"}

    def rds() -> str:
        calls.append(["rds"])
        return "R"

    def clt(value: int) -> str:
        calls.append(["clt", value])
        return "CLT"

    def ms(left: Any, right: Any) -> dict[str, Any]:
        calls.append(["ms", left, right])
        return {"vm": "PYTHON", "nested": {"ok": True}}

    context = {
        "_$cps": native(cps),
        "_$rds": native(rds),
        "_$clt": native(clt),
        "_$ms": native(ms),
        "_debug": False,
    }
    result = FinalDispatcherVm().run(argument, context, now_ms=lambda: fixed_now)
    import json

    print(json.dumps({"out": result.value, "calls": calls}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
