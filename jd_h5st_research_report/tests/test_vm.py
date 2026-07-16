from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
UTILS = ROOT / "utils"
if str(UTILS) not in sys.path:
    sys.path.insert(0, str(UTILS))

from h5st_vm import FinalDispatcherVm, native  # noqa: E402
from vm_bundle import (  # noqa: E402
    BundleError,
    EXPECTED_SOURCE_SHA256,
    OFFICIAL_SOURCE_SHA256,
    extract_bundle,
)
from vm_decompiler import VmBundle  # noqa: E402


ARCHIVES = ROOT / "archives"
SOURCE = ARCHIVES / "js_security_v3_0.1.4_cc4cf49.js"
OFFICIAL_SOURCE = ARCHIVES / "js_security_v3_0.1.4_20260527205706.js"
FIXTURE = ROOT / "tests" / "fixtures" / "final_vm.json"


class BundleExtractionTests(unittest.TestCase):
    def test_source_is_pinned_build(self) -> None:
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), EXPECTED_SOURCE_SHA256)
        self.assertEqual(
            hashlib.sha256(OFFICIAL_SOURCE.read_bytes()).hexdigest(),
            OFFICIAL_SOURCE_SHA256,
        )

    def test_official_and_readable_sources_extract_identically(self) -> None:
        readable = extract_bundle(SOURCE.read_bytes())
        official = extract_bundle(OFFICIAL_SOURCE.read_bytes())
        self.assertEqual(readable["strings"], official["strings"])
        self.assertEqual(readable["bytecode"], official["bytecode"])

        # Formatting and absolute source offsets differ between the minified
        # official snapshot and the readable upstream copy.  Every semantic
        # dispatcher field must still be identical.
        def semantic(dispatchers: list[dict]) -> list[dict]:
            result = []
            for dispatcher in dispatchers:
                result.append(
                    {
                        "entry": dispatcher["entry"],
                        "name": dispatcher["name"],
                        "args": dispatcher["args"],
                        "handlers": [
                            {
                                key: handler[key]
                                for key in (
                                    "opcode",
                                    "immediate_reads",
                                    "operand_cells",
                                    "flow",
                                    "string_base",
                                )
                            }
                            for handler in dispatcher["handlers"]
                        ],
                    }
                )
            return result

        self.assertEqual(semantic(readable["dispatchers"]), semantic(official["dispatchers"]))

    def test_unknown_source_hash_fails_fast(self) -> None:
        with self.assertRaisesRegex(BundleError, "source build mismatch"):
            extract_bundle(SOURCE.read_bytes() + b"\n")

    def test_extraction_matches_committed_assets(self) -> None:
        bundle = extract_bundle(SOURCE.read_bytes())
        self.assertEqual(
            bundle["strings"],
            json.loads((ARCHIVES / "h5st_string_table.json").read_text("utf-8")),
        )
        self.assertEqual(
            bundle["bytecode"],
            json.loads((ARCHIVES / "h5st_bytecode.json").read_text("utf-8")),
        )
        self.assertEqual(len(bundle["dispatchers"]), 34)

    def test_every_dispatcher_has_a_valid_cfg(self) -> None:
        counts = VmBundle.load().validate_all()
        self.assertEqual(len(counts), 34)
        self.assertEqual(counts[5134], 62)
        self.assertGreater(sum(counts.values()), 3_500)


class FinalDispatcherDifferentialTests(unittest.TestCase):
    def python_result(self) -> dict:
        fixture = json.loads(FIXTURE.read_text("utf-8"))
        calls: list[list[object]] = []

        def cps(argument: object) -> object:
            calls.append(["cps", argument])
            return fixture["cps_result"]

        def rds() -> str:
            calls.append(["rds"])
            return "R"

        def clt(timestamp: int) -> object:
            calls.append(["clt", timestamp])
            return fixture["clt_result"]

        def ms(left: object, right: object) -> object:
            calls.append(["ms", left, right])
            return fixture["ms_result"]

        context = {
            "_$cps": native(cps),
            "_$rds": native(rds),
            "_$clt": native(clt),
            "_$ms": native(ms),
            "_debug": False,
        }
        result = FinalDispatcherVm().run(
            fixture["argument"], context, now_ms=lambda: fixture["fixed_now"]
        )
        return {"out": result.value, "calls": calls}

    def test_python_vm_expected_result(self) -> None:
        self.assertEqual(
            self.python_result(),
            {
                "out": {
                    "alpha": 1,
                    "beta": "two",
                    "vm": "PYTHON",
                    "nested": {"ok": True},
                },
                "calls": [
                    ["cps", {"alpha": 1, "beta": "two"}],
                    ["rds"],
                    ["clt", 1_700_000_000_123],
                    ["ms", {"cps": "C"}, "CLT"],
                ],
            },
        )

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for JS differential")
    def test_python_matches_original_js_dispatcher(self) -> None:
        script = ROOT / "tests" / "js" / "final_vm_reference.js"
        process = subprocess.run(
            ["node", str(script), str(FIXTURE)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        javascript_result = json.loads(process.stdout)
        self.assertEqual(self.python_result(), javascript_result)


if __name__ == "__main__":
    unittest.main()
