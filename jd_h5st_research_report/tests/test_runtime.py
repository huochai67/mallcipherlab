from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
UTILS = ROOT / "utils"
if str(UTILS) not in sys.path:
    sys.path.insert(0, str(UTILS))

import h5st_runtime  # noqa: E402


FIXTURE = ROOT / "tests" / "fixtures" / "golden_h5st.json"
HAS_QUICKJS = importlib.util.find_spec("quickjs") is not None


class RuntimeAssetTests(unittest.TestCase):
    def test_all_assets_are_bound_to_the_manifest(self) -> None:
        manifest = h5st_runtime.verify_assets()
        self.assertEqual(manifest["dispatcher_count"], 34)
        self.assertEqual(manifest["official_source_sha256"], h5st_runtime.OFFICIAL_SHA256)

    def test_corrupt_execution_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / "source.js"
            corrupt.write_text("var ParamsSign = null;", "utf-8")
            with mock.patch.object(h5st_runtime, "SOURCE", corrupt):
                with self.assertRaises(h5st_runtime.AssetMismatchError):
                    h5st_runtime.verify_assets()


@unittest.skipUnless(HAS_QUICKJS, "quickjs==1.19.4 is required for runtime tests")
class QuickJsRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text("utf-8"))

    def generate(self) -> dict:
        return h5st_runtime.generate_h5st(
            self.fixture["app_id"],
            self.fixture["params"],
            **self.fixture["options"],
        )

    def test_offline_signature_matches_golden_fixture(self) -> None:
        result = self.generate()
        self.assertEqual(result, self.fixture["expected"])
        h5st = result["h5st"]
        self.assertEqual(hashlib.sha256(h5st.encode()).hexdigest(), self.fixture["expected_h5st_sha256"])
        self.assertEqual([len(part) for part in h5st.split(";")], self.fixture["part_lengths"])

    def test_fixed_clock_and_prng_are_deterministic(self) -> None:
        self.assertEqual(self.generate(), self.generate())

    @unittest.skipUnless(shutil.which("node"), "Node.js is used only as a differential oracle")
    def test_node_oracle_agrees_on_signed_fields(self) -> None:
        command = [
            "node",
            str(UTILS / "h5st_generator.js"),
            self.fixture["app_id"],
            json.dumps(self.fixture["params"], separators=(",", ":")),
            str(self.fixture["options"]["now_ms"]),
            str(self.fixture["options"]["seed"]),
        ]
        process = subprocess.run(
            command,
            cwd=ROOT.parent,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        node_result = json.loads(process.stdout)
        python_result = self.generate()
        node_parts = node_result["h5st"].split(";")
        python_parts = python_result["h5st"].split(";")
        self.assertEqual(node_parts[:7], python_parts[:7])
        self.assertEqual(node_parts[8:], python_parts[8:])
        differences = sum(a != b for a, b in zip(node_parts[7], python_parts[7]))
        self.assertEqual(len(node_parts[7]), len(python_parts[7]))
        self.assertEqual(differences, 1)


if __name__ == "__main__":
    unittest.main()
