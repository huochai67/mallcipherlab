#!/usr/bin/env python3
"""Offline Python entry point for the pinned h5st 5.3 VM build.

The official JavaScript VM is evaluated by the in-process ``quickjs`` Python
extension.  No Node subprocess or network request is used.  Static extraction,
CFG recovery and the native entry-5134 interpreter live in ``vm_bundle.py``,
``vm_decompiler.py`` and ``h5st_vm.py`` respectively.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
ARCHIVES = ROOT / "archives"
SOURCE = ARCHIVES / "js_security_v3_0.1.4_20260527205706.js"
READABLE_SOURCE = ARCHIVES / "js_security_v3_0.1.4_cc4cf49.js"
SHIM = Path(__file__).with_name("browser_shim.js")
MANIFEST = ARCHIVES / "h5st_vm_manifest.json"

OFFICIAL_SHA256 = "78ff71158c7dc6284a0ab381370be33bc8fb8fd7f25571745330848eb766c331"
READABLE_SHA256 = "bbe0f7569bc1823dcc90d7f41d9e28e7f5cc839704afb6ea1576a297ce1a3c78"
BYTECODE_SEMANTIC_SHA256 = "38e5fef28ac880e1d3b6203f354c5ff26d625b8f90737eb25895201fa83633d0"
STRING_SEMANTIC_SHA256 = "6cc5c66c97b2b6e48be64f46abfd0528a2c5dfbf735fb72fb56e1e3676f8da1c"


class AssetMismatchError(RuntimeError):
    """Raised when an archive is mixed with a different polymorphic build."""


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _semantic_json_sha256(path: Path) -> tuple[str, Any]:
    value = json.loads(path.read_text("utf-8"))
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(), value


def verify_assets() -> dict[str, Any]:
    """Fail fast when source and extracted VM assets belong to different builds."""

    checks: dict[str, tuple[str, str]] = {
        "official source": (_raw_sha256(SOURCE), OFFICIAL_SHA256),
        "readable source": (_raw_sha256(READABLE_SOURCE), READABLE_SHA256),
    }
    bytecode_hash, bytecode = _semantic_json_sha256(ARCHIVES / "h5st_bytecode.json")
    strings_hash, strings = _semantic_json_sha256(ARCHIVES / "h5st_string_table.json")
    checks["bytecode JSON"] = (bytecode_hash, BYTECODE_SEMANTIC_SHA256)
    checks["string JSON"] = (strings_hash, STRING_SEMANTIC_SHA256)
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise AssetMismatchError(f"{label} SHA256 mismatch: {actual} != {expected}")
    if len(bytecode) != 5209 or len(strings) != 374:
        raise AssetMismatchError(
            f"asset cardinality mismatch: bytecode={len(bytecode)}, strings={len(strings)}"
        )

    manifest = json.loads(MANIFEST.read_text("utf-8"))
    expected_manifest = {
        "schema": 1,
        "official_source_sha256": OFFICIAL_SHA256,
        "readable_source_sha256": READABLE_SHA256,
        "bytecode_count": 5209,
        "bytecode_json_sha256": BYTECODE_SEMANTIC_SHA256,
        "string_count": 374,
        "string_json_sha256": STRING_SEMANTIC_SHA256,
        "dispatcher_count": 34,
    }
    for key, expected in expected_manifest.items():
        actual = manifest.get(key)
        if actual != expected:
            raise AssetMismatchError(f"manifest {key} mismatch: {actual!r} != {expected!r}")
    dispatchers = json.loads((ARCHIVES / "h5st_vm_dispatchers.json").read_text("utf-8"))
    entries = [dispatcher.get("entry") for dispatcher in dispatchers]
    if entries != manifest.get("dispatcher_entries"):
        raise AssetMismatchError("dispatcher metadata entries differ from the manifest")
    if sum(len(dispatcher.get("handlers", [])) for dispatcher in dispatchers) != 1124:
        raise AssetMismatchError("dispatcher handler cardinality differs from the pinned build")
    return manifest


def _load_quickjs() -> Any:
    try:
        import quickjs  # type: ignore
    except ImportError as error:
        raise RuntimeError("Install the pinned runtime with: pip install -r requirements.txt") from error
    return quickjs


def _bridge_source() -> str:
    return r"""
function __jdSignJson(inputText) {
  var input = JSON.parse(inputText);
  var signer = new globalThis.ParamsSign({
    appId: input.app_id,
    beta: false,
    onSign: function () {},
    onRequestToken: function () {},
    onRequestTokenRemotely: function () {}
  });
  if (input.fingerprint || input.token) {
    var originalRds = signer._$rds;
    signer._$rds = function () {
      originalRds.call(this);
      if (input.fingerprint) this._fingerprint = input.fingerprint;
      if (input.token) {
        this._token = input.token;
        this._isNormal = true;
      }
    };
  }
  var result = signer.signSync(input.params);
  if (!result || typeof result.h5st !== "string" || result.h5st.split(";").length !== 10) {
    throw new Error("VM returned an invalid h5st record");
  }
  return JSON.stringify(result);
}
"""


def generate_h5st(
    app_id: str,
    params: Mapping[str, Any],
    *,
    now_ms: int | None = None,
    seed: int | None = None,
    fingerprint: str | None = None,
    token: str | None = None,
    timezone_offset_minutes: int = 480,
    user_agent: str | None = None,
    check_assets: bool = True,
) -> dict[str, Any]:
    """Execute ``ParamsSign.signSync`` in an isolated in-process VM context."""

    if not isinstance(app_id, str) or not app_id:
        raise ValueError("app_id must be a non-empty string")
    if not isinstance(params, Mapping) or not params:
        raise ValueError("params must be a non-empty mapping")
    if check_assets:
        verify_assets()

    quickjs = _load_quickjs()
    context = quickjs.Context()
    config: dict[str, Any] = {"timezone_offset_minutes": int(timezone_offset_minutes)}
    if now_ms is not None:
        config["now_ms"] = int(now_ms)
    if seed is not None:
        config["seed"] = int(seed)
    if user_agent:
        config["user_agent"] = user_agent

    context.eval("globalThis.__JD_VM_CONFIG__ = " + json.dumps(config, ensure_ascii=False) + ";")
    context.eval(SHIM.read_text("utf-8"))
    context.eval(SOURCE.read_text("utf-8"))
    context.eval(_bridge_source())
    call = context.get("__jdSignJson")
    request = {
        "app_id": app_id,
        "params": dict(params),
        "fingerprint": fingerprint,
        "token": token,
    }
    result_text = call(json.dumps(request, ensure_ascii=False, separators=(",", ":")))
    result = json.loads(result_text)
    parts = result["h5st"].split(";")
    if len(parts) != 10 or parts[5] != "5.3":
        raise RuntimeError("unexpected h5st schema returned by the pinned VM")
    return result


def _parse_params(value: str) -> Mapping[str, Any]:
    if value.startswith("@"):
        return json.loads(Path(value[1:]).read_text("utf-8"))
    return json.loads(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--params", required=True, help="JSON object or @FILE")
    parser.add_argument("--now-ms", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--fingerprint")
    parser.add_argument("--token")
    parser.add_argument("--timezone-offset-minutes", type=int, default=480)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    result = generate_h5st(
        args.app_id,
        _parse_params(args.params),
        now_ms=args.now_ms,
        seed=args.seed,
        fingerprint=args.fingerprint,
        token=args.token,
        timezone_offset_minutes=args.timezone_offset_minutes,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
