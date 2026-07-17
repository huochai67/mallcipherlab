#!/usr/bin/env python3
"""Pure-Python h5st 5.3 generator (vendor-JS free path).

Implemented on the pinned 2026-05-27 build:

* parameter sort (``_$cps``)
* genKey double ``local_key_3`` / HmacSHA256
* part 5 (``_$gs``) and part 9 (``_$gsd``)
* part 10 via deterministic ``encode(stk)``
* fingerprint via ``_$YX`` (entry 1068) pure port
* defaultToken via ``_$YE`` (entry 1553) pure port
* part 8 env via ``_$clt`` pure port (shim statics + y8 randoms + encode)
* full ten-part assembly from seed / now_ms / params alone

Optional overrides remain for fingerprint / token / part8 / skew when the
host environment differs from browser_shim.

Use ``h5st_runtime.generate_h5st`` for the embedded official VM path (A2).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from jd_crypto import (
    DEFAULT_PRNG_SEED,
    DEFAULT_TIMEZONE_OFFSET_MINUTES,
    EDATA_SALT,
    ENCODE_MAP,
    ENCODE_MAGIC,
    ENV_BU14,
    FP_ALPHABET,
    GSD_FIXED,
    LOCAL_KEY_TAIL,
    LOCAL_KEY_TIME_INFIX,
    PART1_MS_OFFSET,
    SEDATA_ALPHABET,
    SEDATA_MULTIPLIER,
    SEDATA_SEGMENTS,
    VERSION,
    custom_encode,
    derive_sign_key,
    format_timestamp_ms,
    generate_fingerprint,
    generate_fingerprint_part8_and_token,
    gs_hex,
    gsd_hex,
    hmac_sha256_hex,
    join_h5st_parts,
    make_sign_body,
    md5_hex,
    part10_from_stk,
    prepare_hash_message,
    prepare_hmac_message,
    se_data_segments,
    sha256_hex,
    sort_params,
)


@dataclass(frozen=True)
class NativeSignResult:
    """Result of a pure-Python signing attempt."""

    app_id: str
    params: dict[str, str]
    now_ms: int
    time_str: str
    fingerprint: str
    token: str
    sorted_params: list[dict[str, str]]
    sign_body: str
    stk: str
    mid_key: str
    sign_key: str
    part5: str
    part9: str
    part8: str | None
    part10: str | None
    h5st: str | None
    missing: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "params": self.params,
            "now_ms": self.now_ms,
            "version": VERSION,
            "time_str": self.time_str,
            "fingerprint": self.fingerprint,
            "token": self.token,
            "sorted_params": self.sorted_params,
            "sign_body": self.sign_body,
            "_stk": self.stk,
            "mid_key": self.mid_key,
            "sign_key": self.sign_key,
            "part5": self.part5,
            "part9": self.part9,
            "part8": self.part8,
            "part10": self.part10,
            "h5st": self.h5st,
            "missing": self.missing,
            "crypto_constants": {
                "seData_alphabet": SEDATA_ALPHABET,
                "seData_segments": SEDATA_SEGMENTS,
                "seData_multiplier": SEDATA_MULTIPLIER,
                "eData_salt": EDATA_SALT,
                "gsd_fixed": GSD_FIXED,
                "local_key_tail": LOCAL_KEY_TAIL,
                "local_key_time_infix": LOCAL_KEY_TIME_INFIX,
                "encode_map": ENCODE_MAP,
                "encode_magic": ENCODE_MAGIC,
            },
        }


def analyze_signing_inputs(
    app_id: str,
    params: Mapping[str, Any],
    *,
    now_ms: int,
    seed: int | None = None,
    timezone_offset_minutes: int = DEFAULT_TIMEZONE_OFFSET_MINUTES,
    skew_ms: int = PART1_MS_OFFSET,
) -> dict[str, Any]:
    """Lightweight pure slices without token/fingerprint."""

    normalized = {str(key): str(value) for key, value in params.items() if value is not None}
    sorted_body = sort_params(normalized)
    time_str = format_timestamp_ms(
        now_ms,
        timezone_offset_minutes=timezone_offset_minutes,
        skew_ms=skew_ms,
    )
    sample = "hello"
    return {
        "app_id": app_id,
        "params": normalized,
        "now_ms": now_ms,
        "seed": seed,
        "version": VERSION,
        "time_str": time_str,
        "sorted_params": sorted_body,
        "sign_body": make_sign_body(sorted_body),
        "prepared_examples": {
            "se_data_segments(hello)": se_data_segments(sample),
            "prepare_hash_message(hello)": prepare_hash_message(sample),
            "prepare_hmac_message(hello)": prepare_hmac_message(sample),
            "md5(hello)": md5_hex(sample),
            "sha256(hello)": sha256_hex(sample),
            "hmac(hello, token123)": hmac_sha256_hex(sample, "token123"),
            "encode(hello)": custom_encode(sample),
            "encode(stk sample)": part10_from_stk("appid,body,functionId"),
        },
        "fingerprint_demo": generate_fingerprint(seed if seed is not None else DEFAULT_PRNG_SEED),
        "fp_alphabet": FP_ALPHABET,
        "missing_for_full_h5st": [],
        "note": "full pure h5st available via generate_h5st(app_id, params, now_ms=..., seed=...)",
    }


def sign_native(
    app_id: str,
    params: Mapping[str, Any],
    *,
    now_ms: int,
    fingerprint: str,
    token: str,
    part8: str | None = None,
    part10: str | None = None,
    timezone_offset_minutes: int = DEFAULT_TIMEZONE_OFFSET_MINUTES,
    skew_ms: int = PART1_MS_OFFSET,
    time_str: str | None = None,
) -> NativeSignResult:
    """Pure-Python sign core.

    ``skew_ms`` defaults to :data:`PART1_MS_OFFSET` (vendor ``_$Y6`` always adds
    5000 ms before formatting part1). Pass ``time_str`` to override entirely.
    """

    normalized = {str(key): str(value) for key, value in params.items() if value is not None}
    sorted_body = sort_params(normalized)
    body = make_sign_body(sorted_body)
    stk = ",".join(item["key"] for item in sorted_body)
    if time_str is None:
        time_str = format_timestamp_ms(
            now_ms,
            timezone_offset_minutes=timezone_offset_minutes,
            skew_ms=skew_ms,
        )

    mid_key, sign_key = derive_sign_key(token, fingerprint, time_str, app_id)
    part5 = gs_hex(sign_key, sorted_body)
    part9 = gsd_hex(sign_key)
    if part10 is None:
        part10 = part10_from_stk(stk)

    missing: list[str] = []
    if not part8:
        missing.append("part8")

    h5st = None
    if part8 and part10:
        h5st = join_h5st_parts(
            [
                time_str,
                fingerprint,
                app_id,
                token,
                part5,
                VERSION,
                str(now_ms),
                part8,
                part9,
                part10,
            ]
        )

    return NativeSignResult(
        app_id=app_id,
        params=normalized,
        now_ms=now_ms,
        time_str=time_str,
        fingerprint=fingerprint,
        token=token,
        sorted_params=sorted_body,
        sign_body=body,
        stk=stk,
        mid_key=mid_key,
        sign_key=sign_key,
        part5=part5,
        part9=part9,
        part8=part8,
        part10=part10,
        h5st=h5st,
        missing=missing,
    )


def generate_h5st(
    app_id: str,
    params: Mapping[str, Any],
    *,
    now_ms: int,
    part8: str | None = None,
    token: str | None = None,
    fingerprint: str | None = None,
    part10: str | None = None,
    seed: int | None = DEFAULT_PRNG_SEED,
    timezone_offset_minutes: int = DEFAULT_TIMEZONE_OFFSET_MINUTES,
    skew_ms: int = PART1_MS_OFFSET,
    time_str: str | None = None,
    bu14: str = ENV_BU14,
    canvas: str | None = None,
    webgl_fp: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Public pure-Python entry (vendor-JS free).

    Omitting ``fingerprint`` / ``token`` / ``part8`` derives them from the shared
    PRNG stream (warmup → fp → clt/part8 → token). ``part10`` defaults to
    ``encode(stk)``. Pass any of them explicitly to override.

    Optional env overrides for part8 when auto-derived:

    * ``bu14`` — pLabel (default ``VRAEjxVEtV``)
    * ``canvas`` — standard MD5 hex of ``toDataURL()``; omit for shim/golden
    * ``webgl_fp`` — WebGL fingerprint string (default empty)
    """

    resolved_seed = seed if seed is not None else DEFAULT_PRNG_SEED
    env_kwargs: dict[str, Any] = {"bu14": bu14}
    if canvas is not None:
        env_kwargs["canvas"] = canvas
    if webgl_fp is not None:
        env_kwargs["webgl_fp"] = webgl_fp
    need_stream = fingerprint is None or token is None or part8 is None
    if need_stream:
        fp_gen, part8_gen, tok_gen = generate_fingerprint_part8_and_token(
            now_ms=now_ms,
            seed=resolved_seed,
            **env_kwargs,
        )
        if fingerprint is None:
            fingerprint = fp_gen
        if token is None:
            token = tok_gen
        if part8 is None:
            part8 = part8_gen
    result = sign_native(
        app_id,
        params,
        now_ms=now_ms,
        fingerprint=fingerprint,
        token=token,
        part8=part8,
        part10=part10,
        timezone_offset_minutes=timezone_offset_minutes,
        skew_ms=skew_ms,
        time_str=time_str,
    )
    if not result.h5st:
        raise RuntimeError(f"incomplete h5st; missing {result.missing}")
    out = dict(result.params)
    out["_stk"] = result.stk
    out["_ste"] = 1
    out["h5st"] = result.h5st
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--params", required=True, help="JSON object")
    parser.add_argument("--now-ms", type=int, required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--fingerprint", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--part8", default=None)
    parser.add_argument("--part10", default=None)
    parser.add_argument("--time-str", default=None)
    parser.add_argument(
        "--skew-ms",
        type=int,
        default=PART1_MS_OFFSET,
        help="part1 offset in ms (vendor _$Y6 adds 5000; default matches)",
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="print recovered pure slices without requiring token/fp/part8/10",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)

    params = json.loads(args.params)
    if args.analyze_only and not (args.fingerprint and args.token and args.part8):
        payload = analyze_signing_inputs(
            args.app_id,
            params,
            now_ms=args.now_ms,
            seed=args.seed,
            skew_ms=args.skew_ms,
        )
    else:
        fingerprint = args.fingerprint
        token = args.token
        part8 = args.part8
        if fingerprint is None or token is None or part8 is None:
            fp_gen, part8_gen, tok_gen = generate_fingerprint_part8_and_token(
                now_ms=args.now_ms,
                seed=args.seed if args.seed is not None else DEFAULT_PRNG_SEED,
            )
            if fingerprint is None:
                fingerprint = fp_gen
            if token is None:
                token = tok_gen
            if part8 is None:
                part8 = part8_gen
        result = sign_native(
            args.app_id,
            params,
            now_ms=args.now_ms,
            fingerprint=fingerprint,
            token=token,
            part8=part8,
            part10=args.part10,
            skew_ms=args.skew_ms,
            time_str=args.time_str,
        )
        payload = result.to_dict()

    text = json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
