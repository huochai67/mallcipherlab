from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UTILS = ROOT / "utils"
if str(UTILS) not in sys.path:
    sys.path.insert(0, str(UTILS))

import h5st_native  # noqa: E402
import jd_crypto  # noqa: E402


VENDOR_MD5 = {
    "": "d41d8cd98f00b204e9800998ecf8427e",
    "a": "bf1c4288aab95ca2bb41ec864b5dcd2d",
    "ab": "a8821e6ecac4fc9d098cd0559aa81a66",
    "hello": "bb0be5ab46ce80a7d66e04fedd8b6788",
    "test123": "b371a5f8e256ac5cb8964372f6699256",
    "abcdef": "df1f96f2ac13d01207d2c2f0343113e3",
}

VENDOR_SHA256 = {
    "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a": "d81d538260e514ae9c714c53f6e35ebbe7b40a69fde564f518156ebc2eddd9f9",
    "ab": "4fa8b27343f1b720cdb526dda7432346b445f93693110e0fffc2c6564ea28b6c",
    "hello": "95ee501d65340f39b0e0ee631ef77611f880089652c94ff4073eeffdc7f1937b",
    "test123": "9d85059e9101bc903784e8fd4415cfa0e78886dfca72a7365abfe60f444af8c9",
    "abcdef": "62f85a8b0e714bed0ede8b98327ec6199e76cc3b315549ec56309228d01f0278",
}

VENDOR_SEGMENTS = {
    "a": "annnnnL",
    "ab": "abnnnnnT",
    "hello": "hellonnnnn3",
    "abcdef": "abcdefLvT3b-",
    "test123": "test1233bT3Lb",
    "xxxxxx": "xxxxxxHHHHHH",
}

VENDOR_HMAC = {
    ("hello", "a"): "3579fe2c8a0865e50787e4317228e791677ea5eea0a50ec333634f0f799679ef",
    ("hello", "ab"): "e11fcfd2352a85755e7139161daddc6cdede903cf729ecf73f15471c4d9f78db",
    ("hello", "token123"): "eb9c74204bccef7828c5a4b5df45fafd62d3ab68a8b030c95f78b530f7deeb1d",
}

GOLDEN = json.loads((ROOT / "tests" / "fixtures" / "golden_h5st.json").read_text("utf-8"))
GOLDEN_PARTS = GOLDEN["expected"]["h5st"].split(";")
TOKEN = GOLDEN_PARTS[3]
FINGERPRINT = GOLDEN_PARTS[1]
TIME_STR = GOLDEN_PARTS[0]
PART8 = GOLDEN_PARTS[7]
PART10 = GOLDEN_PARTS[9]
APP_ID = GOLDEN["app_id"]
NOW_MS = GOLDEN["options"]["now_ms"]


class SeDataTests(unittest.TestCase):
    def test_segment_checksum_samples(self) -> None:
        for plain, expected in VENDOR_SEGMENTS.items():
            with self.subTest(plain=plain):
                self.assertEqual(jd_crypto.se_data_segments(plain), expected)

    def test_prepare_message_appends_build_salt(self) -> None:
        self.assertEqual(
            jd_crypto.prepare_hash_message("hello"),
            "hellonnnnn3" + jd_crypto.EDATA_SALT,
        )

    def test_hmac_message_is_double_sedata(self) -> None:
        self.assertEqual(
            jd_crypto.prepare_hmac_message("hello"),
            "hellonnnnn3HbXXDr" + jd_crypto.EDATA_SALT,
        )


class FingerprintTests(unittest.TestCase):
    def test_prng_matches_shim_first_draws(self) -> None:
        # browser_shim seed 0x12345678 — first draw is module-load noise, then fp stream.
        rng = jd_crypto.make_prng(0x12345678)
        self.assertAlmostEqual(rng(), 0.10615200875326991, places=12)
        self.assertAlmostEqual(rng(), 0.941276284167543, places=12)
        self.assertAlmostEqual(rng(), 0.9398706152569503, places=12)
        self.assertAlmostEqual(rng(), 0.2338848018553108, places=12)

    def test_fingerprint_matches_golden(self) -> None:
        fp = jd_crypto.generate_fingerprint(GOLDEN["options"]["seed"])
        self.assertEqual(fp, FINGERPRINT)
        self.assertEqual(len(fp), 16)
        self.assertRegex(fp, r"^[0-9a-z]{16}$")

    def test_fingerprint_without_warmup_differs(self) -> None:
        fp = jd_crypto.generate_fingerprint(GOLDEN["options"]["seed"], warmup_draws=0)
        self.assertNotEqual(fp, FINGERPRINT)
        self.assertEqual(len(fp), 16)

    def test_fingerprint_mid_finalize_roundtrip_shape(self) -> None:
        # Pure structural check: finalize keeps last char and maps body digits.
        mid = "oo5oo5ee1culqqx8"
        fp = jd_crypto._fp_finalize(mid)
        self.assertEqual(fp, "yzzaj1ibb2pp2pp8")
        self.assertEqual(fp[-1], mid[-1])


class DefaultTokenTests(unittest.TestCase):
    def test_default_token_matches_golden(self) -> None:
        token = jd_crypto.generate_default_token(
            FINGERPRINT,
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
        )
        self.assertEqual(token, TOKEN)
        self.assertTrue(token.startswith("tk06w"))
        self.assertEqual(len(token), 92)

    def test_fingerprint_and_token_pair(self) -> None:
        fp, token = jd_crypto.generate_fingerprint_and_token(
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
        )
        self.assertEqual(fp, FINGERPRINT)
        self.assertEqual(token, TOKEN)

    def test_fingerprint_part8_and_token_triple(self) -> None:
        fp, part8, token = jd_crypto.generate_fingerprint_part8_and_token(
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
        )
        self.assertEqual(fp, FINGERPRINT)
        self.assertEqual(part8, PART8)
        self.assertEqual(token, TOKEN)

    def test_token_without_clt_advance_differs(self) -> None:
        # Token must sit after clt's 21 draws; skipping them shifts the stream.
        token = jd_crypto.generate_default_token(
            FINGERPRINT,
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
            advance_clt_stream=False,
        )
        self.assertNotEqual(token, TOKEN)

    def test_token_adler_is_vendor_md5_prefix(self) -> None:
        token = TOKEN
        magic, version, platform = "tk", "06", "w"
        expires, producer = "41", "l"
        adler8 = token[5:13]
        expr = token[16:28]
        cipher = token[28:]
        material = f"{magic}{version}{platform}{version}{expires}{producer}{expr}{cipher}"
        self.assertEqual(jd_crypto.md5_hex(material)[:8], adler8)


class Part8EnvTests(unittest.TestCase):
    def test_part8_matches_golden(self) -> None:
        part8 = jd_crypto.generate_part8(
            FINGERPRINT,
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
        )
        self.assertEqual(part8, PART8)

    def test_env_json_text_is_indent_2(self) -> None:
        env = jd_crypto.build_env_json(
            FINGERPRINT,
            NOW_MS,
            "8A9N738AwLo",
            "7yF8N3P936",
        )
        text = jd_crypto.env_json_text(env)
        self.assertIn('\n  "sua":', text)
        self.assertEqual(jd_crypto.custom_encode(text), PART8)

    def test_clt_randoms_match_golden_env(self) -> None:
        rnd = jd_crypto.make_prng(GOLDEN["options"]["seed"])
        rnd()
        jd_crypto.generate_fingerprint(random=rnd)
        extend_random, top_random = jd_crypto._clt_random_strings(rnd)
        self.assertEqual(extend_random, "8A9N738AwLo")
        self.assertEqual(top_random, "7yF8N3P936")

    def test_bu14_is_default_plabel_constant(self) -> None:
        # Vendor default when WQ_dy1_pFlag / behavior flag missing (fF 0x2c4).
        self.assertEqual(jd_crypto.ENV_BU14, "VRAEjxVEtV")
        self.assertEqual(jd_crypto.ENV_PLABEL_DEFAULT, jd_crypto.ENV_BU14)
        env = jd_crypto.build_env_json(FINGERPRINT, NOW_MS, "x", "y")
        self.assertEqual(env["bu14"], "VRAEjxVEtV")
        self.assertNotIn("canvas", env)

    def test_resolve_plabel_prefers_pflag(self) -> None:
        self.assertEqual(jd_crypto.resolve_plabel(), "VRAEjxVEtV")
        self.assertEqual(jd_crypto.resolve_plabel(pflag_value="CUSTOM1234"), "CUSTOM1234")
        self.assertEqual(
            jd_crypto.resolve_plabel(pflag_value="CUSTOM1234", pflag_valid=False),
            "VRAEjxVEtV",
        )

    def test_canvas_fingerprint_is_standard_md5_of_data_url(self) -> None:
        data_url = (
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
            "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        )
        # Official runtime observation (Node + working toDataURL).
        self.assertEqual(
            jd_crypto.canvas_fingerprint_from_data_url(data_url),
            "6522394873e0230ef1380c0fc18a9efd",
        )
        # Distinct from vendor seData-MD5 used for sign slices.
        self.assertNotEqual(
            jd_crypto.canvas_fingerprint_from_data_url(data_url),
            jd_crypto.md5_hex(data_url),
        )

    def test_env_includes_canvas_when_provided(self) -> None:
        fp = jd_crypto.canvas_fingerprint_from_data_url("data:image/png;base64,AAA")
        env = jd_crypto.build_env_json(
            FINGERPRINT,
            NOW_MS,
            "8A9N738AwLo",
            "7yF8N3P936",
            canvas=fp,
        )
        keys = list(env.keys())
        self.assertEqual(env["canvas"], fp)
        self.assertLess(keys.index("bu4"), keys.index("canvas"))
        self.assertLess(keys.index("canvas"), keys.index("webglFp"))
        # Encoded part8 differs from golden (golden has no canvas key).
        self.assertNotEqual(jd_crypto.custom_encode(jd_crypto.env_json_text(env)), PART8)

    def test_webgl_fp_from_storage_envelope(self) -> None:
        raw = jd_crypto.pack_env_storage(
            "deadbeefcafebabe0123456789abcdef",
            now_ms=NOW_MS,
        )
        self.assertEqual(
            jd_crypto.webgl_fp_from_storage(raw),
            "deadbeefcafebabe0123456789abcdef",
        )
        self.assertEqual(jd_crypto.webgl_fp_from_storage(None), "")
        self.assertEqual(jd_crypto.webgl_fp_from_storage(""), "")
        env = jd_crypto.build_env_json(
            FINGERPRINT,
            NOW_MS,
            "8A9N738AwLo",
            "7yF8N3P936",
            webgl_fp=jd_crypto.webgl_fp_from_storage(raw),
        )
        self.assertEqual(env["webglFp"], "deadbeefcafebabe0123456789abcdef")

    def test_infer_extend_statics_host_signals(self) -> None:
        base = jd_crypto.infer_extend_statics()
        self.assertEqual(base["wd"], 0)
        self.assertEqual(base["wk"], 64)
        self.assertEqual(base["bu5"], 0)
        wd = jd_crypto.infer_extend_statics(webdriver=True)
        self.assertEqual(wd["wd"], 1)
        ph = jd_crypto.infer_extend_statics(phantom=True)
        self.assertEqual(ph["wk"], 80)
        cy = jd_crypto.infer_extend_statics(cypress=True)
        self.assertEqual(cy["bu5"] & jd_crypto.BU5_BIT_CYPRESS, jd_crypto.BU5_BIT_CYPRESS)
        plug = jd_crypto.infer_extend_statics(plugins_length=5)
        self.assertEqual(plug["ls"], 5)


class Part1TimeTests(unittest.TestCase):
    def test_vendor_y6_offset_is_5000(self) -> None:
        self.assertEqual(jd_crypto.PART1_MS_OFFSET, 5000)
        # 0xff*-0x25 + -0x15eb + 0x4e4e from readable _$Y6
        self.assertEqual(0xFF * -0x25 + -0x15EB + 0x4E4E, 5000)

    def test_format_timestamp_defaults_to_vendor_offset(self) -> None:
        self.assertEqual(
            jd_crypto.format_timestamp_ms(NOW_MS),
            TIME_STR,
        )
        self.assertEqual(
            jd_crypto.format_timestamp_ms(NOW_MS, skew_ms=0),
            "20260716101530123",
        )

    def test_pure_generate_h5st_without_time_str_uses_offset(self) -> None:
        out = h5st_native.generate_h5st(
            APP_ID,
            GOLDEN["params"],
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
        )
        self.assertEqual(out["h5st"].split(";")[0], TIME_STR)
        self.assertEqual(out["h5st"].split(";")[6], str(NOW_MS))
        self.assertEqual(out["h5st"], GOLDEN["expected"]["h5st"])


class ModifiedHashTests(unittest.TestCase):
    def test_md5_matches_vendor_vectors(self) -> None:
        for plain, digest in VENDOR_MD5.items():
            with self.subTest(plain=plain):
                if plain == "":
                    self.assertEqual(jd_crypto.md5_hex_raw(b""), digest)
                else:
                    self.assertEqual(jd_crypto.md5_hex(plain), digest)

    def test_sha256_matches_vendor_vectors(self) -> None:
        for plain, digest in VENDOR_SHA256.items():
            with self.subTest(plain=plain):
                if plain == "":
                    self.assertEqual(jd_crypto.sha256_hex_raw(b""), digest)
                else:
                    self.assertEqual(jd_crypto.sha256_hex(plain), digest)

    def test_ekey_prefix_transform(self) -> None:
        self.assertEqual(jd_crypto.ekey("a"), "s")
        self.assertEqual(jd_crypto.ekey("ab"), "zs")
        self.assertEqual(jd_crypto.ekey("token123"), "v:ken123")
        self.assertEqual(jd_crypto.ekey("tk06w")[:2], "Z:")

    def test_hmac_matches_vendor_vectors(self) -> None:
        for (message, key), digest in VENDOR_HMAC.items():
            with self.subTest(message=message, key=key):
                self.assertEqual(jd_crypto.hmac_sha256_hex(message, key), digest)

    def test_hmac_vendor_gap_alias_is_implemented(self) -> None:
        self.assertEqual(
            jd_crypto.hmac_sha256_vendor_gap("hello", "token123"),
            VENDOR_HMAC[("hello", "token123")],
        )


class EncodeAndPart10Tests(unittest.TestCase):
    def test_custom_encode_samples(self) -> None:
        samples = {
            "": "of7r",
            "a": "pjbT",
            "ab": "qjVT",
            "abc": "of7rIiVT",
            "abcd": "pjrSIiVT",
            "hello": "qvlQ-WlR",
            "appid,body,functionId": PART10,
        }
        for plain, expected in samples.items():
            with self.subTest(plain=plain):
                self.assertEqual(jd_crypto.custom_encode(plain), expected)

    def test_part10_from_stk_matches_golden(self) -> None:
        stk = ",".join(sorted(GOLDEN["params"].keys()))
        # cps sorts keys: appid,body,functionId
        self.assertEqual(stk, "appid,body,functionId")
        self.assertEqual(jd_crypto.part10_from_stk(stk), PART10)


class GenKeyAndSignSliceTests(unittest.TestCase):
    def test_genkey_material_matches_trace(self) -> None:
        material = jd_crypto.build_genkey_material(TOKEN, FINGERPRINT, TIME_STR, APP_ID)
        self.assertEqual(
            material,
            TOKEN + FINGERPRINT + TIME_STR + "54" + APP_ID + "jid+hR",
        )

    def test_derive_sign_key_matches_golden_trace(self) -> None:
        mid, sign_key = jd_crypto.derive_sign_key(TOKEN, FINGERPRINT, TIME_STR, APP_ID)
        self.assertEqual(mid, "7cd25f79047798af4e56fad1c882e871a597374be493d6eef6ffa91e1d036971")
        self.assertEqual(sign_key, "a9a8519ad93690346dc90027dca803e622213ca0456719b8686366894f0b4264")

    def test_gs_and_gsd_match_golden_parts(self) -> None:
        sorted_params = jd_crypto.sort_params(GOLDEN["params"])
        _, sign_key = jd_crypto.derive_sign_key(TOKEN, FINGERPRINT, TIME_STR, APP_ID)
        self.assertEqual(jd_crypto.gs_hex(sign_key, sorted_params), GOLDEN_PARTS[4])
        self.assertEqual(jd_crypto.gsd_hex(sign_key), GOLDEN_PARTS[8])


class NativeScaffoldTests(unittest.TestCase):
    def test_analyze_signing_inputs_golden_shape(self) -> None:
        progress = h5st_native.analyze_signing_inputs(
            GOLDEN["app_id"],
            GOLDEN["params"],
            now_ms=GOLDEN["options"]["now_ms"],
            seed=GOLDEN["options"]["seed"],
            skew_ms=0,
        )
        self.assertEqual(progress["time_str"], "20260716101530123")
        self.assertEqual(
            [item["key"] for item in progress["sorted_params"]],
            ["appid", "body", "functionId"],
        )

    def test_sign_native_core_matches_golden_parts(self) -> None:
        result = h5st_native.sign_native(
            APP_ID,
            GOLDEN["params"],
            now_ms=NOW_MS,
            fingerprint=FINGERPRINT,
            token=TOKEN,
            part8=PART8,
            part10=PART10,
            time_str=TIME_STR,
            skew_ms=0,
        )
        self.assertEqual(result.part5, GOLDEN_PARTS[4])
        self.assertEqual(result.part9, GOLDEN_PARTS[8])
        self.assertEqual(result.h5st, GOLDEN["expected"]["h5st"])
        self.assertEqual(result.missing, [])

    def test_generate_h5st_with_injected_env_matches_golden(self) -> None:
        out = h5st_native.generate_h5st(
            APP_ID,
            GOLDEN["params"],
            now_ms=NOW_MS,
            fingerprint=FINGERPRINT,
            token=TOKEN,
            part8=PART8,
            time_str=TIME_STR,
        )
        self.assertEqual(out["h5st"], GOLDEN["expected"]["h5st"])
        self.assertEqual(out["_stk"], GOLDEN["expected"]["_stk"])
        self.assertEqual(out["_ste"], 1)

    def test_generate_h5st_pure_end_to_end_matches_golden(self) -> None:
        """No injected fp/token/part8 — pure shared PRNG + shim env statics."""
        out = h5st_native.generate_h5st(
            APP_ID,
            GOLDEN["params"],
            now_ms=NOW_MS,
            seed=GOLDEN["options"]["seed"],
            time_str=TIME_STR,
        )
        self.assertEqual(out["h5st"], GOLDEN["expected"]["h5st"])
        self.assertEqual(out["_stk"], GOLDEN["expected"]["_stk"])
        self.assertEqual(out["_ste"], 1)
        self.assertEqual(len(out["h5st"].split(";")), 10)

    def test_part10_is_derived_when_omitted(self) -> None:
        result = h5st_native.sign_native(
            APP_ID,
            GOLDEN["params"],
            now_ms=NOW_MS,
            fingerprint=FINGERPRINT,
            token=TOKEN,
            part8=PART8,
            time_str=TIME_STR,
            skew_ms=0,
        )
        self.assertEqual(result.part10, PART10)
        self.assertEqual(result.h5st, GOLDEN["expected"]["h5st"])


@unittest.skipUnless(
    (UTILS / "h5st_trace.js").is_file(),
    "trace script is part of this repository",
)
class TraceScriptSmokeTests(unittest.TestCase):
    def test_trace_script_runs_on_golden_when_node_available(self) -> None:
        import shutil

        if not shutil.which("node"):
            self.skipTest("node not installed")
        command = [
            "node",
            str(UTILS / "h5st_trace.js"),
            GOLDEN["app_id"],
            json.dumps(GOLDEN["params"], separators=(",", ":")),
            str(GOLDEN["options"]["now_ms"]),
            str(GOLDEN["options"]["seed"]),
        ]
        process = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        trace = json.loads(process.stdout)
        self.assertEqual(trace["schema"], 1)
        self.assertIn("_$cps", trace["method_order"])
        self.assertIn("_$ms", trace["method_order"])
        self.assertEqual(trace["h5st"]["count"], 10)
        self.assertEqual(trace["result"]["h5st"].split(";")[2], GOLDEN["app_id"])


if __name__ == "__main__":
    unittest.main()
