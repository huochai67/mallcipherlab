#!/usr/bin/env python3
"""Pure-Python ports of the pinned h5st 5.3 modified hash helpers.

Recovered from Node instrumentation of the 2026-05-27 official snapshot
(``78ff71158c7dc6284a0ab381370be33bc8fb8fd7f25571745330848eb766c331``):

String path (single-shot MD5/SHA256)
    seData (entry 199): 6-way segment checksum with multiplier 28
    eData  (entry 181): append fixed salt ``RvI<7|``
    then standard MD5 / SHA256 over latin-1 bytes

HMAC / local_key_3
    message: seData(seData(msg)) + salt   (double seData)
    key:     eKey(key) then standard HMAC-SHA256
             eKey maps the first min(2, len) characters (pop/reverse order)
             with ``((c - 32) * 7 + 8) % 95 + 32``, remainder unchanged
             if key length > 64 after eKey, hash key with standard SHA256 first

Sign slices
    _$gs:  SHA256(prepare(key + body + key)) where body is ``k:v`` joined by ``&``
    _$gsd: SHA256(prepare(key + GSD_FIXED + key))

Fingerprint (``_$YX`` / entry 1068)
    alphabet ``ekl9i1uct6``; ordered random subset of 4 chars; destructive permute → fo;
    size digit A=(random*10)|0; charset = transform(alphabet\\\\fo) with (n*5+32)%36;
    mid = Yv(A)+fo+Yv(11-A)+str(A); fp = reverse-transform body (n*5+13)%36 + last digit.
    Fixture seed needs one Math.random warm-up (vendor module load).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Final, Iterable, Mapping, Sequence

# Pinned build: js_security_v3_0.1.4_20260527205706.js
SEDATA_ALPHABET: Final = (
    "nmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvutsrqpo"
)
SEDATA_SEGMENTS: Final = 6
SEDATA_MULTIPLIER: Final = 28
EDATA_SALT: Final = "RvI<7|"
EKEY_PREFIX_CHARS: Final = 2
EKEY_MULTIPLIER: Final = 7
EKEY_OFFSET: Final = 8
EKEY_MOD: Final = 95  # printable ASCII span
EKEY_BASE: Final = 32
GSD_FIXED: Final = "appid:appid&functionid:functionId"
VERSION: Final = "5.3"
LOCAL_KEY_TAIL: Final = "jid+hR"
LOCAL_KEY_TIME_INFIX: Final = "54"
# Custom base64 map used by env/token/stk ``encode`` (distinct from seData alphabet).
ENCODE_MAP: Final = (
    "rqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvuts"
)
ENCODE_MAGIC: Final = "of7r"
# Fingerprint (``_$YX`` entry 1068) constants for this pinned build.
FP_ALPHABET: Final = "ekl9i1uct6"
FP_SAMPLE_SIZE: Final = 4
FP_SIZE_MOD: Final = 10
FP_MID_BODY_LEN: Final = 11  # Yv(A) + fo(4) + Yv(11-A) => 15 body chars + digit
FP_CHARSET_MUL: Final = 5
FP_CHARSET_ADD: Final = 32
FP_FINAL_MUL: Final = 5
FP_FINAL_ADD: Final = 13
FP_RADIX: Final = 36
# Default fixture PRNG seed (browser_shim xorshift family).
DEFAULT_PRNG_SEED: Final = 0x12345678  # 305419896
# defaultToken (``_$YE`` entry 1553) constants for this pinned build.
TOKEN_MAGIC: Final = "tk"
TOKEN_VERSION: Final = "06"
TOKEN_PLATFORM: Final = "w"
TOKEN_EXPIRES: Final = "41"
TOKEN_PRODUCER: Final = "l"
TOKEN_Y8_CHARSET: Final = "0123456789abmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
TOKEN_Y8_LEN: Final = 54
TOKEN_EXPR_MATERIAL_LEN: Final = 32
TOKEN_CIPHER_Y8_LEN: Final = 12
TOKEN_EXPR_DIGITS: Final = "123"
TOKEN_EXPR_OPS: Final = "+x"
TOKEN_VERSION_BYTES: Final = bytes((1, 0, 0))
# Fingerprint consumes this many Math.random draws (after optional module warmup).
FP_RANDOM_DRAWS: Final = 24
# ``_$clt`` env randoms (after fingerprint, before defaultToken) via ``_$Y8``.
CLT_EXTEND_RANDOM_LEN: Final = 11  # extend.random
CLT_TOP_RANDOM_LEN: Final = 10  # top-level random
CLT_RANDOM_DRAWS: Final = CLT_EXTEND_RANDOM_LEN + CLT_TOP_RANDOM_LEN  # 21
# Part8 env statics for the pinned LF build under browser_shim (empty storage).
# Dynamic fields (extend.random / random / t / fp) are filled at sign time.
#
# ``bu14`` is **not** canvas: vendor field maps to ``pLabel`` on
# ``__JDWEBSIGNHELPER_$DATA__['main.sign#__data']``. When storage key
# ``WQ_dy1_pFlag`` / ``JDst_behavior_flag`` is missing or expired, readable
# sample sets ``pLabel = fF(0x2c4)`` which decodes to the literal below.
ENV_SUA: Final = "Windows NT 10.0; Win64; x64"
ENV_PF: Final = "Win32"
ENV_VERSION: Final = "h5_file_v5.3.4"
ENV_BU1: Final = "0.1.4"  # official snapshot; readable cc4cf49 hardcodes 0.1.5
ENV_BU4_TOP: Final = "0"
ENV_WEBGL_FP: Final = ""  # storage ``WQ_gather_wgl1`` empty under shim
ENV_CCN: Final = 8  # navigator.hardwareConcurrency
ENV_BU14: Final = "VRAEjxVEtV"  # default pLabel (fF 0x2c4)
ENV_PLABEL_DEFAULT: Final = ENV_BU14
# Storage keys used by the collector (readable sample ``_$YB``).
STORAGE_KEY_CANVAS_FP: Final = "WQ_gather_cv1"
STORAGE_KEY_WEBGL_FP: Final = "WQ_gather_wgl1"
STORAGE_KEY_PFLAG: Final = "WQ_dy1_pFlag"
STORAGE_KEY_BEHAVIOR_FLAG: Final = "JDst_behavior_flag"
# Vendor storage envelope expiry used for canvas cache (0x1e13380 ms ≈ 365d).
ENV_STORAGE_EXPIRES_MS: Final = 0x1E13380
# Canvas drawing uses these styles (readable ``_$Yo``); the fingerprint itself is
# standard MD5 hex of ``canvas.toDataURL()`` (official runtime observation).
CANVAS_FILL_STYLE_1: Final = "red"
CANVAS_STROKE_STYLE: Final = "#1a3bc1"
CANVAS_FILL_STYLE_2: Final = "#42e1a2"
CANVAS_FONT_1: Final = "15.4px 'Arial'"
CANVAS_FONT_2: Final = "60px 'Not a real font'"
CANVAS_TEXT_1: Final = "PR flacks quiz gym: TV DJ box when? ☠"
CANVAS_TEXT_2: Final = "No骗"
CANVAS_SHADOW_COLOR: Final = "white"
CANVAS_FILL_STYLE_3: Final = "rgba(0, 0, 200, 0.5)"
# Extend object for golden / empty-automation host. Observed differential (Node):
#   wd: 1 if navigator.webdriver else 0
#   ls: -1 default; rises with plugins length in some host configs
#   wk: 64 default; 80 when window.callPhantom / _phantom present
#   bu5: automation bitfield — base often 0/4; Cypress → |32 (e.g. 36); Playwright hooks also probed
#   bu4: host/document probe (live Node often 1; golden fixture pins 0)
ENV_EXTEND_STATICS: Final = {
    "wd": 0,
    "l": 0,
    "ls": -1,
    "wk": 64,
    "bu1": ENV_BU1,
    "bu3": -1,
    "bu4": 0,  # golden pin (live Node+shim may report 1)
    "bu5": 0,  # golden pin (automation bitfield)
    "bu6": -1,
    "bu7": 1,
    "bu8": 1,
    "bu12": -8,  # timezone hours for UTC+8 (getTimezoneOffset -480 → -8h)
    "bu10": 14,  # vendor literal 0x1c70+0x1e0b-0x3a6d
    "bu11": 3,  # vendor literal 0x103-0x4a*7+0x83*2
}
# bu5 automation bits observed under browser_shim patches (not exhaustive).
BU5_BIT_BASE_CLT: Final = 0x4  # sometimes set on bare _$clt under Node
BU5_BIT_CYPRESS: Final = 0x20  # window.Cypress / __Cypress__
# Vendor ``_$Y6`` always does ``ts += 5000`` before formatting part1
# (``0xff*-0x25 + -0x15eb + 0x4e4e == 5000``). Part7 keeps raw ``Date.now()``.
PART1_MS_OFFSET: Final = 5000
DEFAULT_TIMEZONE_OFFSET_MINUTES: Final = 480


def _latin1_bytes(text: str) -> bytes:
    return text.encode("latin-1")


def se_data_segments(
    plain_text: str,
    *,
    segments: int = SEDATA_SEGMENTS,
    multiplier: int = SEDATA_MULTIPLIER,
    alphabet: str = SEDATA_ALPHABET,
) -> str:
    """VM entry 199 style segment checksum (no fixed salt)."""

    if segments <= 0:
        raise ValueError("segments must be positive")
    if len(alphabet) != 64:
        raise ValueError("alphabet must contain 64 characters")

    segment_length = len(plain_text) // segments
    chars: list[str] = []
    for index in range(segments):
        start = index * segment_length
        end = len(plain_text) if index == segments - 1 else start + segment_length
        total = 0
        for offset in range(start, end):
            total += ord(plain_text[offset])
        chars.append(alphabet[(total * multiplier) % 64])
    return plain_text + "".join(chars)


def prepare_hash_message(plain_text: str, *, salt: str = EDATA_SALT) -> str:
    """Single-shot MD5/SHA256 string pre-process: seData once + eData salt."""

    return se_data_segments(plain_text) + salt


def prepare_hmac_message(plain_text: str, *, salt: str = EDATA_SALT) -> str:
    """HMAC message pre-process on this build: seData twice + eData salt."""

    return se_data_segments(se_data_segments(plain_text)) + salt


def ekey(key: str, *, prefix_chars: int = EKEY_PREFIX_CHARS) -> str:
    """HMAC key transform (entry 902 ``eKey`` semantics)."""

    if not key:
        return key
    n = min(prefix_chars, len(key))
    head = list(key[:n])
    out: list[str] = []
    while head:
        code = ord(head.pop())
        # Printable-range affine map used by this build.
        mapped = ((code - EKEY_BASE) * EKEY_MULTIPLIER + EKEY_OFFSET) % EKEY_MOD + EKEY_BASE
        out.append(chr(mapped))
    return "".join(out) + key[n:]


def md5_hex(message: str) -> str:
    """Modified MD5 for string input."""

    if message == "":
        return hashlib.md5(b"").hexdigest()
    return hashlib.md5(_latin1_bytes(prepare_hash_message(message))).hexdigest()


def sha256_hex(message: str) -> str:
    """Modified SHA256 for string input."""

    if message == "":
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(_latin1_bytes(prepare_hash_message(message))).hexdigest()


def sha256_hex_raw(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_hex_raw(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def hmac_sha256_hex(message: str, key: str) -> str:
    """Vendor HmacSHA256 / ``local_key_3`` for this build."""

    key_bytes = _latin1_bytes(ekey(key))
    if len(key_bytes) > 64:
        key_bytes = hashlib.sha256(key_bytes).digest()
    return hmac.new(
        key_bytes,
        _latin1_bytes(prepare_hmac_message(message)),
        hashlib.sha256,
    ).hexdigest()


# Back-compat alias used by earlier scaffold / tests.
def hmac_sha256_vendor_gap(message: str, key: str) -> str:
    return hmac_sha256_hex(message, key)


def hmac_sha256_naive(message: str, key: str) -> str:
    """Incorrect naive form kept only for regression contrast."""

    return hmac.new(
        _latin1_bytes(key),
        _latin1_bytes(prepare_hash_message(message)),
        hashlib.sha256,
    ).hexdigest()


def make_sign_body(sorted_params: Sequence[Mapping[str, str]]) -> str:
    """``key:value`` pairs joined by ``&`` (entry 4548 mapper + join)."""

    return "&".join(f"{item['key']}:{item['value']}" for item in sorted_params)


def gs_hex(sign_key: str, sorted_params: Sequence[Mapping[str, str]]) -> str:
    """``_$gs``: business signature (part 5)."""

    body = make_sign_body(sorted_params)
    return sha256_hex(sign_key + body + sign_key)


def gsd_hex(sign_key: str, fixed: str = GSD_FIXED) -> str:
    """``_$gsd``: secondary signature (part 9). Params are ignored on this build."""

    return sha256_hex(sign_key + fixed + sign_key)


def build_genkey_material(
    token: str,
    fingerprint: str,
    time_str: str,
    app_id: str,
    *,
    time_infix: str = LOCAL_KEY_TIME_INFIX,
    tail: str = LOCAL_KEY_TAIL,
) -> str:
    """First ``_$atm`` message on the default local-token path."""

    return f"{token}{fingerprint}{time_str}{time_infix}{app_id}{tail}"


def derive_sign_key(
    token: str,
    fingerprint: str,
    time_str: str,
    app_id: str,
) -> tuple[str, str]:
    """Double ``local_key_3`` derivation. Returns ``(mid, sign_key)``."""

    material = build_genkey_material(token, fingerprint, time_str, app_id)
    mid = hmac_sha256_hex(material, token)
    sign_key = hmac_sha256_hex(mid, token)
    return mid, sign_key


def format_timestamp_ms(
    now_ms: int,
    *,
    timezone_offset_minutes: int = DEFAULT_TIMEZONE_OFFSET_MINUTES,
    skew_ms: int = PART1_MS_OFFSET,
) -> str:
    """Format part1 wall clock as ``YYYYMMDDHHmmssSSS`` (vendor ``_$Y6``).

    Vendor always adds :data:`PART1_MS_OFFSET` (5000 ms) to the timestamp before
    formatting; part7 of h5st still carries the unshifted ``now_ms``. Pass
    ``skew_ms=0`` only when you need the raw clock view without that offset.
    Pattern used by the build is ``yyyyMMddhhmmssSSS`` (UTC+timezone getters).
    """

    import datetime as _dt

    instant = _dt.datetime.fromtimestamp((now_ms + skew_ms) / 1000.0, tz=_dt.timezone.utc)
    local = instant + _dt.timedelta(minutes=timezone_offset_minutes)
    return (
        f"{local.year:04d}{local.month:02d}{local.day:02d}"
        f"{local.hour:02d}{local.minute:02d}{local.second:02d}"
        f"{local.microsecond // 1000:03d}"
    )


def sort_params(params: Mapping[str, object]) -> list[dict[str, str]]:
    """``_$cps`` style sorted key/value list used by the sign body."""

    items: list[dict[str, str]] = []
    for key in sorted(params.keys()):
        value = params[key]
        if value is None:
            continue
        items.append({"key": str(key), "value": str(value)})
    return items


def _to_int32(n: int) -> int:
    """JS ``ToInt32``."""

    n &= 0xFFFFFFFF
    return n - 0x100000000 if n >= 0x80000000 else n


def _math_imul(a: int, b: int) -> int:
    """JS ``Math.imul`` (signed 32-bit product)."""

    return _to_int32((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))


def make_prng(seed: int = DEFAULT_PRNG_SEED):
    """Match ``browser_shim.js`` seeded ``Math.random`` (imul/xorshift style)."""

    state = seed & 0xFFFFFFFF

    def _usr(n: int, bits: int) -> int:
        """JS unsigned right shift ``>>>``."""

        return (n & 0xFFFFFFFF) >> bits

    def random() -> float:
        nonlocal state
        state = (state + 0x6D2B79F5) & 0xFFFFFFFF
        value = _to_int32(state)
        value = _math_imul(value ^ _usr(value, 15), value | 1)
        value = _to_int32(
            value ^ _to_int32(value + _math_imul(value ^ _usr(value, 7), value | 61))
        )
        return float((value ^ _usr(value, 14)) & 0xFFFFFFFF) / 4294967296.0

    return random


def _to_base36(n: int) -> str:
    """Single-digit base36 for ``0 <= n < 36`` (JS ``Number#toString(36)``)."""

    if n < 0 or n >= FP_RADIX:
        raise ValueError(f"base36 digit out of range: {n}")
    return "0123456789abcdefghijklmnopqrstuvwxyz"[n]


def _from_base36_char(ch: str) -> int:
    return int(ch, FP_RADIX)


def _fp_transform_char(ch: str, add: int, mul: int = FP_CHARSET_MUL) -> str:
    return _to_base36((_from_base36_char(ch) * mul + add) % FP_RADIX)


def _fp_sample_chars(alphabet: str, k: int, random) -> list[str]:
    """Ordered random subset (``vm_1304`` first loop): keep relative alphabet order."""

    picked: list[str] = []
    need = k
    left = len(alphabet)
    for ch in alphabet:
        if need <= 0:
            break
        if random() * left < need:
            picked.append(ch)
            need -= 1
            if need == 0:
                break
        left -= 1
    return picked


def _fp_permute_chars(chars: list[str], random) -> str:
    """Destructive random pick / swap (``vm_1304`` second loop) → fo string."""

    arr = list(chars)
    out: list[str] = []
    for k in range(len(arr)):
        j = int(random() * (len(arr) - k))  # JS ``(r * n) | 0`` for r in [0,1)
        out.append(arr[j])
        end = len(arr) - k - 1
        arr[j], arr[end] = arr[end], arr[j]
    return "".join(out)


def _fp_make_charset(alphabet: str, fo: str) -> str:
    """``vm_1447``: transform alphabet chars not present in fo with ``*5+32``."""

    return "".join(
        _fp_transform_char(ch, FP_CHARSET_ADD) for ch in alphabet if fo.find(ch) < 0
    )


def _fp_yv(size: int, charset: str, random) -> str:
    """``_$Yv``: ``size`` random picks from charset."""

    if not charset:
        raise ValueError("charset must be non-empty")
    n = len(charset)
    return "".join(charset[int(random() * n)] for _ in range(size))


def _fp_finalize(mid: str) -> str:
    """Outer 1068 loop: reverse body via pop, ``(n*5+13)%36``, keep last digit raw."""

    if len(mid) < 2:
        raise ValueError("mid fingerprint material too short")
    chars = list(mid)
    last = chars.pop()
    out: list[str] = []
    while chars:
        out.append(_fp_transform_char(chars.pop(), FP_FINAL_ADD, FP_FINAL_MUL))
    out.append(last)
    return "".join(out)


def generate_fingerprint(
    seed: int | None = DEFAULT_PRNG_SEED,
    *,
    random=None,
    alphabet: str = FP_ALPHABET,
    sample_size: int = FP_SAMPLE_SIZE,
    warmup_draws: int = 1,
) -> str:
    """Pure ``_$YX`` / ``_$rds`` fingerprint (16 chars) for the pinned build.

    Consumes 24 ``Math.random`` draws for the algorithm itself:
    sample subset + permute (12) + size digit (1) + two ``_$Yv`` fills (11).

    When constructing a PRNG from ``seed``, ``warmup_draws`` defaults to 1 to
    skip the single vendor-module-load ``Math.random`` observed on this snapshot
    (so golden seed ``0x12345678`` yields ``yzzaj1ibb2pp2pp8``). Pass
    ``warmup_draws=0`` for a pristine PRNG stream, or supply ``random=`` directly.
    """

    if random is None:
        if seed is None:
            raise ValueError("seed or random callable is required")
        random = make_prng(seed)
        for _ in range(max(0, warmup_draws)):
            random()

    picked = _fp_sample_chars(alphabet, sample_size, random)
    fo = _fp_permute_chars(picked, random)
    size_digit = int(random() * FP_SIZE_MOD)  # A in 0..9
    charset = _fp_make_charset(alphabet, fo)
    part1 = _fp_yv(size_digit, charset, random)
    part2 = _fp_yv(FP_MID_BODY_LEN - size_digit, charset, random)
    mid = f"{part1}{fo}{part2}{size_digit}"
    return _fp_finalize(mid)


def _token_y8(n: int, random) -> str:
    """``_$Y8``: n charset picks; if n>5 insert ``3`` at index 5 and drop last char."""

    if len(TOKEN_Y8_CHARSET) != TOKEN_Y8_LEN:
        raise ValueError("TOKEN_Y8_CHARSET length mismatch")
    s = "".join(TOKEN_Y8_CHARSET[int(random() * TOKEN_Y8_LEN)] for _ in range(n))
    if len(s) > 5:
        s = s[:5] + "3" + s[5:-1]
    return s


def _token_b64_stringify(text: str, alphabet: str = ENCODE_MAP) -> str:
    """CryptoJS-style Base64.stringify with :data:`ENCODE_MAP` (no reverse / no magic)."""

    data = text.encode("utf-8")
    out: list[str] = []
    index = 0
    length = len(data)
    while index < length:
        b1 = data[index]
        b2 = data[index + 1] if index + 1 < length else 0
        b3 = data[index + 2] if index + 2 < length else 0
        triplet = (b1 << 16) | (b2 << 8) | b3
        remaining = length - index
        out.append(alphabet[(triplet >> 18) & 63])
        out.append(alphabet[(triplet >> 12) & 63])
        if remaining > 1:
            out.append(alphabet[(triplet >> 6) & 63])
        if remaining > 2:
            out.append(alphabet[triplet & 63])
        index += 3
    return "".join(out)


def _token_timestamp_tail(now_ms: int) -> bytes:
    """5-byte tail: little-endian low 32 bits of ``now_ms`` + high byte."""

    low = now_ms & 0xFFFFFFFF
    high = (now_ms >> 32) & 0xFF
    return low.to_bytes(4, "little") + bytes((high,))


def _clt_random_strings(random) -> tuple[str, str]:
    """``_$clt`` consumes ``_$Y8(11)`` then ``_$Y8(10)`` after fingerprint."""

    return (
        _token_y8(CLT_EXTEND_RANDOM_LEN, random),
        _token_y8(CLT_TOP_RANDOM_LEN, random),
    )


def _token_expr(random) -> str:
    """Build expr field: Base64(digit+op+digit+material[:5]+digit).

    Must run on the PRNG stream *after* fingerprint and ``_$clt`` (21 draws).
    Historically an equivalent body was obtained by y8(32) first then burning
    21 draws and taking ``material[-10:-5]`` (same five raw picks via Y8 layout).
    """

    material = _token_y8(TOKEN_EXPR_MATERIAL_LEN, random)
    # Four Math.random draws: first unused for digit/op on this build; next three pick chars.
    _ = random()
    d1 = TOKEN_EXPR_DIGITS[int(random() * 3)]
    op = TOKEN_EXPR_OPS[int(random() * 2)]
    d2 = TOKEN_EXPR_DIGITS[int(random() * 3)]
    body = material[:5]
    plain = f"{d1}{op}{d2}{body}{d2}"
    return _token_b64_stringify(plain)


def _token_cipher(fingerprint: str, now_ms: int, random) -> str:
    """Build cipher field: ``encode(md5_prefix + e8 + y8 + ts_tail + ver + fp)``.

    The MD5 checksum is taken over a *rotated* y8 (``y8[5:]+y8[:5]``) body, while
    the encoded plaintext keeps the original y8 order.
    """

    y8 = _token_y8(TOKEN_CIPHER_Y8_LEN, random)
    rotated = y8[5:] + y8[:5]
    tail = _token_timestamp_tail(now_ms)
    # MD5 body uses rotated y8; encode body uses original order.
    md5_body = b"e8" + rotated.encode("latin-1") + tail + TOKEN_VERSION_BYTES + fingerprint.encode(
        "latin-1"
    )
    head = hashlib.md5(md5_body).hexdigest()[:8]
    enc_body = b"e8" + y8.encode("latin-1") + tail + TOKEN_VERSION_BYTES + fingerprint.encode(
        "latin-1"
    )
    blob = head.encode("latin-1") + enc_body
    return custom_encode(blob.decode("latin-1"))


def generate_default_token(
    fingerprint: str,
    *,
    now_ms: int,
    seed: int | None = DEFAULT_PRNG_SEED,
    random=None,
    advance_fp_stream: bool = True,
    advance_clt_stream: bool = True,
) -> str:
    """Pure ``_$YE(fingerprint)`` defaultToken for the pinned build.

    Token layout::

        magic + version + platform + adler8 + expires + producer + expr + cipher
        tk    + 06      + w        + md5[:8]+ 41      + l        + ...  + ...

    ``adler8`` is vendor MD5 (seData) of
    ``magic+version+platform+version+expires+producer+expr+cipher``, first 8 hex chars.

    Full-sign PRNG order (after seed PRNG create)::

        warmup(1) → fingerprint(24) → clt y8(11)+y8(10) → token y8(32)+4floor+y8(12)

    When ``random`` is omitted, a PRNG is built from ``seed`` and advanced past
    warmup / fingerprint / clt draws so the stream matches a full sign. Pass
    ``advance_fp_stream=False`` / ``advance_clt_stream=False`` if ``random`` is
    already positioned after those stages (e.g. after :func:`generate_part8`).
    """

    if random is None:
        if seed is None:
            raise ValueError("seed or random callable is required")
        random = make_prng(seed)
        random()  # module-load warmup
        if advance_fp_stream:
            for _ in range(FP_RANDOM_DRAWS):
                random()
        if advance_clt_stream:
            _clt_random_strings(random)
    elif advance_clt_stream:
        _clt_random_strings(random)

    expr = _token_expr(random)
    cipher = _token_cipher(fingerprint, now_ms, random)
    material = (
        f"{TOKEN_MAGIC}{TOKEN_VERSION}{TOKEN_PLATFORM}"
        f"{TOKEN_VERSION}{TOKEN_EXPIRES}{TOKEN_PRODUCER}"
        f"{expr}{cipher}"
    )
    adler8 = md5_hex(material)[:8]
    return (
        f"{TOKEN_MAGIC}{TOKEN_VERSION}{TOKEN_PLATFORM}"
        f"{adler8}{TOKEN_EXPIRES}{TOKEN_PRODUCER}{expr}{cipher}"
    )


def canvas_fingerprint_from_data_url(data_url: str) -> str:
    """Canvas env field / ``WQ_gather_cv1.v`` for the official snapshot.

    Readable ``_$Yo`` draws on a 2d canvas then effectively fingerprints the
    data URL. On the pinned official build the stored value is **standard MD5**
    (raw, no seData) of ``canvas.toDataURL()`` as hex. Under browser_shim
    ``getContext`` is null so collection throws and the ``canvas`` key is
    omitted from part8 (golden path).
    """

    return hashlib.md5(data_url.encode("utf-8")).hexdigest()


def pack_env_storage(
    value: str,
    *,
    now_ms: int,
    expires_ms: int = ENV_STORAGE_EXPIRES_MS,
) -> str:
    """JSON envelope written to ``WQ_gather_cv1`` / ``WQ_gather_wgl1`` etc."""

    return json.dumps(
        {"v": value, "t": now_ms, "e": expires_ms},
        ensure_ascii=False,
        separators=(",", ":"),
    )


def unpack_env_storage(raw: str | None) -> str:
    """Read ``.v`` from a gather storage envelope; empty if missing/invalid."""

    if not raw:
        return ""
    try:
        obj = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(obj, dict):
        return ""
    value = obj.get("v")
    return value if isinstance(value, str) else ""


def webgl_fp_from_storage(raw: str | None) -> str:
    """``webglFp`` field: vendor only *reads* ``WQ_gather_wgl1`` in this build.

    The pinned ``js_security`` snapshot never *writes* WebGL fingerprints.
    Generation lives outside this file (encrypted rac payload / other hosts).
    Empty storage → ``\"\"`` (golden).
    """

    return unpack_env_storage(raw)


def resolve_plabel(
    *,
    pflag_value: str | None = None,
    pflag_valid: bool | None = None,
    default: str = ENV_PLABEL_DEFAULT,
) -> str:
    """Resolve ``bu14`` / pLabel the way vendor token-read does.

    If a valid behavior pFlag payload is present, use its ``v``; otherwise the
    hard-coded default ``VRAEjxVEtV``.
    """

    if pflag_value is not None and (pflag_valid is None or pflag_valid):
        return pflag_value
    return default


def infer_extend_statics(
    *,
    webdriver: bool = False,
    plugins_length: int | None = None,
    phantom: bool = False,
    cypress: bool = False,
    bu4: int | None = None,
    bu5: int | None = None,
    base: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Best-effort extend statics from host signals (differential under shim).

    Defaults start from :data:`ENV_EXTEND_STATICS` (golden). Known mappings:

    * ``webdriver`` → ``wd`` 0/1
    * ``plugins_length`` → ``ls`` when provided (else leave base)
    * ``phantom`` → ``wk`` 80 (else 64)
    * ``cypress`` → ``bu5 |= 0x20``
    * ``bu4`` / ``bu5`` explicit overrides win last
    """

    out = dict(ENV_EXTEND_STATICS if base is None else base)
    out["wd"] = 1 if webdriver else 0
    if plugins_length is not None:
        out["ls"] = plugins_length
    out["wk"] = 80 if phantom else 64
    flags = int(out.get("bu5", 0) or 0)
    if cypress:
        flags |= BU5_BIT_CYPRESS
    if bu5 is not None:
        flags = bu5
    out["bu5"] = flags
    if bu4 is not None:
        out["bu4"] = bu4
    return out


def build_env_json(
    fingerprint: str,
    now_ms: int,
    extend_random: str,
    top_random: str,
    *,
    bu14: str = ENV_BU14,
    sua: str = ENV_SUA,
    pf: str = ENV_PF,
    version: str = ENV_VERSION,
    ccn: int = ENV_CCN,
    webgl_fp: str = ENV_WEBGL_FP,
    bu4_top: str = ENV_BU4_TOP,
    canvas: str | None = None,
    extend_statics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the ``_$clt`` env object (key order matches vendor stringify).

    Top-level allowlist fields for the env mode used by part8 include
    ``sua/pp/extend/pf/random/v/bu4/canvas/webglFp/ccn/bu14`` plus ``t``/``fp``
    added by ``_$clt``. The ``canvas`` key is only present when collection
    succeeds (pass a non-empty ``canvas=`` fingerprint to include it).
    """

    statics = dict(ENV_EXTEND_STATICS if extend_statics is None else extend_statics)
    extend: dict[str, Any] = {
        "wd": statics["wd"],
        "l": statics["l"],
        "ls": statics["ls"],
        "wk": statics["wk"],
        "bu1": statics["bu1"],
        "bu3": statics["bu3"],
        "bu4": statics["bu4"],
        "bu5": statics["bu5"],
        "bu6": statics["bu6"],
        "bu7": statics["bu7"],
        "bu8": statics["bu8"],
        "random": extend_random,
        "bu12": statics["bu12"],
        "bu10": statics["bu10"],
        "bu11": statics["bu11"],
    }
    env: dict[str, Any] = {
        "sua": sua,
        "pp": {},
        "extend": extend,
        "pf": pf,
        "random": top_random,
        "v": version,
        "bu4": bu4_top,
    }
    # Vendor insertion order when canvas collection succeeds: after bu4, before webglFp.
    if canvas:
        env["canvas"] = canvas
    env["webglFp"] = webgl_fp
    env["ccn"] = ccn
    env["bu14"] = bu14
    env["t"] = now_ms
    env["fp"] = fingerprint
    return env


def env_json_text(env: Mapping[str, Any]) -> str:
    """Pretty JSON matching vendor ``JSON.stringify(env, null, 2)`` for part8."""

    return json.dumps(dict(env), ensure_ascii=False, indent=2)


def generate_part8(
    fingerprint: str,
    *,
    now_ms: int,
    seed: int | None = DEFAULT_PRNG_SEED,
    random=None,
    advance_fp_stream: bool = True,
    bu14: str = ENV_BU14,
    **env_kwargs: Any,
) -> str:
    """Pure ``_$clt`` part8: ``encode(JSON.stringify(env, null, 2))``.

    Consumes ``_$Y8(11)`` + ``_$Y8(10)`` from the shared PRNG after fingerprint.
    Static collector fields match browser_shim for the pinned golden; override
    via kwargs / ``bu14=`` when the host environment differs.
    """

    if random is None:
        if seed is None:
            raise ValueError("seed or random callable is required")
        random = make_prng(seed)
        random()  # module-load warmup
        if advance_fp_stream:
            for _ in range(FP_RANDOM_DRAWS):
                random()

    extend_random, top_random = _clt_random_strings(random)
    env = build_env_json(
        fingerprint,
        now_ms,
        extend_random,
        top_random,
        bu14=bu14,
        **env_kwargs,
    )
    return custom_encode(env_json_text(env))


def generate_fingerprint_and_token(
    *,
    now_ms: int,
    seed: int = DEFAULT_PRNG_SEED,
) -> tuple[str, str]:
    """Generate fingerprint and defaultToken from one shared PRNG stream.

    Burns the ``_$clt`` random draws between fingerprint and token so the token
    matches a full sign (same as :func:`generate_fingerprint_part8_and_token`
    without returning part8).
    """

    fingerprint, _part8, token = generate_fingerprint_part8_and_token(
        now_ms=now_ms,
        seed=seed,
    )
    return fingerprint, token


def generate_fingerprint_part8_and_token(
    *,
    now_ms: int,
    seed: int = DEFAULT_PRNG_SEED,
    bu14: str = ENV_BU14,
    **env_kwargs: Any,
) -> tuple[str, str, str]:
    """Shared stream: warmup → fingerprint → part8 → defaultToken."""

    random = make_prng(seed)
    random()  # module-load warmup
    fingerprint = generate_fingerprint(random=random)
    part8 = generate_part8(
        fingerprint,
        now_ms=now_ms,
        random=random,
        advance_fp_stream=False,
        bu14=bu14,
        **env_kwargs,
    )
    token = generate_default_token(
        fingerprint,
        now_ms=now_ms,
        random=random,
        advance_fp_stream=False,
        advance_clt_stream=False,
    )
    return fingerprint, part8, token


def join_sign_body(sorted_params: list[dict[str, str]]) -> str:
    """Alias of :func:`make_sign_body` for earlier call sites."""

    return make_sign_body(sorted_params)


def join_h5st_parts(parts: Iterable[str]) -> str:
    return ";".join(parts)


def _base64_encode_map(data: bytes, alphabet: str = ENCODE_MAP) -> str:
    """CryptoJS-style Base64 without ``=`` padding (input length is a multiple of 3)."""

    if len(alphabet) != 64:
        raise ValueError("alphabet must contain 64 characters")
    out: list[str] = []
    for index in range(0, len(data), 3):
        b1 = data[index]
        b2 = data[index + 1] if index + 1 < len(data) else 0
        b3 = data[index + 2] if index + 2 < len(data) else 0
        triplet = (b1 << 16) | (b2 << 8) | b3
        out.append(alphabet[(triplet >> 18) & 63])
        out.append(alphabet[(triplet >> 12) & 63])
        out.append(alphabet[(triplet >> 6) & 63])
        out.append(alphabet[triplet & 63])
    return "".join(out)


def _reverse_base64_blocks(encoded: str) -> str:
    """Reverse each 4-char block, then reverse block order."""

    if len(encoded) % 4 != 0:
        raise ValueError("encoded length must be a multiple of 4")
    blocks = [encoded[i : i + 4][::-1] for i in range(0, len(encoded), 4)]
    blocks.reverse()
    return "".join(blocks)


def custom_encode(plain_text: str, *, alphabet: str = ENCODE_MAP, magic: str = ENCODE_MAGIC) -> str:
    """Vendor ``encode`` used for part8/part10/token fragments (entry 473).

    Algorithm (this build, deterministic — no PRNG inside encode):

    1. latin-1 bytes of input
    2. if ``len % 3 != 0``, pad with ``pad`` bytes of value ``pad`` where ``pad = 3 - len%3``
    3. custom base64 with :data:`ENCODE_MAP`
    4. reverse every 4-char group, then reverse group order
    5. if original length is a multiple of 3 (including empty), prepend ``of7r``
    """

    data = bytearray(plain_text.encode("latin-1"))
    original_len = len(data)
    rem = original_len % 3
    if rem != 0:
        pad = 3 - rem
        data.extend([pad] * pad)
    if not data:
        return magic
    encoded = _base64_encode_map(bytes(data), alphabet)
    transformed = _reverse_base64_blocks(encoded)
    if original_len % 3 == 0:
        return magic + transformed
    return transformed


def part10_from_stk(stk: str) -> str:
    """Part 10 is ``encode(stk)`` where stk is comma-joined signed keys."""

    return custom_encode(stk)
