#!/usr/bin/env python3
"""Convenience API built on the in-process h5st QuickJS runtime."""

from __future__ import annotations

import json
import time
from typing import Any, Mapping

try:
    from .h5st_runtime import generate_h5st as _generate_h5st
except ImportError:  # direct execution from utils/
    from h5st_runtime import generate_h5st as _generate_h5st


def generate_h5st(
    app_id: str,
    params: Mapping[str, Any],
    token: str = "",
    *,
    now_ms: int | None = None,
    seed: int | None = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    """Generate a ten-part h5st record without starting a Node process.

    ``app_id`` is the short ParamsSign application identifier.  It is distinct
    from the request field commonly named ``params["appid"]``.
    """

    return _generate_h5st(
        app_id,
        params,
        token=token or None,
        now_ms=now_ms,
        seed=seed,
        fingerprint=fingerprint,
    )


def generate_h5st_for_search(
    keyword: str,
    page: int = 1,
    *,
    app_id: str = "rdv6s",
    now_ms: int | None = None,
    seed: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the sampled search parameter shape and sign it locally."""

    timestamp = int(time.time() * 1000) if now_ms is None else int(now_ms)
    params: dict[str, Any] = {
        "appid": "search-pc-java",
        "functionId": "pc_search_searchWare",
        "t": str(timestamp),
        "body": json.dumps(
            {
                "enc": "utf-8",
                "pvid": f"fixture-pvid-{timestamp}",
                "from": "home",
                "area": "1_2_3_4",
                "page": page,
                "mode": "",
                "concise": False,
                "hoverPictures": True,
                "newAdvRepeat": False,
                "mixerParam": False,
                "new_interval": True,
                "s": 27,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        "client": "pc",
        "clientVersion": "1.0.0",
        "uuid": f"fixture-uuid-{timestamp}",
        "loginType": "3",
        "keyword": keyword,
    }
    params.update(extra)
    return generate_h5st(app_id, params, now_ms=now_ms, seed=seed)


def main() -> int:
    fixed_now = 1_700_000_000_123
    result = generate_h5st_for_search(
        "fixture",
        app_id="rdv6s",
        now_ms=fixed_now,
        seed=12_345,
    )
    parts = result["h5st"].split(";")
    print(json.dumps(result, ensure_ascii=False))
    print(f"parts={len(parts)} lengths={[len(part) for part in parts]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
