"""HMAC helpers so inspect can show whether a stored signature is well-formed.

This does not decide trust. Path building must still start from a trust anchor
and must not treat a valid HMAC as sufficient.
"""

from __future__ import annotations

import hashlib
import hmac

from pkibuild.certs import tbs_bytes


def sign(tbs: bytes, key_hex: str) -> str:
    return hmac.new(bytes.fromhex(key_hex), tbs, hashlib.sha256).hexdigest()


def check_sig(cert_obj: dict, keys: dict[str, str]) -> bool:
    key = keys.get(cert_obj.get("sig_key") or "")
    if not key:
        return False
    actual = cert_obj.get("signature") or ""
    expect = sign(tbs_bytes(cert_obj), key)
    return hmac.compare_digest(actual, expect)
