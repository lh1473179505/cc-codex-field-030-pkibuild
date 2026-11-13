"""Certification path building. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any


def build_path(bundle: dict[str, Any], leaf_serial: str, now: int, required_eku: str | None) -> dict[str, Any]:
    raise NotImplementedError("build_path is not implemented in this snapshot")
