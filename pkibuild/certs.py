"""Load JSON certificates, trust anchors, and CRLs. Path building is not implemented here."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CertError(Exception):
    pass


@dataclass
class Name:
    cn: str
    org: str | None = None
    ou: str | None = None
    country: str | None = None
    dns: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    email: list[str] = field(default_factory=list)

    def rfc4514(self) -> str:
        parts = []
        if self.country:
            parts.append(f"C={self.country}")
        if self.org:
            parts.append(f"O={self.org}")
        if self.ou:
            parts.append(f"OU={self.ou}")
        parts.append(f"CN={self.cn}")
        return ",".join(parts)


@dataclass
class NameConstraints:
    permitted_dns: list[str] = field(default_factory=list)
    excluded_dns: list[str] = field(default_factory=list)
    permitted_ip: list[str] = field(default_factory=list)
    excluded_ip: list[str] = field(default_factory=list)


@dataclass
class Certificate:
    serial: str
    subject: Name
    issuer: Name
    ski: str
    aki: str | None
    not_before: int
    not_after: int
    ca: bool
    path_len: int | None
    key_usage: list[str]
    eku: list[str]
    name_constraints: NameConstraints | None
    sig_key: str
    signature: str
    raw: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "subject": self.subject.rfc4514(),
            "issuer": self.issuer.rfc4514(),
            "ca": self.ca,
            "ski": self.ski,
            "aki": self.aki,
        }


def _name(obj: dict[str, Any]) -> Name:
    san = obj.get("san") or {}
    return Name(
        cn=str(obj["cn"]),
        org=obj.get("org"),
        ou=obj.get("ou"),
        country=obj.get("country"),
        dns=list(san.get("dns") or []),
        ip=list(san.get("ip") or []),
        email=list(san.get("email") or []),
    )


def _nc(obj: Any) -> NameConstraints | None:
    if not obj:
        return None
    return NameConstraints(
        permitted_dns=list(obj.get("permitted_dns") or []),
        excluded_dns=list(obj.get("excluded_dns") or []),
        permitted_ip=list(obj.get("permitted_ip") or []),
        excluded_ip=list(obj.get("excluded_ip") or []),
    )


def load_cert(obj: dict[str, Any]) -> Certificate:
    try:
        return Certificate(
            serial=str(obj["serial"]),
            subject=_name(obj["subject"]),
            issuer=_name(obj["issuer"]),
            ski=str(obj["ski"]),
            aki=obj.get("aki"),
            not_before=int(obj["not_before"]),
            not_after=int(obj["not_after"]),
            ca=bool(obj.get("ca", False)),
            path_len=obj.get("path_len"),
            key_usage=list(obj.get("key_usage") or []),
            eku=list(obj.get("eku") or []),
            name_constraints=_nc(obj.get("name_constraints")),
            sig_key=str(obj["sig_key"]),
            signature=str(obj["signature"]),
            raw=obj,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CertError(f"bad cert: {exc}") from exc


def load_bundle(path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    certs = [load_cert(c) for c in raw.get("certs") or []]
    anchors = [load_cert(c) for c in raw.get("trust_anchors") or []]
    crls = raw.get("crls") or []
    return {"certs": certs, "trust_anchors": anchors, "crls": crls, "raw": raw}


def tbs_bytes(obj: dict[str, Any]) -> bytes:
    """Canonical TBS used by the lab signatures: JSON with sort_keys and no signature field."""
    body = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
