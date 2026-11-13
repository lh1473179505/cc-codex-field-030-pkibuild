"""CLI. inspect already works; build is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pkibuild.certs import CertError, load_bundle
from pkibuild.sign import check_sig


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkibuild")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="list certificates and whether their HMAC verifies against the keyring")
    ins.add_argument("--bundle", required=True)
    bld = sub.add_parser("build", help="build and validate a certification path for a leaf")
    bld.add_argument("--bundle", required=True)
    bld.add_argument("--leaf", required=True, help="serial of the leaf certificate")
    bld.add_argument("--now", type=int, default=1763000000)
    bld.add_argument("--eku", required=False, help="required extended key usage, e.g. serverAuth")
    bld.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        bundle = load_bundle(args.bundle)
    except (OSError, json.JSONDecodeError, CertError) as exc:
        print(f"failed to load bundle: {exc}", file=sys.stderr)
        return 2
    keys = (bundle["raw"].get("keys") or {})

    if args.cmd == "inspect":
        def rows(certs):
            out = []
            for c in certs:
                out.append({**c.as_dict(), "hmac_ok": check_sig(c.raw, keys)})
            return out
        print(json.dumps({
            "anchors": rows(bundle["trust_anchors"]),
            "certs": rows(bundle["certs"]),
            "crls": bundle["crls"],
        }, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "build":
        from pkibuild.engine import build_path
        try:
            report = build_path(bundle, args.leaf, args.now, args.eku)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
