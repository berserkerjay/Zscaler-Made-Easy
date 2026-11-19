#!/usr/bin/env python3
"""Write the Word build guide of one or every DLP policy pack.

    python tools/build_pack_guides.py --all --out docs/packs
    python tools/build_pack_guides.py --pack canada_privacy_baseline --out docs/packs

One file per pack: <out>/<pack_id>_build_guide.docx. It reads the local pack
files only; it never touches a tenant. The same guide is served by the app at
GET /api/dlp-packs/{pack_id}/build-guide.
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import dlp_importer  # noqa: E402
import pack_build_guide  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Write the Word build guide of a DLP policy pack.")
    which = ap.add_mutually_exclusive_group(required=True)
    which.add_argument("--all", action="store_true", help="every pack discover_packs() returns")
    which.add_argument("--pack", metavar="ID", help="one pack id")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "packs"), help="output folder (default docs/packs)")
    ap.add_argument("--prepared-for", default="", help="name for the cover's Prepared for line")
    ap.add_argument("--prepared-by", default="", help="name for the cover's Prepared by line")
    a = ap.parse_args(argv)
    ids = [p["id"] for p in dlp_importer.discover_packs()] if a.all else [a.pack]
    os.makedirs(a.out, exist_ok=True)
    for pid in ids:
        try:
            data = pack_build_guide.build(pid, a.prepared_for, a.prepared_by)
        except pack_build_guide.GuideError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        path = os.path.join(a.out, f"{pid}_build_guide.docx")
        with open(path, "wb") as f:
            f.write(data)
        print(f"wrote {os.path.relpath(path, ROOT) if path.startswith(ROOT) else path} ({len(data) // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
