#!/usr/bin/env python3
"""Check original spec and pinned browser crypto assets without network access."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def verify(directory, entries):
    for name, expected in entries.items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory) or not path.is_file():
            raise SystemExit(f"Invalid integrity manifest path: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Integrity mismatch: {path.relative_to(ROOT)}")
    return len(entries)


spec = ROOT / "docs/security/spec-v1.1"
count = verify(spec, json.loads((spec / "SHA256SUMS.json").read_text()))
vendor = ROOT / "ui/static/vendor/hash-wasm-4.12.0"
count += verify(vendor, json.loads((vendor / "provenance.json").read_text())["files"])
print(f"Verified {count} original specification and vendored crypto files.")
