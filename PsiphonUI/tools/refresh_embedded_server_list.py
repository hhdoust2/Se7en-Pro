#!/usr/bin/env python3
"""
Refresh PsiphonUI/Resources/server_entries.txt by merging the upstream
Psiphon remote-server-list (DSL) into the bundled embedded list.

Why: the embedded list ships only ~400 entries baked in at build time; the
FRONTED-MEEK-CDN-OSSH variant only exists for a handful of egress regions
(GB, US, CA, ...).  The official client gets the rest of the network at
runtime by fetching the upstream DSL.  For our build to connect to FR / DE
/ JP via CDN fronting on a *fresh* install (empty %LOCALAPPDATA%\\Psiphon
\\tunnel-core\\data folder, no cached BoltDB), the entries that come back
from that DSL need to be present in the embedded list as well.

Usage: python3 tools/refresh_embedded_server_list.py

The script:
  1. Downloads https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed
  2. Verifies the RSA-PKCS1v15+SHA256 signature against the public key
     baked into EmbeddedValues.cs (RemoteServerListSignaturePublicKey).
  3. Decompresses the inner JSON (zlib).
  4. Parses each line as a tunnel-core server entry (hex-encoded with a
     "0 0 0 0 " prefix followed by JSON).
  5. Deduplicates against the current Resources/server_entries.txt by
     (ipAddress, sshPort) and appends the new entries to the end so the
     existing per-installation ordering is preserved.

Dependencies: cryptography (pip install cryptography).
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
import zlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMBED_VALUES = os.path.join(ROOT, "Services", "EmbeddedValues.cs")
SERVER_ENTRIES = os.path.join(ROOT, "Resources", "server_entries.txt")
DSL_URL = "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"


def extract_pubkey_b64(path: str) -> str:
    text = open(path).read()
    m = re.search(r"RemoteServerListSignaturePublicKey\s*=\s*(.+?);", text, re.DOTALL)
    if not m:
        raise SystemExit("RemoteServerListSignaturePublicKey not found in " + path)
    return "".join(re.findall(r'"([^"]+)"', m.group(1)))


def parse_entry(line: str):
    try:
        text = bytes.fromhex(line.strip()).decode("utf-8", errors="replace")
    except ValueError:
        return None
    idx = text.find("{")
    if idx < 0:
        return None
    try:
        return json.loads(text[idx:])
    except json.JSONDecodeError:
        return None


def key_of(obj: dict) -> str:
    return f"{obj.get('ipAddress')}:{obj.get('sshPort', obj.get('webServerPort', 0))}"


def main() -> int:
    pubkey_b64 = extract_pubkey_b64(EMBED_VALUES)
    pubkey = serialization.load_der_public_key(base64.b64decode(pubkey_b64))

    print(f"Fetching {DSL_URL} ...")
    with urllib.request.urlopen(DSL_URL, timeout=30) as r:
        compressed = r.read()
    print(f"  {len(compressed)} bytes compressed")

    raw = zlib.decompress(compressed)
    obj = json.loads(raw)
    data_bytes = obj["data"].encode("utf-8")
    sig = base64.b64decode(obj["signature"])

    pubkey.verify(sig, data_bytes, padding.PKCS1v15(), hashes.SHA256())
    print("  signature verified (RSA-PKCS1v15+SHA256)")

    dsl_lines = [l for l in obj["data"].split("\n") if l.strip()]
    print(f"  {len(dsl_lines)} entries in upstream DSL")

    existing_lines = [l for l in open(SERVER_ENTRIES).read().split("\n") if l.strip()]
    print(f"  {len(existing_lines)} entries currently embedded")

    seen = set()
    merged = []
    for l in existing_lines:
        e = parse_entry(l)
        if e is None:
            continue
        k = key_of(e)
        if k in seen:
            continue
        seen.add(k)
        merged.append(l)

    added = 0
    for l in dsl_lines:
        e = parse_entry(l)
        if e is None:
            continue
        k = key_of(e)
        if k in seen:
            continue
        seen.add(k)
        merged.append(l)
        added += 1
    print(f"  +{added} new entries from DSL")
    print(f"  = {len(merged)} entries after merge")

    with open(SERVER_ENTRIES, "w") as f:
        f.write("\n".join(merged) + "\n")
    print(f"Wrote {SERVER_ENTRIES}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
