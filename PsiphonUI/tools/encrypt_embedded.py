#!/usr/bin/env python3
"""
One-shot tool that encrypts the Psiphon embedded values + server entries
with AES-256-GCM and emits:

  - Services/SecretStore.cs (key-share byte arrays + helper)
  - Services/EmbeddedValues.cs (encrypted blobs as byte[] fields)
  - Resources/server_entries.bin (encrypted server-list blob)

The runtime SecretStore reconstructs the AES key from three byte arrays at
load time via HMAC-SHA256(salt=alpha^beta, password=gamma). Each share is
random per run of this tool, so each rebuild rotates the at-rest key without
changing any runtime behaviour.

Run from the PsiphonUI/ directory:

    python3 tools/encrypt_embedded.py

The script reads the plaintext values from Services/EmbeddedValues.plaintext.json
(generated from the current EmbeddedValues.cs by this script, see --extract)
and the server entries from Resources/server_entries.txt, then overwrites
the .cs files and writes the .bin blob.
"""

import argparse
import json
import os
import re
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("Please `pip install cryptography` first")

import hashlib
import hmac


REPO_ROOT = Path(__file__).resolve().parent.parent
EMBEDDED_VALUES = REPO_ROOT / "Services" / "EmbeddedValues.cs"
SECRET_STORE = REPO_ROOT / "Services" / "SecretStore.cs"
SERVER_ENTRIES_TXT = REPO_ROOT / "Resources" / "server_entries.txt"
SERVER_ENTRIES_BIN = REPO_ROOT / "Resources" / "server_entries.bin"
PLAINTEXT_JSON = REPO_ROOT / "Services" / "EmbeddedValues.plaintext.json"

VALUES_ORDER = [
    "PropagationChannelId",
    "SponsorId",
    "ClientVersion",
    "ClientPlatform",
    "RemoteServerListSignaturePublicKey",
    "ServerEntrySignaturePublicKey",
    "FeedbackEncryptionPublicKey",
    "RemoteServerListUrlsJson",
    "ObfuscatedServerListRootUrlsJson",
    "FeedbackUploadUrlsJson",
]


def extract_plaintexts() -> dict[str, str]:
    """Parse the current EmbeddedValues.cs and pull each const string out."""
    src = EMBEDDED_VALUES.read_text(encoding="utf-8")
    values: dict[str, str] = {}

    for name in VALUES_ORDER:
        m = re.search(
            r'public\s+(?:const|static\s+readonly)\s+string\s+'
            + re.escape(name)
            + r'\s*(?:=>|=)\s*((?:"""[\s\S]*?"""|"[^"]*"(?:\s*\+\s*"[^"]*")*))\s*;',
            src,
        )
        if not m:
            raise SystemExit(f"Could not find plaintext for {name} in EmbeddedValues.cs")

        literal = m.group(1).strip()
        if literal.startswith('"""'):
            inner = literal[3:-3]
        else:
            parts = re.findall(r'"([^"]*)"', literal)
            inner = "".join(parts)
        values[name] = inner

    return values


def derive_key(alpha: bytes, beta: bytes, gamma: bytes) -> bytes:
    salt = bytes(a ^ b for a, b in zip(alpha, beta))
    return hmac.new(salt, gamma, hashlib.sha256).digest()


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    ct_and_tag = aes.encrypt(nonce, plaintext, None)
    return nonce + ct_and_tag


def fmt_bytes(name: str, data: bytes, indent: int = 4) -> str:
    pad = " " * indent
    body_pad = " " * (indent + 4)
    chunks = []
    line = []
    for i, b in enumerate(data):
        line.append(f"0x{b:02X}")
        if (i + 1) % 16 == 0:
            chunks.append(", ".join(line))
            line = []
    if line:
        chunks.append(", ".join(line))
    body = ",\n".join(body_pad + c for c in chunks)
    return f"{pad}private static readonly byte[] {name} = new byte[]\n{pad}{{\n{body}\n{pad}}};"


def write_secret_store(alpha: bytes, beta: bytes, gamma: bytes) -> None:
    s = f"""using System;
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace PsiphonUI.Services;

internal static class SecretStore
{{
{fmt_bytes("Alpha", alpha)}

{fmt_bytes("Beta", beta)}

{fmt_bytes("Gamma", gamma)}

    private static readonly ConcurrentDictionary<int, string> StringCache = new();
    private static readonly ConcurrentDictionary<int, byte[]> BytesCache = new();

    private static byte[] DeriveKey()
    {{
        var salt = new byte[Alpha.Length];
        for (var i = 0; i < Alpha.Length; i++)
        {{
            salt[i] = (byte)(Alpha[i] ^ Beta[i]);
        }}
        using var mac = new HMACSHA256(salt);
        return mac.ComputeHash(Gamma);
    }}

    public static string DecryptString(byte[] blob)
    {{
        var key = System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(blob);
        if (StringCache.TryGetValue(key, out var cached))
        {{
            return cached;
        }}
        var plain = Decrypt(blob);
        var s = Encoding.UTF8.GetString(plain);
        StringCache[key] = s;
        return s;
    }}

    public static byte[] DecryptBytes(byte[] blob)
    {{
        var key = System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(blob);
        if (BytesCache.TryGetValue(key, out var cached))
        {{
            return cached;
        }}
        var plain = Decrypt(blob);
        BytesCache[key] = plain;
        return plain;
    }}

    public static byte[] DecryptResource(string resourceName)
    {{
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded resource not found: {{resourceName}}");
        var buf = new byte[stream.Length];
        var read = 0;
        while (read < buf.Length)
        {{
            var n = stream.Read(buf, read, buf.Length - read);
            if (n <= 0) break;
            read += n;
        }}
        return Decrypt(buf);
    }}

    private static byte[] Decrypt(byte[] blob)
    {{
        if (blob.Length < 12 + 16)
        {{
            throw new CryptographicException("Encrypted payload too short");
        }}
        var nonce = new byte[12];
        Buffer.BlockCopy(blob, 0, nonce, 0, 12);
        var tagOffset = blob.Length - 16;
        var tag = new byte[16];
        Buffer.BlockCopy(blob, tagOffset, tag, 0, 16);
        var ctLen = tagOffset - 12;
        var ct = new byte[ctLen];
        Buffer.BlockCopy(blob, 12, ct, 0, ctLen);
        var plain = new byte[ctLen];
        var aesKey = DeriveKey();
        try
        {{
            using var aes = new AesGcm(aesKey, 16);
            aes.Decrypt(nonce, ct, tag, plain);
        }}
        finally
        {{
            Array.Clear(aesKey, 0, aesKey.Length);
        }}
        return plain;
    }}
}}
"""
    SECRET_STORE.write_text(s, encoding="utf-8")


def write_embedded_values(encrypted: dict[str, bytes]) -> None:
    field_decls = []
    prop_decls = []
    for name in VALUES_ORDER:
        blob_field = f"_e_{name}"
        field_decls.append(fmt_bytes(blob_field, encrypted[name]))
        prop_decls.append(
            f"    public static string {name} => SecretStore.DecryptString({blob_field});"
        )

    body = "\n\n".join(field_decls) + "\n\n" + "\n".join(prop_decls)

    s = f"""namespace PsiphonUI.Services;

internal static class EmbeddedValues
{{
{body}
}}
"""
    EMBEDDED_VALUES.write_text(s, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Just extract the current plaintexts to EmbeddedValues.plaintext.json and exit",
    )
    args = parser.parse_args()

    if args.extract:
        plaintexts = extract_plaintexts()
        PLAINTEXT_JSON.write_text(json.dumps(plaintexts, indent=2), encoding="utf-8")
        print(f"Wrote {PLAINTEXT_JSON}")
        return

    if PLAINTEXT_JSON.exists():
        plaintexts = json.loads(PLAINTEXT_JSON.read_text(encoding="utf-8"))
        print(f"Loaded plaintexts from {PLAINTEXT_JSON}")
    else:
        plaintexts = extract_plaintexts()
        print(f"Extracted plaintexts from {EMBEDDED_VALUES}")

    if not SERVER_ENTRIES_TXT.exists():
        raise SystemExit(f"Missing {SERVER_ENTRIES_TXT}")

    alpha = secrets.token_bytes(32)
    beta = secrets.token_bytes(32)
    gamma = secrets.token_bytes(32)
    key = derive_key(alpha, beta, gamma)

    encrypted_values: dict[str, bytes] = {}
    for name in VALUES_ORDER:
        pt = plaintexts[name].encode("utf-8")
        encrypted_values[name] = encrypt(key, pt)

    server_pt = SERVER_ENTRIES_TXT.read_bytes()
    server_blob = encrypt(key, server_pt)
    SERVER_ENTRIES_BIN.write_bytes(server_blob)

    write_secret_store(alpha, beta, gamma)
    write_embedded_values(encrypted_values)

    print(f"Wrote {SECRET_STORE}")
    print(f"Wrote {EMBEDDED_VALUES}")
    print(f"Wrote {SERVER_ENTRIES_BIN} ({len(server_blob)} bytes)")
    print()
    print("Sanity round-trip:")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _A
    aes = _A(key)
    for name, blob in encrypted_values.items():
        nonce = blob[:12]
        ct = blob[12:]
        dec = aes.decrypt(nonce, ct, None).decode("utf-8")
        ok = dec == plaintexts[name]
        print(f"  {name}: {'OK' if ok else 'MISMATCH'}")
    nonce = server_blob[:12]
    ct = server_blob[12:]
    dec = aes.decrypt(nonce, ct, None)
    print(f"  server_entries.bin: {'OK' if dec == server_pt else 'MISMATCH'} ({len(dec)} bytes)")


if __name__ == "__main__":
    main()
