#!/usr/bin/env python3
"""Build the remote app-identities blob.

The JSON (format 1) lists the plain-key app credentials used by
AppIdentities: label, productType, securityVersion, regions, default,
privateKeyHex and certificateHex. It never goes in the repository; the host
app downloads the xz-compressed blob and RoundWhiteDiscKit checks its
SHA-256 against AppIdentities.expectedPayloadSHA256.

    Scripts/build_app_identities_blob.py --json RemoteTables/RWDAppIdentities.json
"""
import argparse
import hashlib
import json
import lzma
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_JSON = os.path.join(REPO, "RemoteTables", "RWDAppIdentities.json")
DEFAULT_OUT = os.path.join(REPO, "RemoteTables", "roundwhitedisckit-app-identities-v1.xz")


def check(payload: bytes) -> None:
    doc = json.loads(payload)
    assert doc["format"] == 1 and doc["curve"] == "P-256", "unsupported format"
    for entry in doc["identities"]:
        cert = bytes.fromhex(entry["certificateHex"])
        assert len(cert) == 162 and cert[33] == 0x04, f"{entry['label']}: bad certificate"
        key = ec.derive_private_key(int(entry["privateKeyHex"], 16), ec.SECP256R1())
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        assert point == cert[33:98], f"{entry['label']}: key and certificate disagree"
        print(f"  {entry['label']:4} regions={entry['regions']} default={entry['default']}  ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default=DEFAULT_JSON)
    ap.add_argument("-o", "--output", default=DEFAULT_OUT)
    args = ap.parse_args()

    payload = open(args.json, "rb").read()
    check(payload)
    blob = lzma.compress(payload, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32,
                         preset=9 | lzma.PRESET_EXTREME)
    assert lzma.decompress(blob) == payload
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(blob)
    print(f"wrote {args.output} ({len(blob)} bytes)")
    print(f"blob sha256    {hashlib.sha256(blob).hexdigest()}")
    print(f"payload sha256 {hashlib.sha256(payload).hexdigest()}  (expectedPayloadSHA256)")


if __name__ == "__main__":
    main()
