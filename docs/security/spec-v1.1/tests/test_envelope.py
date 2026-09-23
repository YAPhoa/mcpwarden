#!/usr/bin/env python3
"""Synthetic explicit-nonce AES-GCM interoperability check, not production crypto."""
import base64
import json
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIXTURE = Path(__file__).resolve().parents[1] / "reference" / "envelope-vector.json"


def main() -> None:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    key = bytes.fromhex(vector["key_hex"])
    nonce = bytes.fromhex(vector["nonce_hex"])
    aad = vector["aad_utf8"].encode("utf-8")
    plaintext = vector["plaintext_utf8"].encode("utf-8")
    ciphertext = bytes.fromhex(vector["ciphertext_and_tag_hex"])
    aes = AESGCM(key)
    assert aes.decrypt(nonce, ciphertext, aad) == plaintext
    assert aes.encrypt(nonce, plaintext, aad) == ciphertext
    # This fixed string-only ASCII header needs no general number/Unicode JCS code.
    header = {k: v for k, v in vector["envelope"].items() if k not in {"nonce", "ciphertext"}}
    assert all(isinstance(v, str) and v.isascii() for v in header.values())
    assert json.dumps(header, sort_keys=True, separators=(",", ":")).encode() == aad
    assert base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode() == vector["envelope"]["ciphertext"]
    assert base64.urlsafe_b64encode(nonce).rstrip(b"=").decode() == vector["envelope"]["nonce"]
    variants = [
        (nonce, ciphertext, aad.replace(b'"owner_id":"local"', b'"owner_id":"other"'), key),
        (nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), aad, key),
        (bytes([nonce[0] ^ 1]) + nonce[1:], ciphertext, aad, key),
        (nonce, ciphertext, aad, bytes([key[0] ^ 1]) + key[1:]),
    ]
    for bad_nonce, bad_ciphertext, bad_aad, bad_key in variants:
        try:
            AESGCM(bad_key).decrypt(bad_nonce, bad_ciphertext, bad_aad)
        except InvalidTag:
            continue
        raise AssertionError("Tampered input was accepted")
    print("PASS Python: AES-GCM roundtrip, exact encoding, wrong owner/tag/nonce/key rejection")


if __name__ == "__main__":
    main()
