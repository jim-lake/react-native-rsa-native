#!/usr/bin/env python3
import sys
import base64
from ecdsa import SigningKey, NIST256p

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <hexkey>")
    sys.exit(1)

hexkey = sys.argv[1]
key_bytes = bytes.fromhex(hexkey)

# EC key format: 0x04 + public key + private key
if key_bytes[0] != 0x04:
    print("Expected uncompressed EC point (0x04 prefix)")
    sys.exit(1)

public_key_len = 64  # P-256: 32 X + 32 Y
if len(key_bytes) <= 1 + public_key_len:
    print("Key too short")
    sys.exit(1)

# Slice out public and private parts
public_bytes = key_bytes[1 : 1 + public_key_len]
private_bytes = key_bytes[1 + public_key_len :]

# Base64 of extracted public and private
b64_public_extracted = base64.b64encode(public_bytes).decode('ascii')
b64_private = base64.b64encode(private_bytes).decode('ascii')

# Recompute public key from private key
sk = SigningKey.from_string(private_bytes, curve=NIST256p)
vk = sk.verifying_key
computed_pub_bytes = vk.to_string()
b64_public_computed = base64.b64encode(computed_pub_bytes).decode('ascii')

# Print all
print("Extracted public key (Base64):", b64_public_extracted)
print("Computed public key  (Base64):", b64_public_computed)
print("Private key         (Base64):", b64_private)

# Verify match
if public_bytes == computed_pub_bytes:
    print("✅ Public key verification succeeded!")
else:
    print("❌ Public key mismatch!")
