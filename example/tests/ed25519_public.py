#!/usr/bin/env python3
import sys
import base64
from nacl.signing import SigningKey

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <32-byte-private-key-base64>")
    sys.exit(1)

b64_priv = sys.argv[1]

# Decode Base64 to bytes
try:
    priv_bytes = base64.b64decode(b64_priv)
except Exception as e:
    print("Invalid Base64:", e)
    sys.exit(1)

if len(priv_bytes) != 32:
    print("Private key must be exactly 32 bytes")
    sys.exit(1)

# Create SigningKey from private key
sk = SigningKey(priv_bytes)

# Compute public key
vk = sk.verify_key

# Encode both keys in Base64
b64_private = base64.b64encode(priv_bytes).decode('ascii')
b64_public = base64.b64encode(vk.encode()).decode('ascii')

print("Private key (Base64):", b64_private)
print("Public  key (Base64):", b64_public)

