#!/usr/bin/env python3
import hashlib, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("challenge/data.json") as f:
    data = json.load(f)

p = int(data["p"], 16)
q = int(data["q"], 16)
g = int(data["g"], 16)
pub = int(data["pub"], 16)
log_g = int(data["log_g"], 16)
log_pub = int(data["log_pub"], 16)

# Compute private scalar x = log(pub) * log(g)^-1 mod q
x = (log_pub * pow(log_g, -1, q)) % q
assert pow(g, x, p) == pub

print(f"[+] Group modulus p: {p.bit_length()}-bit prime (vulnerable to NFS DLP)")
print(f"[+] Subgroup order q: {q.bit_length()}-bit prime")
print(f"[+] Recovered Private Scalar: {hex(x)}")

# Derive AES-GCM key and decrypt sealed ciphertext
key = hashlib.sha256(b"SecLeaf/shadow-redshift/v3/secret|" + x.to_bytes(20, "big")).digest()
nonce = bytes.fromhex(data["sealed"]["nonce"])
ct = bytes.fromhex(data["sealed"]["ct"])

flag = AESGCM(key).decrypt(nonce, ct, None).decode()
print(f"[+] Flag: {flag}")
