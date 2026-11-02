#!/usr/bin/env python3
import json
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

with open("data.json") as f:
    data = json.load(f)

records = data["records"]
sealed = data["sealed"]

# Precompute alpha and beta for ECDSA equation: k = alpha + beta * d
alphas = []
betas = []
for item in records:
    r, s = int(item["r"], 16), int(item["s"], 16)
    h = int.from_bytes(sha256(item["msg"].encode()).digest(), "big") % N
    s_inv = pow(s, -1, N)
    alphas.append((s_inv * h) % N)
    betas.append((s_inv * r) % N)

# Test all 7 candidate length-5 windows
for start in range(len(records) - 4):
    u = [(alphas[start + j + 1] - alphas[start + j]) % N for j in range(4)]
    v = [(betas[start + j + 1] - betas[start + j]) % N for j in range(4)]

    # Delta_2 * Delta_0 - Delta_1^2 = 0
    a1 = (v[2] * v[0] - v[1] * v[1]) % N
    b1 = (u[2] * v[0] + u[0] * v[2] - 2 * u[1] * v[1]) % N
    c1 = (u[2] * u[0] - u[1] * u[1]) % N

    # Delta_3 * Delta_1 - Delta_2^2 = 0
    a2 = (v[3] * v[1] - v[2] * v[2]) % N
    b2 = (u[3] * v[1] + u[1] * v[3] - 2 * u[2] * v[2]) % N
    c2 = (u[3] * u[1] - u[2] * u[2]) % N

    lin_b = (a2 * b1 - a1 * b2) % N
    lin_c = (a2 * c1 - a1 * c2) % N
    if lin_b == 0:
        continue

    cand_d = (-lin_c * pow(lin_b, -1, N)) % N

    # Decrypt sealed ciphertext with derived AES key
    key = sha256(b"SecLeaf/nonce-nursery/v2/" + cand_d.to_bytes(32, "big")).digest()
    try:
        flag = AESGCM(key).decrypt(
            bytes.fromhex(sealed["nonce"]),
            bytes.fromhex(sealed["ct"]),
            None
        ).decode()
        print(f"[+] Found affine sequence at window indices {start}..{start+4}")
        print(f"[+] Recovered private key d: {cand_d}")
        print(f"[+] Flag: {flag}")
        break
    except Exception:
        continue
