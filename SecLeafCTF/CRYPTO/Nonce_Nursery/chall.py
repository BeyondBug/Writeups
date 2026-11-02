#!/usr/bin/env python3
import json
from secrets import randbelow
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def make_nonces(count):
    start = randbelow(count - 4)
    A = 1 + randbelow(N - 1)
    B = 1 + randbelow(N - 1)
    k = 1 + randbelow(N - 1)
    nonces = [1 + randbelow(N - 1) for _ in range(count)]
    for j in range(start, start + 5):
        if j != start:
            k = (A * k + B) % N
        nonces[j] = k
    return nonces

if __name__ == "__main__":
    print("[*] Nonce Nursery generator loaded.")
