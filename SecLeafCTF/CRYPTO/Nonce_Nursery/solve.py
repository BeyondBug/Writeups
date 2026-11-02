import json
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

data = json.load(open("data.json"))
records = data["records"]
sealed = data["sealed"]

alphas = []
betas = []
for item in records:
    r, s = int(item["r"], 16), int(item["s"], 16)
    h = int.from_bytes(sha256(item["msg"].encode()).digest(), "big") % N
    s_inv = pow(s, -1, N)
    alphas.append((s_inv * h) % N)
    betas.append((s_inv * r) % N)

for start in range(len(records) - 4):
    u = [(alphas[start + j + 1] - alphas[start + j]) % N for j in range(4)]
    v = [(betas[start + j + 1] - betas[start + j]) % N for j in range(4)]

    a1 = (v[2] * v[0] - v[1] * v[1]) % N
    b1 = (u[2] * v[0] + u[0] * v[2] - 2 * u[1] * v[1]) % N
    c1 = (u[2] * u[0] - u[1] * u[1]) % N

    a2 = (v[3] * v[1] - v[2] * v[2]) % N
    b2 = (u[3] * v[1] + u[1] * v[3] - 2 * u[2] * v[2]) % N
    c2 = (u[3] * u[1] - u[2] * u[2]) % N

    lin_b = (a2 * b1 - a1 * b2) % N
    lin_c = (a2 * c1 - a1 * c2) % N
    if lin_b == 0:
        continue

    cand_d = (-lin_c * pow(lin_b, -1, N)) % N
    key = sha256(b"SecLeaf/nonce-nursery/v2/" + cand_d.to_bytes(32, "big")).digest()
    try:
        flag = AESGCM(key).decrypt(
            bytes.fromhex(sealed["nonce"]),
            bytes.fromhex(sealed["ct"]),
            None
        ).decode()
        print(flag)
        break
    except:
        continue
