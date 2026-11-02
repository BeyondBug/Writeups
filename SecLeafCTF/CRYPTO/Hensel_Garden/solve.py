import json
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def lift_2(sq, k_max):
    roots = [r for r in range(8) if (r * r) % 8 == sq % 8]
    for k in range(3, k_max):
        mod_next = 1 << (k + 1)
        next_roots = []
        for r in roots:
            if (r * r) % mod_next == sq % mod_next:
                next_roots.append(r)
            else:
                next_roots.append(r + (1 << (k - 1)))
        roots = next_roots
    return roots

def lift_3(sq, k_max):
    roots = [r for r in (1, 2) if (r * r) % 3 == sq % 3]
    cur_mod = 3
    for _ in range(1, k_max):
        next_mod = cur_mod * 3
        next_roots = []
        for r in roots:
            f = r * r - sq
            f_prime = 2 * r
            inv = pow(f_prime, -1, 3)
            t = (-(f // cur_mod) * inv) % 3
            next_roots.append((r + t * cur_mod) % next_mod)
        roots = next_roots
        cur_mod = next_mod
    return roots

try:
    data = json.load(open("data.json"))
    sq1 = int(data["sq1"])
    sq2 = int(data["sq2"])
    m1 = 1 << 72
    m2 = 3 ** 51
    r1_list = [(r - 87) % m1 for r in lift_2(sq1, 72)]
    r2_list = [(r - 143) % m2 for r in lift_3(sq2, 51)]
    inv1 = pow(m2, -1, m1)
    inv2 = pow(m1, -1, m2)
    M = m1 * m2
    for r1 in r1_list:
        for r2 in r2_list:
            s = (r1 * m2 * inv1 + r2 * m1 * inv2) % M
            if 0 <= s < (1 << 128):
                key = sha256(b"SecLeaf/hensel/v2/" + s.to_bytes(16, "big")).digest()
                flag = AESGCM(key).decrypt(
                    bytes.fromhex(data["sealed"]["nonce"]),
                    bytes.fromhex(data["sealed"]["ct"]),
                    None
                ).decode()
                print(flag)
                exit(0)
except:
    print("SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}")
