# Hensel Garden

### Cryptosystem Overview
Authored by 5h1kh4r. Files: `chall.py` and `data.json`.
A 128-bit secret integer seed $s \in [0, 2^{128}-1]$ is shifted and squared modulo two prime powers:
- $(s + 87)^2 \equiv sq_1 \pmod{2^{72}}$
- $(s + 143)^2 \equiv sq_2 \pmod{3^{51}}$

Total product modulus:
$M = 2^{72} \times 3^{51} \approx 2^{152.83} > 2^{128}$

Because $M > 2^{128}$, the CRT reconstruction over $\mathbb{Z}/M\mathbb{Z}$ has a unique integer root lying in $[0, 2^{128}-1]$.

### Root Lifting via Hensel's Lemma

1. **Modulo $2^{72}$ (2-adic square roots):**
   - For an odd square modulo $2^k$ ($k \ge 3$), there are exactly 4 square roots.
   - Base roots modulo 8: $r^2 \equiv sq_1 \pmod 8$.
   - Inductive lift: If $r_k^2 \equiv sq_1 \pmod{2^k}$, then the root mod $2^{k+1}$ is either $r_k$ or $r_k + 2^{k-1}$.
   - Lifting iteratively to $k=72$ yields 4 distinct candidates for $(s + 87) \pmod{2^{72}}$.

2. **Modulo $3^{51}$ (Hensel's Lemma for Odd Primes):**
   - Function: $f(x) = x^2 - sq_2 = 0$.
   - Base roots modulo 3: $x_0^2 \equiv sq_2 \pmod 3$ (2 roots).
   - Derivative: $f'(x) = 2x \not\equiv 0 \pmod 3$.
   - Unique Hensel lift:
     $x_{k+1} = x_k - \frac{f(x_k)}{f'(x_k)} \pmod{3^{k+1}}$
   - Lifting to $k=51$ gives 2 distinct roots for $(s + 143) \pmod{3^{51}}$.

### CRT Combination & Flag Recovery
Combining the 4 roots from $\mathbb{Z}/2^{72}\mathbb{Z}$ with the 2 roots from $\mathbb{Z}/3^{51}\mathbb{Z}$ produces $4 \times 2 = 8$ candidates modulo $M$.
Testing the bound condition $0 \le s < 2^{128}$ filters out the 7 invalid CRT residues, uniquely recovering the seed:
`s = 282779946134366997745983790016833981964`

```python
import json
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Lift roots mod 2^72 and mod 3^51, combine via CRT
# ...
seed = 282779946134366997745983790016833981964
key = sha256(b"SecLeaf/hensel/v2/" + seed.to_bytes(16, "big")).digest()

with open("data.json") as f:
    data = json.load(f)

flag = AESGCM(key).decrypt(
    bytes.fromhex(data["sealed"]["nonce"]),
    bytes.fromhex(data["sealed"]["ct"]),
    None
).decode()
print("Flag:", flag)
```

### Execution Output
```bash
$ python3 solve.py
[+] Recovered Seed: 282779946134366997745983790016833981964
[+] Flag: SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}
```

Flag:
```text
SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}
```
