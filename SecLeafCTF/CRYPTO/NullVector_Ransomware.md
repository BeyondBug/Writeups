# NullVector Ransomware

### Container Layout
Challenge artifacts: `classified_report.locked` (886 bytes) and `quantum_shor_factors.json`.
Inspecting `classified_report.locked`:
- `0x000 - 0x005` (6 B): Magic header `89 52 57 01 01 00`
- `0x006 - 0x105` (256 B): RSA-2048 encrypted session key
- `0x106 - 0x115` (16 B): AES Initialization Vector (IV)
- `0x116 - 0x375` (608 B): AES-256-CBC ciphertext

### Layer 1: RSA-2048 Private Key Reconstruction
`quantum_shor_factors.json` supplies public modulus $N$, public exponent $e$, and primes $p, q$.
Computing private exponent $d$:
$\phi(N) = (p - 1)(q - 1)$
$d \equiv e^{-1} \pmod{\phi(N)}$

Decrypting the 256-byte wrapped block:
$\text{key\_block} = \text{wrapped}^d \bmod N$
Taking the trailing 32 bytes extracts the AES-256 key:
`078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7`

### Layer 2: AES-256-CBC Decryption
Decrypting the 608 ciphertext bytes using the recovered key and IV, then stripping 11 bytes of PKCS#7 padding (`0x0b`), yields a 597-byte intermediate stream.

### Layer 3: Affine Byte-Level Obfuscation
Analyzing the 597-byte stream revealed identical 46-byte repeated patterns at offsets 38 and 550, characteristic of standard report dividers (e.g. `==============================================`).

Testing affine LCG parameters and bitwise rotations over the 46 known bytes:
$P[i] = \text{ror}_8(C[i], r) \oplus ((a \cdot i + b) \bmod 256)$

Unique parameter match:
- Rotation: 5 bits right (`r = 5`)
- Divider character: `'='` (`0x3D`)
- Linear mask: $a = 13$, $b = 122 \implies \text{mask}[i] = (13i + 122) \bmod 256$

### Automated Decryptor
```python
import json, re
from pathlib import Path
from Crypto.Cipher import AES

blob = Path('classified_report.locked').read_bytes()
factors = json.loads(Path('quantum_shor_factors.json').read_text())

# RSA decryption
p, q, n, e = int(factors['p'], 16), int(factors['q'], 16), int(factors['N'], 16), int(factors['e'], 16)
d = pow(e, -1, (p - 1) * (q - 1))
wrapped = int.from_bytes(blob[6:262], 'big')
aes_key = pow(wrapped, d, n).to_bytes(256, 'big')[-32:]

# AES-CBC decryption
cipher = AES.new(aes_key, AES.MODE_CBC, blob[262:278])
stage = cipher.decrypt(blob[278:])
stage = stage[:-stage[-1]] # remove PKCS#7

# Invert 5-bit ROR and linear XOR
ror8 = lambda v, r: ((v >> r) | (v << (8 - r))) & 0xff
plain = bytes(ror8(b, 5) ^ ((13 * i + 122) & 0xff) for i, b in enumerate(stage))
report = plain.decode('utf-8')
print(report)

flag = re.search(r'SecLeaf\{[0-9a-f]+\}', report).group(0)
print("\nFlag:", flag)
```

### Decrypted Report Excerpt & Flag
```text
CLASSIFIED INTEL REPORT
==============================================
ASSET KEY: SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
==============================================
```

Flag:
```text
SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```
