# umbra

**CTF Event:** Lun4R CTF 2026  
**Category:** Reverse Engineering  
**Difficulty:** Medium / Hard  
**Binary Name:** `umbra`  

---

## 1. Challenge Overview

`umbra` is a 64-bit Linux ELF binary that acts as a "Lunar Telemetry Gateway" receiver. To unlock the gateway and decrypt the payload, the binary requires a specific 32-byte secret key (passphrase). 

The key verification logic is implemented using a custom cryptographic state machine and 32 system-of-equations constraints evaluated modulo 256 over 4 blocks of 8 bytes each. Once valid input passes the checksum verification, the binary uses the key material to decrypt the transmission payload using SHA-256 state updates and byte stream transformation to emit the flag.

---

## 2. Binary Inspection & Security Analysis

Initial triage with standard tools:

```bash
$ file umbra
umbra: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped

$ checksec --file=umbra
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
* The binary is **stripped** (no symbol names for internal functions).
* Dynamic linkage with standard `libc` functions (`strncmp`, `strlen`, `memcpy`, `fprintf`, `fwrite`, `puts`).

---

## 3. Reverse Engineering & Control Flow Analysis

Decompiling the entry points with Ghidra reveals two main user functions:
1. `FUN_001003c0` (`main`): Handles CLI input parsing, validation sequence, key expansion, and string decryption.
2. `FUN_00102040`: A hash/sponge state update function (SHA-256 implementation) used to derive payload keying material.

### 3.1 Input Parsing

The program accepts a single CLI argument `argv[1]` in four acceptable input formats:
1. `Lun4R{<64 hex characters>}` (Length = 71)
2. `<64 hex characters>` (Length = 64)
3. `Lun4R{<32 raw bytes>}` (Length = 39)
4. `<32 raw bytes>` (Length = 32)

Regardless of format, `main` parses and converts the input into a 32-byte binary buffer `key[0..31]` (`local_148` in decompilation).

---

## 4. Cryptographic Validation Mechanics

The core verification occurs in a loop of 4 iterations (`local_20c = 0..3`). In each iteration, 8 bytes of the key `b0..b7` are processed.

### 4.1 State Table Permutation
Before evaluating the equations, the binary maintains a 64-byte lookup table $S$ initialized from `DAT_00103620`. For each input byte $b_i$ ($i \in [0, 7]$), $S$ is mutated:

$$\text{idx}_i = (b_i \oplus u \oplus (7 \times i)) \bmod 64$$
$$S[\text{idx}_i] = S[\text{idx}_i] \times 3 + b_i + i$$

### 4.2 System of Modular Equations
For each block of 8 key bytes ($b_0, b_1, b_2, b_3, b_4, b_5, b_6, b_7$), the program evaluates 8 modular equations against target constants stored in `DAT_00103780`:

Let $P_1$ and $P_2$ be the preceding two key bytes (for block 0, hardcoded initial seeds $P_1 = 0x5a$ and $P_2 = 0xa5$ are used):

$$
\begin{aligned}
E_0 &: (b_0 + 3 b_1 + 7 b_2 + 2 b_3 + 5 P_1) \equiv T_0 \pmod{256} \\
E_1 &: (5 b_1 + b_2 + 4 b_3 + 9 b_4) \equiv T_1 \pmod{256} \\
E_2 &: (2 b_2 + 8 b_3 + b_4 + 3 b_5) \equiv T_2 \pmod{256} \\
E_3 &: (7 b_3 + 3 b_4 + 5 b_5 + b_6) \equiv T_3 \pmod{256} \\
E_4 &: (4 b_4 + 2 b_5 + 6 b_6 + b_7 + 3 P_2) \equiv T_4 \pmod{256} \\
E_5 &: \left( (b_0 \oplus b_2 \oplus b_4 \oplus b_6 \oplus P_1) + (b_1 \oplus b_3 \oplus b_5 \oplus b_7) \right) \equiv T_5 \pmod{256} \\
E_6 &: (3 b_0 + 7 b_1 + 5 b_2 + 11 b_3 + b_4 + 3 b_5 + 9 b_6 + 5 b_7 + 7 P_1) \equiv T_6 \pmod{256} \\
E_7 &: (7 b_0 + 3 b_2 + 11 b_4 + 5 b_6 + 13 P_1) \equiv T_7 \pmod{256}
\end{aligned}
$$

If **any** equation fails across the 4 blocks, the program prints:
`[-] Invalid Access Sequence. Carrier lock lost.` and exits immediately.

---

## 5. Constraint Solving with Z3

Because the system operates over $\mathbb{Z} / 256\mathbb{Z}$ (8-bit integers) with non-linear XOR operations, we formulate the SMT constraint model in Python using `z3-solver`.

While raw modular arithmetic yields multiple valid byte sequences, adding the constraint that the passphrase consists of **human-readable printable ASCII characters** ($0x20 \le b_i \le 0x7e$) converges onto a unique 32-character solution:

**Key:** `Lun4R_0rbital_umbra_2026_key_7a9`

---

## 6. Complete Solution Script (`solve.py`)

```python
#!/usr/bin/env python3
"""
Solution script for CTF challenge: umbra
Author: Antigravity
"""

import subprocess
from z3 import *

# Target byte array extracted from DAT_00103780 (file offset 0x3780)
dat_3780 = [
    0xd7, 0x69, 0xeb, 0x6d, 0x87, 0x86, 0x48, 0x66,
    0xc5, 0xd1, 0x79, 0x3b, 0x29, 0xb7, 0x59, 0xc1,
    0x3e, 0xd9, 0x7c, 0x51, 0xe9, 0x99, 0xcb, 0x7a,
    0x63, 0xb7, 0x96, 0xe0, 0xff, 0x4e, 0x3a, 0x80
]

def solve():
    s = Solver()
    bytes_var = [BitVec(f"b_{i}", 8) for i in range(32)]

    for block in range(4):
        b0 = bytes_var[block * 8 + 0]
        b1 = bytes_var[block * 8 + 1]
        b2 = bytes_var[block * 8 + 2]
        b3 = bytes_var[block * 8 + 3]
        b4 = bytes_var[block * 8 + 4]
        b5 = bytes_var[block * 8 + 5]
        b6 = bytes_var[block * 8 + 6]
        b7 = bytes_var[block * 8 + 7]

        if block == 0:
            prev1 = BitVecVal(0x5a, 8)
            prev2 = BitVecVal(0xa5, 8)
        else:
            prev1 = bytes_var[block * 8 - 1]
            prev2 = bytes_var[block * 8 - 2]

        target = dat_3780[block * 8 : (block + 1) * 8]

        # 8 block equations modulo 256
        s.add(b0 + 3*b1 + 7*b2 + 2*b3 + 5*prev1 == target[0])
        s.add(5*b1 + b2 + 4*b3 + 9*b4 == target[1])
        s.add(2*b2 + 8*b3 + b4 + 3*b5 == target[2])
        s.add(7*b3 + 3*b4 + 5*b5 + b6 == target[3])
        s.add(4*b4 + 2*b5 + 6*b6 + b7 + 3*prev2 == target[4])
        s.add((b0 ^ b2 ^ b4 ^ b6 ^ prev1) + (b1 ^ b3 ^ b5 ^ b7) == target[5])
        s.add(3*b0 + 7*b1 + 5*b2 + 11*b3 + b4 + 3*b5 + 9*b6 + 5*b7 + 7*prev1 == target[6])
        s.add(7*b0 + 3*b2 + 11*b4 + 5*b6 + 13*prev1 == target[7])

    # Filter for printable ASCII passphrase
    for i in range(32):
        s.add(bytes_var[i] >= 0x20)
        s.add(bytes_var[i] <= 0x7e)

    if s.check() == sat:
        m = s.model()
        key_bytes = bytes([m[bytes_var[i]].as_long() for i in range(32)])
        key_str = key_bytes.decode('ascii')
        print(f"[+] Recovered key: {key_str}")

        # Execute target binary with recovered key
        res = subprocess.run(["./umbra", key_str], capture_output=True, text=True)
        print(res.stdout)
    else:
        print("[-] Solution unsat.")

if __name__ == "__main__":
    solve()
```

---

## 7. Output & Execution Verification


<img width="1859" height="203" alt="image" src="https://github.com/user-attachments/assets/57325707-fed9-4c28-b3d6-ea2db55fff5d" />


Running the script executes `./umbra Lun4R_0rbital_umbra_2026_key_7a9`:

```
[+] Recovered key: Lun4R_0rbital_umbra_2026_key_7a9
[+] Access Sequence Verified: Checksum 0x9E3779B97F4A7C15 confirmed.
[+] Lunar Telemetry Gateway Unlocked. Initializing transmission decoder...
[+] Payload Decrypted Successfully:
Lun4R{sh4d0w_c4lc_1n_th3_lunar_umbra_7a9f}
```

---

## 8. Summary of Flag & Key

* **Key:** `Lun4R_0rbital_umbra_2026_key_7a9`
* **Flag:** `Lun4R{sh4d0w_c4lc_1n_th3_lunar_umbra_7a9f}`
