# The Lockley Differential Challenge Write-up

## Overview
The challenge supplies two stripped ELF binaries (`reference` and `chall`) inside `differential.tar.gz`.  

- `reference` documents the baseline two-personality protocol.  
- `chall` extends the protocol with a third stateful transformation attributed to **Jake Lockley**.

The objective is to recover the unique 40-byte input accepted by `chall` and obtain the flag.

---

## 1. Initial Reconnaissance

```bash
mkdir -p work/differential
tar -xzf differential.tar.gz -C work/differential
cd work/differential
file reference chall
```

<img width="1600" height="637" alt="image" src="https://github.com/user-attachments/assets/8950268a-c978-473c-9128-d4de9c0c93cd" />


Both binaries are stripped ELF executables that accept a single 40-byte argument. Rejection messages are phase-specific and report the failing glyph index (e.g. `[-] [MIDNIGHT-MISSION-2.2] Incantation rejected at glyph 0`). While useful for probing, the index alone is insufficient because the transformations are stateful.

The expected final output (40 bytes) is embedded at virtual/file offset `0x3000`:

```
5d4fcbd8be9763b914877e73f05d469eb74c0c49fa05b350b0960d024467f07fdf69c0ab6c3e201c
```

---

## 2. Anti-Debugging Behaviour

Debugger-assisted analysis can select a fallback execution path. Under that path the first 16-byte state becomes:

```
ef be ad de be ba fe ca 37 13 37 13 88 88 88 88
```

The normal execution path initialises the four 32-bit words from the string:

```
anulro-r1tib6202
```

Jake state initialisation (normal path):

```
state       = 0x1337c0de
accumulator = 0
previous_byte = 0x5a
```

When inspecting under GDB, the fallback branch can be bypassed by stopping after S-box initialisation and clearing the branch condition. Final candidates must always be verified by executing `./chall` outside the debugger.

---

## 3. Recovering the S-box

The verifier maintains a 256-byte S-box beginning at offset `0x10` in its state structure. Dumping the S-box immediately after initialisation yields the exact permutation used by the normal path:

```gdb
set disable-randomization on
starti
b *0x5555555548f2
continue
x/256bx $rsp+0x40
```

<img width="1600" height="153" alt="image" src="https://github.com/user-attachments/assets/7b689064-2254-4b38-bf9c-42240309fde2" />


The resulting bytes were saved as `runtime_sbox.bin` and loaded by the solver.  

An additional 32-byte key used during setup is also present:

```
3f9a1285c47e0b53f1286d4cb097348e596a1be2780f43d6298cf5314abd671e
```

---

## 4. Phase 1 — Steven Transformation

Processes input left-to-right. Maintains four little-endian 32-bit words (`w0`–`w3`) initially loaded from `anulro-r1tib6202`.

For position `i` and input byte `ch`:

```
idx  = (31 * i) ⊕ ch ⊕ low8(w3) ⊕ byte1(edx)
v    = S[idx]
out  = low8(w0) ⊕ v ⊕ 0xa5
```

State update (all arithmetic modulo 2³²):

```
new_w0 = ROL32(out ⊕ w0, 11) + w1
new_w1 = ROR32(v + w1, 7) ⊕ w2
new_w2 = (w2 * 0x41c64e6d + 0x3039) ⊕ w3
new_w3 = ROL32(w3 ⊕ new_w0, 13) - 0x61c88647
```

After positions 3, 7, 11, … the S-box is mutated:

```
swap(S[low8(new_w0)], S[bits16..23(new_w2)])
```

**Inversion**  
Given a desired Phase-1 output byte, enumerate all 256 candidates for `ch`. Accept the unique value that satisfies the output equation, then replay the state update and any S-box swap before advancing.

---

## 5. Phase 2 — Marc Reverse Differential

Processes positions from 39 down to 0. Maintains a 32-bit accumulator with initial values:

```
eax = 0x5a
edx = 0x11
```

At each reverse position `i`:

```
eax  = eax + edx
out  = ROL8(low8(eax), 3) ⊕ inp[i] ⊕ 0x7c
eax  = (eax & 0xffffff00) | out
edx  = edx - 7
```

**Inversion** (still performed high-to-low):

```
inp[i] = ROL8(low8(eax), 3) ⊕ out[i] ⊕ 0x7c
```

---

<img width="1600" height="268" alt="image" src="https://github.com/user-attachments/assets/9e8d5a63-94db-48ec-b0e8-89c152446fd7" />


## 6. Phase 3 — Jake State Machine

Processes left-to-right with:

```
state = 0x1337c0de
acc   = 0
prev  = 0x5a
```

For each input byte `ch`:

```
x   = ((state >> 16) ⊕ state) + acc
out = low8(x) ⊕ ch ⊕ 0x53

delta = (ch - prev) & 0xff
state = ROL32((delta * 0x1000193) ⊕ state, 5) + 0x4b
acc   = acc + 0x37
prev  = ch
```

**Inversion** is direct:

```
ch = out ⊕ low8(x) ⊕ 0x53
```

followed by a forward state update using the recovered byte.

---

## 7. Complete Solve Order

Forward computation order:

```
input → Steven → Marc → Jake → target
```

<img width="1600" height="77" alt="image" src="https://github.com/user-attachments/assets/b6842fd8-5158-40f0-8657-424f5f14f8b2" />


>Therefore invert in reverse:

```
target
  → invert Jake
  → invert Marc
  → invert Steven
  → 40-byte input
```

Recovered intermediates:

```
Phase-2 input (to Jake):
e7c8bd8dd2354149fd7d16fb5070acba21e3a32903d441aa32774cd9628ab7a24f3bfd49304eddaa

Phase-1 output:
dd921dce246aa6442cab606b0a343092c74fe2117c0e1f48b6d44c5d6ce2689feb60381c1e35048d
```

Accepted 40-byte input (hex):

```
4c756e34527b6a346b335f6c30636b6c33795f7468335f74683172645f346c7433725f323032367d
```

ASCII representation:

```
Lun4R{j4k3_l0ckl3y_th3_th1rd_4lt3r_2026}
```

---

## 8. Verification

```bash
./chall 'Lun4R{j4k3_l0ckl3y_th3_th1rd_4lt3r_2026}'
```

Output:

```
[+] [MIDNIGHT-MISSION-2.2] Jake Lockley bloodline authentication successful!
[+] Decrypted Lunar Rite Transmission:
    MIDNIGHT MISSION: Jake Lockley differential bloodline awakened!
    Flag: Lun4R{j4k3_l0ckl3y_th3_th1rd_4lt3r_2026}
```

<img width="1600" height="94" alt="image" src="https://github.com/user-attachments/assets/130e2aae-801a-4f98-9ce5-7a4922caf5ea" />


>An independent forward re-implementation of all three phases confirms that the recovered input produces the embedded 40-byte target.

---

## Final Flag

```
Lun4R{j4k3_l0ckl3y_th3_th1rd_4lt3r_2026}
```
