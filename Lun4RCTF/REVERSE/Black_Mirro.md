# Black Mirror 

> **Category:** Reverse Engineering  
> **Flag Format:** `lun4r{...}`  
> **Author:** ROOT RIET CTF Team  

## 1. Challenge Overview

Black Mirror is a reverse engineering challenge from the Lun4R CTF 2026, organized by ROOT RIET. The challenge presents you with two files: an ELF 64-bit Linux binary named `black_mirror`, and an opaque binary blob called `encrypted_memory.bin`. The binary runs a virtual machine that validates an *access code* you type in. If the access code passes all checks, the binary prints the flag. If it fails at any point, the binary either exits silently or, if you fell into one of its traps, prints a convincing-looking but completely fake flag to mislead you.

The alphabet for the access code is restricted to uppercase letters and digits. The code is 38 characters long and follows the pattern `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, eight groups of four characters separated by hyphens, giving 32 actual payload characters. The challenge is entirely offline — no networking, no external oracle. Everything needed to derive the correct access code lives inside those two files.

The difficulty lies in three concentric layers of obfuscation: a sophisticated anti-analysis trap system that prints false flags, an encrypted and integrity-protected memory payload that hides the VM's real parameters, and a four-layer mathematical transformation pipeline that is deliberately designed to be irreversible by hand but perfectly invertible with the right approach.

---

## 2. First Contact - What We Are Given

Running `file black_mirror` tells us it is a dynamically linked ELF 64-bit x86-64 executable. Running it without arguments prompts:

```
ENTER ACCESS CODE:
```

The binary reads a line of input, strips the hyphens, and runs the 32 remaining bytes through its virtual machine. On wrong input, it either exits silently or (if you guessed a known decoy string) prints one of eight fake flags.

Running `strings black_mirror` immediately reveals something suspicious: there are multiple flag-shaped strings embedded in the binary, all beginning with `lun4r{`. This is a deliberate honeypot. Every single one of those strings is a decoy. The real flag is never stored as a plaintext string anywhere inside the binary.

Running `objdump -d black_mirror` produces the full disassembly. The binary is not stripped — function names are present, which is a generous hint from the author. The key functions visible in the symbol table are:

- `main` — entry point, reads input, orchestrates the validation flow
- `load_memory` — reads and decrypts `encrypted_memory.bin`
- `vm_stage1` — initializes VM state from the decrypted payload
- `vm_dispatch` — the core opcode dispatcher for Stage 2 execution
- `check_decoy` — the anti-analysis trap routine

Understanding what each of these functions does, in order, reveals the complete solution.

---

## 3. Anti-Analysis and Decoy Traps

Before the real validation logic runs, the binary executes a decoy-detection routine at address `0x2850`. This function is called `check_decoy` in the symbol table. Its purpose is to check whether the user's input matches any of eight known "decoy access codes" — strings that were presumably discovered by people reverse-engineering earlier, simpler versions of a similar challenge, or strings that appear plausible from naive analysis. If any decoy matches, the function returns a non-zero value and the binary immediately prints one of the eight fake flags and exits. This is designed to fool a solver who finds the hash comparison, thinks they have beaten the check, and never investigates further.

The decoy detection uses a *cyclic rotate-add hash*, not a simple strcmp. This makes the comparison harder to spot in a debugger. The hash function works as follows: it starts with a seed value of `0x6d697272` (which is ASCII for "mirr" in little-endian — a subtle nod to the "Black Mirror" theme). For each character of the input, it rotates the accumulator left by 5 bits, XORs in the current character, then XORs in a secondary running counter that increments by `0x45d9f3b` each iteration. After processing all 32 characters, the final hash is compared against `0x424d1337`. The constant `0x424d1337` embeds both "BM" (Black Mirror) and the classic `1337` — again, thematic.

The eight decoy strings are stored in the `.data` section beginning at virtual offset `0x8020`, as an array of eight pointers to eight separate plaintext strings. These decoy codes look structurally valid — same length, same hyphen grouping, alphanumeric characters — but produce the wrong hash and fail the real four-layer pipeline even if you somehow bypass the decoy check.

**The lesson here is clear:** when you see multiple flag-shaped strings in a binary, none of them are real. When you see a hash-based "shortcut" that seems to gate the flag, it is a trap. The real flag is produced only when the mathematical pipeline at the end of the VM is fully satisfied.

---

## 4. Protected Memory Decryption Pipeline

The most important function in the binary is `load_memory`, disassembled around address `0x2f80`. This function reads the entire `encrypted_memory.bin` file into memory and then performs a multi-stage decryption process before handing the plaintext payload to the VM. Understanding this pipeline is essential because the real parameters of the four-layer transformation are hidden inside the encrypted payload — they are never visible in the binary itself.

### 4.1 File Layout of `encrypted_memory.bin`

The encrypted memory file has a fixed-size header occupying the first 64 bytes, followed by the variable-length encrypted payload. The header is structured as follows:

- **Bytes 0–7:** The magic signature `BMEMV200`. This is checked byte-for-byte. If it does not match exactly, the binary aborts immediately. This is how you confirm you have the correct companion file.
- **Bytes 8–11:** A 4-byte little-endian integer representing the format version. The expected value is 2. Version 1 headers are rejected.
- **Bytes 12–15:** A 4-byte little-endian integer containing the payload size in bytes. In the provided file this value is `0x889` = 2185 bytes.
- **Bytes 16–31:** A 16-byte nonce, used for both the integrity check and the ChaCha20 stream cipher initialization.
- **Bytes 32–63:** A 32-byte SHA-256 digest of the *plaintext* payload. This is verified *after* decryption to confirm the key was correct and the payload was not tampered with.

The encrypted payload begins immediately at byte offset 64 and runs for exactly as many bytes as the payload size field specifies.

### 4.2 Key Material Hidden in the ELF

The ChaCha20 decryption key is never stored directly in the binary. Instead, two 32-byte constants are stored in the `.rodata` section and combined at runtime. By inspecting the file at offsets `0x5948` and `0x5988`, you find two arrays of 32 bytes each. Neither alone is the key — the function XORs them together byte-by-byte to produce a 32-byte base key, which we call `k_base`.

This XOR combination is trivially reversible in a solver script: load the raw ELF bytes and XOR `elf[0x5988:0x5988+32]` with `elf[0x5948:0x5948+32]`. The result is `k_base`. This is not cryptographic security — it is obfuscation intended to hide the key from naive `strings` analysis.

### 4.3 Two-Stage Key Derivation

With `k_base` and the 16-byte nonce from the header, the binary derives two separate 32-byte ChaCha20 keys using SHA-256:

- **Stage 1 key:** `SHA256(k_base || nonce16 || b'MEMORY')` — used to decrypt the first pass of the payload.
- **Stage 2 key:** `SHA256(k_base || nonce16 || b'VM2STAGE')` — used to decrypt a second pass of the payload.

In both cases, ChaCha20 is used with a 12-byte nonce (the first 12 bytes of `nonce16`) and an initial counter value of 1. The counter starting at 1 rather than 0 is an unusual choice that exists purely to trip up solvers who assume counter=0.

Both stages decrypt the same buffer sequentially. After the first pass, the buffer still looks like noise to SHA-256. After the second pass, the SHA-256 of the plaintext buffer matches the digest stored in header bytes 32–63. If the digest matches, decryption succeeded and the payload is valid.

### 4.4 What Lives in the Decrypted Payload

Once decrypted, the 2185-byte payload contains all the parameters for the four-layer transformation pipeline, laid out at fixed offsets:

- **Offset 0x61 — Permutation Table (32 bytes):** A permutation of the integers 0 through 31. Each byte at position `i` tells you where input byte `i` should move during the permutation layer.
- **Offset 0x81 — S-Box (32 bytes):** Another permutation of 0 through 31. Acts as a substitution layer mapping each value to another.
- **Offset 0xa1 — Matrix (16 bytes):** A 4×4 lower-triangular matrix stored in row-major order. The diagonal elements are `[3, 5, 7, 9]` and the off-diagonal lower elements include values like 26, 7, 27, 6, 6, 19. All matrix arithmetic is done modulo 32.
- **Offset 0xc1 — Feistel Round Constants (8 bytes):** Eight values, one per round, used in the Feistel network's round function. Values: `[15, 17, 11, 11, 17, 1, 13, 17]`.
- **Offset 0xc9 — Target Vector (32 bytes):** The expected output of the four-layer pipeline. The access code is valid if and only if transforming the stripped input through all four layers produces exactly this vector.

---

## 5. Virtual Machine Architecture

The binary implements a two-stage virtual machine. This design adds an extra layer of complexity for an analyst: you cannot simply follow the code linearly because the "code" being executed is data produced at runtime.

### 5.1 Stage 1 - Initialization

`vm_stage1`, disassembled around address `0x3b90`, is responsible for bootstrapping VM state from the decrypted payload. It reads the permutation table, the S-Box, the matrix, the round constants, and the target vector, and copies them into a VM context structure that is passed to Stage 2. Stage 1 also seeds the VM's register file with initial values derived from the header nonce, making the register state unique to each binary instance. This ensures that even if two CTF competitors compare notes on "register values", they are looking at the same challenge.

### 5.2 Stage 2 - Bytecode Dispatch

`vm_dispatch`, disassembled around address `0x3fb0`, is the main execution engine. It implements a simple stack-based VM with a custom instruction set. The key opcodes drive the four-layer transformation: one opcode performs the permutation, one the S-Box lookup, one the matrix-vector multiplication, and one triggers the Feistel network evaluation. A final comparison opcode checks the VM's output registers against the target vector. Additional opcodes exist for stack manipulation, loop control, and the conditional branch that leads to either the flag-print path or silent failure.

The VM does not do anything surprising beyond executing the transformation pipeline in order. Once you understand what the opcodes mean, Stage 2 is transparent. The real complexity is in the transformation layers themselves.

---

## 6. The Four-Layer Validation Pipeline

When you type the 32-character access code (hyphens stripped), the binary treats those 32 bytes as a sequence of 32 integer values, each in the range 0–31 (derived by indexing the legal character alphabet). These 32 values flow through four transformation layers in sequence. The pipeline computes `T = L4(L3(L2(L1(input))))` and checks that `T` equals the target vector.

The four layers are applied in this order: **Permutation → S-Box Substitution → Matrix Multiplication mod 32 → Feistel Network**.

### 6.1 Layer 1 - Permutation

The permutation table `P` is a 32-element array that is a bijection of `{0, 1, ..., 31}`. The permutation operates on the *positions* of the 32-element input vector. Specifically, the output vector `out` is defined by:

`out[i] = in[P[i]]` for every `i` from 0 to 31.

In plain terms: the byte at position `P[i]` in the input is moved to position `i` in the output. This is a classical position permutation identical to what you see in DES key schedules or block cipher diffusion layers.

### 6.2 Layer 2 - S-Box Substitution

The S-Box `S` is also a 32-element bijection of `{0, 1, ..., 31}`. It operates on the *values* of the 32-element vector, not the positions. For each element `v` in the permuted vector, the substituted value is `S[v]`. Since `S` is a permutation, every value 0–31 appears exactly once in its codomain, making the substitution trivially invertible.

### 6.3 Layer 3 - Matrix Multiplication mod 32

The 4×4 lower-triangular matrix `M` (with non-zero diagonal) acts on the S-Box output, but not all 32 elements at once. The 32-element vector is divided into eight consecutive 4-element chunks. Each chunk is treated as a column vector in `Z/32Z` and multiplied by `M`. The result is an 8-element collection of 4-element output chunks, which are concatenated back into a 32-element vector.

The matrix multiplication is performed modulo 32. The matrix is lower-triangular, meaning all entries above the diagonal are zero. The diagonal values are `[3, 5, 7, 9]`. Lower-triangular structure means the matrix is always non-singular as long as the diagonal entries are coprime to 32 — and 3, 5, 7, 9 are all odd, so they are coprime to any power of 2, and their modular inverses mod 32 exist. This is not accidental: the author chose these diagonal values precisely so that the matrix is invertible mod 32.

The flat row-major layout of the matrix, reading left to right, top to bottom, is: `[3, 0, 0, 0, 26, 5, 0, 0, 7, 27, 7, 0, 6, 6, 19, 9]`. So the full matrix is:

```
Row 0: [  3,  0,  0,  0 ]
Row 1: [ 26,  5,  0,  0 ]
Row 2: [  7, 27,  7,  0 ]
Row 3: [  6,  6, 19,  9 ]
```

For a 4-element input vector `[x0, x1, x2, x3]`, the matrix produces:

```
y0 =  3*x0                           mod 32
y1 = 26*x0 +  5*x1                   mod 32
y2 =  7*x0 + 27*x1 +  7*x2          mod 32
y3 =  6*x0 +  6*x1 + 19*x2 + 9*x3  mod 32
```

### 6.4 Layer 4 - Feistel Network

The Feistel network operates on the 32-element vector after the matrix stage. The 32 elements are split into two halves: the Left half (elements 0–15) and the Right half (elements 16–31). Each half is treated as a 16-element block of 20-bit integers — or more precisely, as 16 values each in the range 0–31, which are packed conceptually into 20-bit words for the round function arithmetic.

The network runs for 8 rounds. In each round, the Left half is updated using a function of the Right half and the round constant, and then the halves swap. Specifically, for round `r` (0-indexed from 0 to 7):

1. A secondary accumulator `r8` starts at 0 and increases by `0x1337` each round (so it is `r * 0x1337`).
2. For each of the 16 element positions, the round function is computed as:
   `f = ROL20((R[i] * 0x5a7b + r8 + c[r]) & 0xfffff, rot)`
   where `rot = ((c[r] + r) % 19) + 1`, `c[r]` is the round constant for round `r`, and `ROL20` is a 20-bit left rotation.
3. The Left element is XORed with `f` to produce the new Left element.
4. The halves swap: the updated Left becomes the new Right, and the old Right becomes the new Left.

The `0x5a7b` multiplier, the `0x1337` accumulator increment, and the rotation formula `((c[r] + r) % 19) + 1` are all hardcoded in the VM's round-function opcode handler. They are not stored in the encrypted payload — they are baked into the binary itself. The only per-instance parameters are the 8 round constants `c[r]` from the payload at offset `0xc1`.

---

## 7. Inverting Each Layer to Recover the Access Code

To find the access code, we need to run the pipeline **backwards**. We start from the 32-byte target vector (at offset `0xc9` in the decrypted payload) and apply the inverse of each layer in reverse order:

`input = L1_inv(L2_inv(L3_inv(L4_inv(target))))`

### 7.1 Inverting the Feistel Network

The Feistel structure makes inversion straightforward. In a balanced Feistel network, the forward transformation is its own inverse structure — you just run the rounds backwards and use the same round function.

To invert 8 forward rounds (0 through 7), you run rounds 7 through 0 in that order. For each reverse round `r` (starting from round 7 down to 0):

1. You know the current Left and Right halves.
2. After a forward round, what was the Left half became the new Right half (after swapping). So to undo the swap, you un-swap: the current Right half is what was Left before the swap.
3. The current Left half is what was Right after the swap in forward direction. Before the swap, it was the updated Left, meaning: `L_updated = R_old XOR f(L_old)`. Since `L_old = R_current` (after un-swapping), you can compute `f` and recover: `R_old = L_current XOR f(R_current)`.

Concretely, for reverse round `r`:
- Temporarily swap Left and Right (undo the forward swap).
- Compute the same `f` values using `R` (which is now what was Left in the forward step) and the round constants.
- XOR `f` into `L` to recover the old Left.

You apply this process for rounds 7, 6, 5, 4, 3, 2, 1, 0, in that order. After all 8 reverse rounds, you have recovered the state before the Feistel network — that is, the output of Layer 3.

### 7.2 Inverting the Matrix

To invert a lower-triangular linear system over `Z/32Z`, you apply **forward substitution** (not backward substitution, because the matrix is lower-triangular, not upper-triangular). Given the output vector `[y0, y1, y2, y3]`, you solve for `[x0, x1, x2, x3]` in order:

```
x0 = y0 * inv(3) mod 32        = y0 * 11 mod 32
x1 = (y1 - 26*x0) * inv(5) mod 32   = (...) * 13 mod 32
x2 = (y2 - 7*x0 - 27*x1) * inv(7) mod 32  = (...) * 23 mod 32
x3 = (y3 - 6*x0 - 6*x1 - 19*x2) * inv(9) mod 32  = (...) * 25 mod 32
```

The modular inverses are computed once:
- `inv(3) mod 32 = 11`  (because 3 × 11 = 33 ≡ 1 mod 32)
- `inv(5) mod 32 = 13`  (because 5 × 13 = 65 ≡ 1 mod 32)
- `inv(7) mod 32 = 23`  (because 7 × 23 = 161 ≡ 1 mod 32)
- `inv(9) mod 32 = 25`  (because 9 × 25 = 225 ≡ 1 mod 32)

All arithmetic is done modulo 32 and taken `& 0x1f` after each operation to stay in range. This inversion is applied independently to each of the eight 4-element chunks of the 32-element vector.

### 7.3 Inverting the S-Box

The S-Box is a bijection. Its inverse is simply the lookup table read in the other direction. If `S[v] = w`, then `S_inv[w] = v`. You build the inverse S-Box in O(32) time by iterating over all values 0–31 and filling in `S_inv[S[i]] = i`. Then, for each element in the matrix-inverted vector, you look up `S_inv[element]` to recover the permuted-but-unsubstituted value.

### 7.4 Inverting the Permutation

The permutation table `P` maps input position `j` to output position `i` via `out[i] = in[P[i]]`. To invert this, you need to know, for each position `j` in the input, where it ends up in the output — that is, you need the inverse permutation `P_inv` defined by `P_inv[P[i]] = i`. You build `P_inv` in O(32) time: `P_inv[P[i]] = i` for all `i`. Then the inverse permutation is `in[P_inv[i]] = out[i]`, or equivalently `in[j] = out[P[j]]` where `P` was the forward permutation. Simply: for each `i`, set `input[P[i]] = sbox_inverted[i]`.

### 7.5 The Solver Script

The inversion logic fits in a compact Python script. You open the ELF binary, extract `k1` and `k2` from offsets `0x5988` and `0x5948` respectively, XOR them to get `k_base`. You then open `encrypted_memory.bin`, parse the header (magic, version, payload size, nonce, digest), and perform two-pass ChaCha20 decryption using `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`. After verifying the SHA-256 digest, you read the tables from offsets `0x61`, `0x81`, `0xa1`, `0xc1`, and `0xc9`. You run the inverse pipeline: Feistel inverse → matrix inverse (per 4-element chunk) → S-Box inverse → permutation inverse. The resulting 32 values are indices into the alphabet `[0-9A-Z]`, producing the access code characters. You insert hyphens every 4 characters to get the final formatted code.

---

## 8. Final Flag

Running the inversion pipeline on the decrypted payload produces the access code:

```
T7WZ-XRGR-SEWF-4ZWY-W82M-BXGU-NBSL-NCVL
```

You verify this by running the binary:

```
$ ./black_mirror
ENTER ACCESS CODE: T7WZ-XRGR-SEWF-4ZWY-W82M-BXGU-NBSL-NCVL
```

The binary prints:

```
lun4r{v1rtual_m1rr0rs_h1de_the_truth}
```

The flag is:

> **`lun4r{v1rtual_m1rr0rs_h1de_the_truth}`**

<img width="930" height="109" alt="image" src="https://github.com/user-attachments/assets/a6db7464-e857-4ef2-81fa-06004fa60540" />

---

## 9. Summary Cheat Sheet

| Step | What to do | Key detail |
|------|-----------|------------|
| Identify decoys | Run `strings`, find 8 fake flags | All fake — never trust embedded flag strings |
| Extract ELF constants | Read bytes at file offsets `0x5948` and `0x5988` | XOR them → `k_base` |
| Parse header | Read `encrypted_memory.bin` bytes 0–63 | Magic=`BMEMV200`, nonce at `[16:32]`, digest at `[32:64]` |
| Derive keys | `SHA256(k_base + nonce + b'MEMORY')` and `SHA256(k_base + nonce + b'VM2STAGE')` | ChaCha20, 12-byte nonce, counter=1 for both |
| Decrypt payload | Two-pass ChaCha20 | Verify SHA-256 after second pass |
| Extract tables | Permutation @ `0x61`, S-Box @ `0x81`, Matrix @ `0xa1`, Round consts @ `0xc1`, Target @ `0xc9` | All 32 bytes each (matrix 16 bytes) |
| Invert Feistel | 8 rounds, reversed (7 down to 0) | Same round function, XOR to recover L |
| Invert matrix | Forward substitution in `Z/32Z` | Inverses: 3→11, 5→13, 7→23, 9→25 |
| Invert S-Box | Build reverse lookup | `S_inv[S[i]] = i` |
| Invert permutation | Build reverse lookup | `P_inv[P[i]] = i` |
| Format output | Map values to alphabet, insert hyphens | Groups of 4, 8 groups total |
| Access code | `T7WZ-XRGR-SEWF-4ZWY-W82M-BXGU-NBSL-NCVL` | Feed to binary |
| Flag | `lun4r{v1rtual_m1rr0rs_h1de_the_truth}` | done |
