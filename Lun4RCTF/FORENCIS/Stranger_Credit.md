# Stranger Credit

**Category:** Forensics / Cryptography  
**Flag Format:** `Lun4R{...}`
---

## 1. Challenge Overview

The challenge provides what initially appears to be a damaged machine-learning checkpoint together with several recovery and diagnostic artifacts.

Rather than simply decrypting a single file, the challenge combines several forensic and cryptographic tasks:

- Identifying the correct metadata among decoy values
- Deriving an AES-256 encryption key
- Parsing a custom encrypted container
- Recovering a permutation used to reorder checkpoint fragments
- Detecting a corrupted fragment
- Reconstructing that fragment from the decrypted checkpoint
- Reassembling the checkpoint
- Extracting the final embedded flag

The most important observation during the initial investigation was that the files were not equally trustworthy.

The actual recovery procedure was documented inside `researcher.note`, while some information in `system.log` was deliberately misleading.

---

# 2. Evidence Triage

After extracting the challenge archive, the following directory structure was present:

```text
evidence/
├── model.enc
├── manifest.bin
├── recovery.journal
├── researcher.note
├── training.log
├── system.log
├── integrity.report
└── checkpoint.parts/
    ├── chunk_00.bin
    ├── chunk_01.bin
    ├── chunk_02.bin
    ├── chunk_03.bin
    └── chunk_04.bin
```

The files serve different purposes.

| File | Purpose |
|---|---|
| `model.enc` | Encrypted model/checkpoint containing the authoritative data |
| `manifest.bin` | Layer metadata including names, dimensions and integrity information |
| `recovery.journal` | Recovery daemon output containing nonce and segment mapping information |
| `researcher.note` | Main recovery instructions and key-derivation recipe |
| `training.log` | Original model/training metadata including the genuine model ID |
| `system.log` | Crash information plus deliberately misleading metadata |
| `integrity.report` | Hashes and CRC values for checkpoint fragments |
| `checkpoint.parts/*.bin` | Five raw checkpoint fragments stored in scrambled order |

The encrypted checkpoint has a size of approximately:

```text
2,263,743 bytes
```

---

# 3. Identifying the Correct Source of Truth

One of the first traps in the challenge is the presence of multiple model identifiers.

`system.log` contains what looks like a usable model ID.

However, `researcher.note` explicitly warns that the model identifier from the system log should not be trusted.

The correct identifier comes from the first line of:

```text
training.log
```

The genuine model identifier is:

```text
scbm-v2.3.1-final
```

This distinction is important because using the decoy metadata would lead to an incorrect recovery path.

The researcher note therefore becomes the central reference for the remainder of the investigation.

---

# 4. Key Derivation

The encrypted checkpoint is protected using AES-256.

The key itself is not stored directly anywhere in the evidence. Instead, `researcher.note` defines a multi-stage key derivation process.

The final key is calculated using:

```text
HMAC-SHA256(
    key = "SCBM_MASTER",
    message = nonce || hash8 || dimcheck
)
```

Three values therefore need to be recovered:

1. `nonce`
2. `hash8`
3. `dimcheck`

---

## 4.1 Recovering the Session Nonce

The recovery journal contains the session information generated during the failed checkpoint recovery.

Inside `recovery.journal` we find:

```text
session_nonce=a3f1c2e4b5d6a7f8
```

Therefore:

```text
nonce = a3f1c2e4b5d6a7f8
```

The raw nonce bytes are:

```text
a3 f1 c2 e4 b5 d6 a7 f8
```

---

## 4.2 Calculating `hash8`

The second component is derived from `config.fragment`.

The note specifies that we must:

1. Read the file as raw bytes.
2. Calculate its SHA-256 digest.
3. Take only the first eight bytes.

Conceptually:

```python
hash8 = SHA256(config_fragment)[:8]
```

The calculated value is:

```text
65d4f643f01a4150
```

Therefore:

```text
hash8 = 65 d4 f6 43 f0 1a 41 50
```

It is important here to hash the original binary contents directly rather than their textual or hexadecimal representation.

---

## 4.3 Recovering `dimcheck`

The third value comes from `training.log`.

The log contains:

```text
dim_checksum=0xA278
```

<img width="1293" height="195" alt="image" src="https://github.com/user-attachments/assets/c5273ed6-d508-4f74-a613-3758f384d28e" />


According to the instructions in `researcher.note`, this value must be encoded as an unsigned 16-bit integer using **big-endian byte order**.

Therefore:

```text
0xA278
```

becomes:

```text
a2 78
```

So:

```text
dimcheck = a278
```

---

# 5. Constructing the HMAC Input

The three values are concatenated directly.

```text
nonce:
a3f1c2e4b5d6a7f8

hash8:
65d4f643f01a4150

dimcheck:
a278
```

Combined:

```text
a3f1c2e4b5d6a7f865d4f643f01a4150a278
```

The HMAC secret/key is the ASCII string:

```text
SCBM_MASTER
```

Therefore:

```text
HMAC-SHA256(
    "SCBM_MASTER",
    a3f1c2e4b5d6a7f865d4f643f01a4150a278
)
```

produces:

```text
ba0f18a971a6d72f980435696c204359885dde7316a0729b94f00b0f613345
```

This is exactly 32 bytes:

```text
256 bits
```

and therefore forms the AES-256 key.

### Final AES Key

```text
ba0f18a971a6d72f980435696c204359885dde7316a0729b94f00b0f613345
```

---

# 6. Understanding `model.enc`

Examining the beginning of `model.enc` reveals a small custom container format.

Its structure is:

```text
+----------------+----------------------+-------------------------+
| 4-byte magic   | 16-byte IV           | encrypted checkpoint    |
+----------------+----------------------+-------------------------+
| "ENCM"         | AES initialization   | ciphertext              |
|                | vector               |                         |
+----------------+----------------------+-------------------------+
```

Or simply:

```text
magic || IV || ciphertext
```

The magic value is:

```text
ENCM
```

This confirms that the correct encrypted container has been identified.

The next 16 bytes are used as the AES initialization vector.

Everything after the IV is ciphertext.

---

<img width="1815" height="237" alt="image" src="https://github.com/user-attachments/assets/7d0a2e3c-4d4c-435e-9d69-f51216e4d534" />


# 7. AES-256-CTR Decryption

The researcher instructions indicate that the checkpoint was encrypted using AES in CTR mode.

The required parameters are therefore:

```text
Algorithm : AES
Key size  : 256 bits
Mode      : CTR
Key       : ba0f18a971a6d72f980435696c204359885dde7316a0729b94f00b0f613345
IV        : bytes 0x04 through 0x13 of model.enc
Ciphertext: bytes after the IV
```

CTR mode is particularly important because it does not use traditional block padding.

Encryption and decryption are performed by XORing the plaintext/ciphertext with a generated AES keystream:

```text
C = P XOR KS
P = C XOR KS
```

where `KS` represents the CTR-mode keystream.

Once the correct key and IV are supplied, the resulting plaintext forms the authoritative checkpoint data.

---

# 8. Fragment Recovery

The challenge also provides five checkpoint segments:

```text
chunk_00.bin
chunk_01.bin
chunk_02.bin
chunk_03.bin
chunk_04.bin
```

However, their filenames do **not** represent their logical order.

The fragments were deliberately permuted before being written to disk.

According to `recovery.journal`, the mapping is generated by:

```text
f(i) = (A × i + B) mod N
```

where:

```text
N = 5
```


<img width="1235" height="239" alt="image" src="https://github.com/user-attachments/assets/26c94e71-9973-4caa-9f26-ced34d9f00e8" />


The journal additionally records the destination offset associated with each physical segment.

```text
segment[0] -> 0x4000
segment[1] -> 0x1000
segment[2] -> 0x3000
segment[3] -> 0x5000
segment[4] -> 0x2000
```

---

# 9. Normalizing the Segment Offsets

Each logical slot is separated by:

```text
0x1000
```

Therefore, dividing every offset by `0x1000` gives:

```text
segment[0] -> 4
segment[1] -> 1
segment[2] -> 3
segment[3] -> 5
segment[4] -> 2
```

So the observed sequence is:

```text
4, 1, 3, 5, 2
```

Because the mathematical function works modulo 5, slot `5` corresponds to modular value `0`.

The sequence can therefore also be represented as:

```text
4, 1, 3, 0, 2
```

---

# 10. Solving the Permutation Function

We need to determine `A` and `B` such that:

```text
f(i) = (A × i + B) mod 5
```

From the first mapping:

```text
f(0) = B mod 5 = 4
```

Therefore:

```text
B = 4
```

Using the second mapping:

```text
f(1) = 1
```

Substituting:

```text
(A + 4) mod 5 = 1
```

Therefore:

```text
A = 2
```

So the complete function is:

```text
f(i) = (2i + 4) mod 5
```

---

# 11. Verifying the Permutation

Testing all segment indices:

```text
f(0) = (2×0 + 4) mod 5
     = 4

f(1) = (2×1 + 4) mod 5
     = 6 mod 5
     = 1

f(2) = (2×2 + 4) mod 5
     = 8 mod 5
     = 3

f(3) = (2×3 + 4) mod 5
     = 10 mod 5
     = 0

f(4) = (2×4 + 4) mod 5
     = 12 mod 5
     = 2
```

Result:

```text
4, 1, 3, 0, 2
```

Converting `0` back into logical slot `5`:

```text
4, 1, 3, 5, 2
```

This matches every recorded offset.

Therefore:

```text
A = 2
B = 4
N = 5
```

and the permutation has been fully recovered.

---

# 12. Determining the Correct Chunk Order

The mapping tells us where each physical chunk belongs.

| Physical chunk | Logical slot |
|---|---:|
| `chunk_00.bin` | 4 |
| `chunk_01.bin` | 1 |
| `chunk_02.bin` | 3 |
| `chunk_03.bin` | 5 |
| `chunk_04.bin` | 2 |

Therefore the correct checkpoint reconstruction order is:

```text
slot 1 -> chunk_01.bin
slot 2 -> chunk_04.bin
slot 3 -> chunk_02.bin
slot 4 -> chunk_00.bin
slot 5 -> chunk_03.bin
```

Or:

```text
chunk_01.bin
chunk_04.bin
chunk_02.bin
chunk_00.bin
chunk_03.bin
```

Simply concatenating:

```text
chunk_00 + chunk_01 + chunk_02 + chunk_03 + chunk_04
```

would therefore produce an invalid checkpoint.

---


<img width="961" height="725" alt="image" src="https://github.com/user-attachments/assets/74796e87-633e-47b9-a150-96aa459a75e4" />


# 13. Integrity Verification

Before trusting the fragments, their integrity needs to be checked.

`integrity.report` contains expected CRC/hash values for the checkpoint chunks.

Most chunks pass validation.

<img width="1024" height="512" alt="image" src="https://github.com/user-attachments/assets/4aa00dad-921f-43ed-b8f3-ae6491857083" />


One does not:

```text
chunk_02.bin
```

The expected CRC for this fragment is:

```text
0x0BAA09B6
```

The CRC calculated from the recovered on-disk `chunk_02.bin` does not match this value.

Therefore, the fragment has been corrupted.

---

# 14. Determining Why `chunk_02.bin` Is Corrupted

The reason becomes clear from the crash information in `system.log`.

The recovery process was interrupted by:

```text
SIGKILL
```

during a write operation near:

```text
0x00114560
```

This means `chunk_02.bin` was only partially or incorrectly written before the recovery process terminated.

The corrupted chunk therefore cannot simply be repaired by:

- Reordering it
- Recalculating its CRC
- Padding missing bytes
- Copying neighboring chunk data

Its original contents must instead be reconstructed from another authoritative source.

---

# 15. Using `model.enc` as the Recovery Source

Fortunately, the encrypted checkpoint still contains the complete original model.

After successful AES-256-CTR decryption, the resulting plaintext becomes the trusted source for reconstructing the damaged checkpoint fragment.

The process is therefore:

```text
model.enc
   |
   | derive AES key
   v
AES-256-CTR decrypt
   |
   v
complete checkpoint stream
   |
   | parse using manifest.bin
   v
model layers
   |
   | identify data corresponding to chunk_02
   v
reconstructed chunk_02.bin
```

---

# 16. Understanding `manifest.bin`

`manifest.bin` provides the metadata needed to interpret the decrypted checkpoint.

It contains information such as:

- Layer names
- Tensor dimensions
- Data lengths
- Layer offsets
- Expected hashes

Example entries include model layers such as:

```text
fc1.weight
fc1.bias
fc2.weight
fc2.bias
```

The tensor dimensions are especially useful because they allow the expected byte size of each layer to be calculated.

For example, if a tensor contains:

```text
rows × columns
```

32-bit floating-point parameters, then:

```text
layer_size = rows × columns × 4
```

bytes.

By walking through the manifest entries and their boundaries, it becomes possible to locate exactly which region of the decrypted checkpoint corresponds to the corrupted fragment.

---

# 17. Reconstructing `chunk_02.bin`

Using the offsets and layer metadata from `manifest.bin`, the relevant range is extracted from the freshly decrypted checkpoint.

Conceptually:

```python
recovered_chunk_02 = decrypted_checkpoint[start:end]
```

The reconstructed data is then verified against the integrity information.

The expected result is:

```text
CRC32(recovered_chunk_02) == 0x0BAA09B6
```

Once the CRC matches, the reconstruction can be trusted.

The corrupted disk copy is discarded and replaced by this recovered version.

---

# 18. Final Checkpoint Reassembly

At this stage we have:

```text
chunk_01.bin    valid
chunk_04.bin    valid
chunk_02.bin    reconstructed
chunk_00.bin    valid
chunk_03.bin    valid
```

Using the recovered logical ordering:

```text
checkpoint =
    chunk_01 ||
    chunk_04 ||
    recovered_chunk_02 ||
    chunk_00 ||
    chunk_03
```

This produces the restored checkpoint.

---

# 19. Recovery Workflow

The complete challenge can be represented as:

```text
                 ┌─────────────────────┐
                 │   researcher.note   │
                 └──────────┬──────────┘
                            │
              identifies recovery procedure
                            │
                            v
     ┌──────────────────────────────────────────┐
     │            KEY DERIVATION                │
     └──────────────────────────────────────────┘
              │              │             │
              v              v             v
      recovery.journal  config.fragment  training.log
              │              │             │
              v              v             v
           nonce       SHA256[:8]      dimcheck
              │              │             │
              └──────────────┼─────────────┘
                             v
                     HMAC-SHA256
                             │
                             v
                    AES-256 KEY
                             │
                             v
                       model.enc
                             │
                      AES-256-CTR
                             │
                             v
                  decrypted checkpoint
                             │
                  ┌──────────┴─────────┐
                  │                    │
                  v                    v
            manifest.bin       chunk recovery
                  │                    │
                  └──────────┬─────────┘
                             v
                  reconstruct chunk_02
                             │
                             v
                    CRC verification
                             │
                             v
      chunk_01 -> chunk_04 -> chunk_02
           -> chunk_00 -> chunk_03
                             │
                             v
                    restored checkpoint
                             │
                             v
                      metadata/header
                             │
                             v
                         FLAG
```

---

# 20. Automated Recovery Logic

The core recovery process can be represented with Python-style pseudocode:

```python
import hashlib
import hmac
import struct

from Crypto.Cipher import AES
from Crypto.Util import Counter


# Step 1: Recover nonce
nonce = bytes.fromhex("a3f1c2e4b5d6a7f8")


# Step 2: Calculate hash8
config_data = open("config.fragment", "rb").read()

hash8 = hashlib.sha256(config_data).digest()[:8]


# Step 3: Convert dimension checksum to big-endian uint16
dimcheck = struct.pack(">H", 0xA278)


# Step 4: Derive the AES-256 key
material = nonce + hash8 + dimcheck

key = hmac.new(
    b"SCBM_MASTER",
    material,
    hashlib.sha256
).digest()


print("AES key:", key.hex())


# Step 5: Parse encrypted checkpoint
encrypted = open("model.enc", "rb").read()

assert encrypted[:4] == b"ENCM"

iv = encrypted[4:20]
ciphertext = encrypted[20:]


# Step 6: AES CTR decryption
counter = Counter.new(
    128,
    initial_value=int.from_bytes(iv, "big")
)

cipher = AES.new(
    key,
    AES.MODE_CTR,
    counter=counter
)

checkpoint = cipher.decrypt(ciphertext)


# Step 7: Recover physical -> logical mapping
mapping = {}

for i in range(5):
    logical_slot = (2 * i + 4) % 5

    if logical_slot == 0:
        logical_slot = 5

    mapping[i] = logical_slot


print(mapping)
```

This results in:

```text
{
    0: 4,
    1: 1,
    2: 3,
    3: 5,
    4: 2
}
```

which gives:

```text
chunk_01
chunk_04
chunk_02
chunk_00
chunk_03
```

as the correct order.

The real recovery script would additionally parse `manifest.bin`, identify the damaged fragment boundaries and extract the replacement bytes from the decrypted checkpoint.

---

# 21. Extracting the Flag

After:

1. Deriving the correct AES key
2. Decrypting `model.enc`
3. Recovering the affine permutation
4. Reordering the checkpoint fragments
5. Detecting the corrupted `chunk_02.bin`
6. Reconstructing `chunk_02.bin` from the decrypted checkpoint
7. Verifying its CRC
8. Reassembling the checkpoint

the restored checkpoint metadata becomes readable.

Within the recovered metadata/header is the challenge flag:

```text
Lun4R{bfd5930913ecb6ac41e465838f7997f6}
```

---

# 22. Final Flag

```text
Lun4R{bfd5930913ecb6ac41e465838f7997f6}
```

---

# 23. Key Takeaways

This challenge combines several areas of practical digital forensics and cryptography rather than relying on a single trick.

The important lessons are:

- Do not automatically trust every log file in forensic evidence.
- Cross-check metadata from independent sources.
- Pay attention to explicit warnings about decoys and red herrings.
- Understand exactly whether cryptographic inputs are ASCII strings, hexadecimal strings or raw bytes.
- Endianness matters when constructing binary key material.
- HMAC can be used as a deterministic key-derivation mechanism.
- AES-CTR requires the correct key and initial counter/IV but does not require padding.
- File ordering can sometimes be reconstructed mathematically from observed offsets.
- Integrity checks such as CRC32 help distinguish ordering problems from genuine corruption.
- A corrupted artifact can often be reconstructed from another authoritative evidence source.
- Manifest files are valuable when recovering structured binary formats because they provide boundaries, dimensions and expected hashes.

The challenge's main trick is therefore not any single cryptographic operation. It is recognizing how multiple independent pieces of forensic evidence connect together.

---

# 24. Summary

The recovery chain can be reduced to:

```text
training.log
recovery.journal
config.fragment
      |
      v
HMAC-SHA256
      |
      v
AES-256 key
      |
      v
model.enc
      |
      v
AES-CTR decrypt
      |
      v
complete model
      |
      +----------------------+
      |                      |
      v                      v
manifest.bin          recovery.journal
      |                      |
layer boundaries       affine mapping
      |                      |
      v                      v
recover chunk_02       reorder chunks
      |                      |
      +----------+-----------+
                 |
                 v
         restored checkpoint
                 |
                 v
          embedded metadata
                 |
                 v
Lun4R{bfd5930913ecb6ac41e465838f7997f6}
```

**Final Flag:**

```text
Lun4R{bfd5930913ecb6ac41e465838f7997f6}
```
