# The Last Transmission — CTF Write-up

**Category:** Forensics / Reverse Engineering / OSINT  
**CTF:** Lun4R CTF  
**Difficulty:** Medium–Hard  
**Points:** 450  
**Flag Format:** `Lun4R{...}`

## Challenge Description

Lun4r17 disappeared after its final transmission. An encrypted recovery archive remains, but its key was derived from an old public technical record. Find the archive, uncover the legacy key, and unlock the transmission.

## Overview

This challenge combines three disciplines — OSINT, archive decryption, and binary reverse engineering. The path to the flag is:

1. Investigate the Lun4r17 identity to find a public GitHub repository containing a deleted key-generation script.
2. Use the recovered algorithm to derive the ZIP password.
3. Decrypt the archive and reverse-engineer a custom binary format (`transmission.bin`) to extract the flag.

## Step 1 — Initial File Analysis

The challenge provides an encrypted ZIP archive:

| Property | Value |
|----------|-------|
| **File** | `lunar_last_transmission (1).zip` |
| **Size** | 315,260 bytes |
| **MD5** | `746953811843270ebf4e7c87e47073c9` |
| **SHA256** | `6baa926498adccc1c694853ccf27ab3610c4adf1f4706fccd9c9fa5795af7caa` |

A quick inspection reveals:

```python
import zipfile, hashlib

zip_path = "lunar_last_transmission (1).zip"

with open(zip_path, "rb") as f:
    data = f.read()

print("Size:  ", len(data))
print("SHA256:", hashlib.sha256(data).hexdigest())

with zipfile.ZipFile(zip_path, "r") as z:
    entries = z.infolist()
    print("Total Entries:", len(entries))
    print("Sample files:", [e.filename for e in entries[:6]])
```

**Results:**

- 792 total entries — 581 files, 211 directories
- Notable paths: `manifest/`, `logs/`, `recovered/`, `system/`, `transmission.bin`
- Encryption: PKZIP / ZipCrypto

The challenge description hints that the password came from an old public technical record, which points toward OSINT rather than brute-force cracking.

## Step 2 — OSINT Investigation

Searching for the station designation using variations such as `Lun4r17`, `LUN4R-17`, and `Lun4R-17` leads to a public GitHub repository:

**https://github.com/nox7392/lun4r17**

The repository is linked to the operator handle `nox7392`.

### Key Discovery — Deleted File in Git History

Examining the commit history reveals a deleted file called `legacy-key.py`. This file contains the password-generation algorithm used by the old system:

```python
def legacy_key(operator, station, relay, cycle):
    operator = operator.lower()
    station  = station.split("-")[-1]
    relay    = relay.lower().replace("-", "")
    return f"{operator}{station}{relay}{cycle}"
```

This is the exact function needed to reconstruct the ZIP password.

> **Lesson:** Git history permanently preserves deleted files. Even if a developer removes a sensitive file from the latest commit, it remains fully accessible in the repository's history.

## Step 3 — Password Derivation

The technical record associated with the repository provides the following values:

| Field    | Value     |
|----------|-----------|
| Operator | N0X       |
| Station  | LUN4R-17  |
| Relay    | ECHO-7    |
| Cycle    | 7392      |

Applying the legacy algorithm step by step:

| Step | Input     | Transformation          | Result  |
|------|-----------|-------------------------|---------|
| 1    | N0X       | Lowercase               | `n0x`   |
| 2    | LUN4R-17  | Take text after `-`     | `17`    |
| 3    | ECHO-7    | Lowercase, remove `-`   | `echo7` |
| 4    | 7392      | Use as-is               | `7392`  |

**Derived Password:** `n0x17echo77392`

## Step 4 — Decrypting the Archive

```python
import zipfile

zip_path = "lunar_last_transmission (1).zip"
password = b"n0x17echo77392"

with zipfile.ZipFile(zip_path, "r") as z:
    z.extractall("extracted", pwd=password)

print("[+] Archive successfully decrypted and extracted.")
```

After extraction, the directory structure is:

```
lunar_last_transmission/
├── transmission.bin
├── system/
│   ├── manifest
│   ├── calibration.dat
│   └── diagnostics
└── logs/
    └── diagnostic.log
```

The primary target is `transmission.bin`.

## Step 5 — Binary Analysis (`transmission.bin`)

| Property | Value |
|----------|-------|
| **Size** | 8,719 bytes |
| **MD5** | `3cab6fb6f3a17e600d272f965c31187e` |
| **SHA256** | `79c7958dde052ac7c176f5d626318f4ce8c51d846bdcdf2713b2c6d54afc432b` |

The file starts with the magic bytes `LN4R`, indicating a custom binary container.

### File Header (15 bytes)

| Offset | Field            | Type      | Value              |
|--------|------------------|-----------|--------------------|
| 0x00   | Magic            | 4 bytes   | `LN4R`             |
| 0x04   | Version          | uint8     | 1                  |
| 0x05   | Record Count     | uint16 LE | 256                |
| 0x07   | Obfuscated Seed  | uint64 LE | `0xa24502ec670fc107` |

**Size verification:** `15 + (256 × 34) = 8719` bytes ✓

### Record Structure (34 bytes each)

| Offset | Field          | Size    |
|--------|----------------|---------|
| +0x00  | Record ID      | 2 bytes |
| +0x02  | Sequence Hint  | 2 bytes |
| +0x04  | Timestamp      | 4 bytes |
| +0x08  | Payload        | 16 bytes|
| +0x18  | Checksum       | 2 bytes |
| +0x1A  | Metadata       | 8 bytes |

Records are not processed in order. Each record's metadata encodes a pointer to the next record — forming a linked traversal graph.

## Step 6 — State Machine Reconstruction

Additional parameters are found in the supporting system files.

### Reconstructing the Initial State

The IV values from `system/calibration.dat` and `system/diagnostics`:

- **Lower IV:** `0xE66EB118`
- **Upper IV:** `0x10BA53D8`
- **Full IV** = `0x10BA53D8E66EB118`

The actual starting state is the XOR of the obfuscated seed and the full IV:

```
0xa24502ec670fc107
XOR
0x10ba53d8e66eb118
= 0xb2ff51348161701f
```

The starting record ID is:

```
0xb2ff51348161701f % 256 = 31
```

Traversal begins at record 31.

### Per-Record Processing (6 steps)

For each visited record:

1. **Extract one byte:**
   ```
   pos           = 8 + (state % 4)
   plaintext_byte = payload[pos] ^ ((state >> 8) & 0xFF)
   ```

2. **Mix the payload into state:**
   ```
   state ^= uint64_le(payload[0:8])
   ```

3. **Rotate the state:**
   ```
   rot   = (metadata[0] % 63) + 1
   state = ROTL64(state, rot)
   ```

4. **Add a metadata accumulator:**
   ```
   accum = uint32_le(metadata[2:6])
   state = (state + accum) & 0xFFFFFFFFFFFFFFFF
   ```

5. **Apply checksum spread:**
   ```
   spread = checksum | (checksum << 16) | (checksum << 32) | (checksum << 48)
   state ^= spread
   ```

6. **Compute the next record ID:**
   ```
   word_a  = uint16_le(payload[12:14])
   word_b  = uint16_le(metadata[6:8])
   next_id = word_a ^ word_b
   ```

Traversal terminates when `next_id == 0xFFFF`.

## Step 7 — Complete Decoder

```python
#!/usr/bin/env python3
import struct

MASK64 = 0xFFFFFFFFFFFFFFFF

def rotl64(value: int, count: int) -> int:
    count %= 64
    return ((value << count) | (value >> (64 - count))) & MASK64

def decode_transmission(file_path: str):
    with open(file_path, "rb") as f:
        data = f.read()

    if data[:4] != b"LN4R":
        raise ValueError("Invalid LN4R container")

    version      = data[4]
    record_count = struct.unpack("<H", data[5:7])[0]
    obf_seed     = struct.unpack("<Q", data[7:15])[0]

    if version != 1:
        raise ValueError(f"Unsupported version: {version}")

    # Reconstruct initial state
    lower_iv = 0xE66EB118
    upper_iv = 0x10BA53D8
    full_iv  = lower_iv | (upper_iv << 32)
    state    = obf_seed ^ full_iv

    # Parse all records
    records = {}
    for i in range(record_count):
        offset = 15 + (i * 34)
        rec    = data[offset:offset + 34]
        if len(rec) != 34:
            raise ValueError("Incomplete record")

        record_id = struct.unpack("<H", rec[0:2])[0]
        records[record_id] = {
            "payload":  rec[8:24],
            "checksum": struct.unpack("<H", rec[24:26])[0],
            "metadata": rec[26:34],
        }

    # Traverse the record graph
    current_id = state % 256
    extracted  = []
    hops       = 0

    while current_id != 0xFFFF:
        if current_id not in records:
            raise ValueError(f"Unknown record ID: {current_id}")

        record   = records[current_id]
        payload  = record["payload"]
        checksum = record["checksum"]
        metadata = record["metadata"]

        # Step 1 — Extract byte
        pos            = 8 + (state % 4)
        plaintext_byte = payload[pos] ^ ((state >> 8) & 0xFF)
        extracted.append(chr(plaintext_byte))

        # Step 2 — Mix payload
        fragment = struct.unpack("<Q", payload[:8])[0]
        state ^= fragment

        # Step 3 — Rotate
        rotation = (metadata[0] % 63) + 1
        state    = rotl64(state, rotation)

        # Step 4 — Accumulate
        accum = struct.unpack("<I", metadata[2:6])[0]
        state = (state + accum) & MASK64

        # Step 5 — Checksum spread
        spread = (checksum | (checksum << 16) |
                  (checksum << 32) | (checksum << 48))
        state ^= spread

        # Step 6 — Next record
        word_a     = struct.unpack("<H", payload[12:14])[0]
        word_b     = struct.unpack("<H", metadata[6:8])[0]
        current_id = word_a ^ word_b
        hops      += 1

    payload_text = "".join(extracted)
    flag         = f"Lun4R{{{payload_text}}}"
    return payload_text, flag, hops

if __name__ == "__main__":
    path = "extracted/lunar_last_transmission/transmission.bin"
    payload, flag, hops = decode_transmission(path)
    print(f"[+] Traversal completed in {hops} hops.")
    print(f"[+] Recovered Payload: {payload}")
    print(f"[+] Flag: {flag}")
```

## Step 8 — Result

```
[+] Traversal completed in 27 hops.
[+] Recovered Payload: FRAGMENT_SHARD_b5acb9c6b3dc
[+] Flag: Lun4R{FRAGMENT_SHARD_b5acb9c6b3dc}
```

Traversal starts at record 31 and reaches the terminal marker `0xFFFF` after 27 hops, extracting one character per record.

## Flag

```
Lun4R{FRAGMENT_SHARD_b5acb9c6b3dc}
```
