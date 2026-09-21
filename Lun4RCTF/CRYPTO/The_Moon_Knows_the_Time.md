# The Moon Knows the Time

**Category:** Crypto  
**Points:** 200  

## Challenge Description

An internal service encrypted a message during an incident investigation. The recovered record contains a ciphertext, a nonce, and a timestamp.

The challenge hints that the timestamp contains more information than it appears to:

> The record contains more information than just the ciphertext.  
> Look carefully at how precise the recorded time actually is.  
> Sometimes the weakest part of encryption happens before the cipher is ever called.

The important clue is the recorded time and the fact that it has been rounded.

## 1. Inspect the Incident Record

The endpoint exposes an incident record similar to:

```json
{
  "ciphertext": "/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q==",
  "created_at": "2026-09-20T04:37:00Z",
  "nonce": "7e197b75b71d8956",
  "request_id": "req-ceadab40405c"
}
```

Three values are immediately interesting:

- **Ciphertext:** Base64 encoded encrypted data
- **Nonce:** `7e197b75b71d8956`
- **Timestamp:** `2026-09-20T04:37:00Z`

The challenge specifically tells us to pay attention to the timestamp.

## 2. Notice the Timestamp Weakness

The displayed timestamp ends in:

```
04:37:00
```

That strongly suggests the time has been rounded to the minute.

However, encryption normally happens at a particular second.

That means the real encryption time could have been anywhere between:

```
2026-09-20 04:37:00
```

and

```
2026-09-20 04:37:59
```

So instead of searching an enormous keyspace, we only need to test **60 possible Unix timestamps**.

## 3. Determine How the Nonce Was Generated

The nonce is:

```
7e197b75b71d8956
```

It is exactly 8 bytes long.

An 8-byte value is suspiciously small for a randomly generated cryptographic value and is a good candidate for a truncated hash.

We therefore test:

```python
sha256(str(timestamp).encode()).digest()[:8]
```

for every second in the recorded minute.

The matching timestamp is:

```
1789879078
```

which corresponds to:

```
2026-09-20 04:37:58 UTC
```

**Verification:**

```python
import hashlib

ts = b"1789879078"
print(hashlib.sha256(ts).digest()[:8].hex())
```

**Output:**

```
7e197b75b71d8956
```

This proves that the nonce was derived from the actual encryption timestamp.

## 4. Recover the AES Key

The same timestamp-derived hash is also used as the encryption key.

Instead of only taking the first 8 bytes, we use the full SHA-256 digest:

```python
key = hashlib.sha256(b"1789879078").digest()
```

A SHA-256 digest is 32 bytes, so the resulting AES key is:

```
256 bits
```

Therefore, despite the service indicating AES-128-CTR, the recovered key length corresponds to **AES-256-CTR**.

The important relationship is:

```
timestamp
    |
    v
SHA-256(timestamp)
    |
    +---- first 8 bytes ---> nonce
    |
    +---- full 32 bytes ---> AES key
```

This means that once the timestamp is recovered, both the nonce and the key can be reconstructed.

## 5. Decrypt the Ciphertext

The ciphertext is Base64 encoded, so decode it first and decrypt it using AES in CTR mode.

### Solver

```python
import base64
import hashlib
from Crypto.Cipher import AES

ciphertext = base64.b64decode(
    "/QuCUtzvX5n3x/c3OPyV4MAF7Y749Mjn4Q=="
)
nonce = bytes.fromhex("7e197b75b71d8956")
timestamp = b"1789879078"

# Full SHA-256 digest becomes the AES key
key = hashlib.sha256(timestamp).digest()

# Decrypt using AES-256-CTR
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

print(plaintext.decode())
```


<img width="937" height="421" alt="image" src="https://github.com/user-attachments/assets/cbe5079d-d006-48ab-b284-3f0c6c227956" />


## 6. Why the Challenge Is Vulnerable

The cryptography itself is not the main problem. The weakness is the **predictable key material**.

The encryption process effectively behaves like:

```
current_timestamp
       |
       v
    SHA-256
       |
       +------------------+
       |                  |
       v                  v
   8-byte nonce        32-byte AES key
```

Although SHA-256 is cryptographically strong, using a timestamp that can be predicted or reconstructed makes the overall construction weak.

Because the timestamp was only rounded in the visible record, the attacker can recover the exact second by testing a tiny number of possibilities.

Once the exact second is known:

```
timestamp → SHA-256 → key
timestamp → SHA-256[:8] → nonce
```

and the ciphertext can be decrypted.

## Exploit Summary

1. Inspect the incident record.
2. Notice that `created_at` is rounded to the minute.
3. Treat the 60 seconds in that minute as the candidate timestamps.
4. Hash each Unix timestamp with SHA-256.
5. Compare the first 8 bytes of each hash with the supplied nonce.
6. Recover the real timestamp: `1789879078`.
7. Use the full SHA-256 digest as the AES key.
8. Decrypt the Base64 ciphertext with AES-CTR.
9. Recover the flag.

## Flag

```
Lun4r{t1m3_1s_n0t_4_prng}
```
