# Umbra Challenge Write-up

## Overview
`umbra` is a stripped Linux ELF binary. Static analysis of embedded strings reveals two important clues:

- The constant `"expand 32-byte k"` indicates the use of ChaCha20.
- Failure to validate decrypted data produces the message `"Frame Integrity Check Failed"`.

The challenge theme of **duality** reflects the fact that many keys satisfy the initial validation checks, yet only one produces a correctly checksummed payload.

---

## Program Flow

Analysis of the disassembly shows the following stages:

1. **Access Sequence Validation**  
   The supplied 32-byte key is processed through a series of 32 arithmetic and bitwise operations (additions, multiplications, and XORs). Each intermediate result is compared against a hardcoded constant. Failure of any check results in `"Invalid Access Sequence"`.

2. **Key Derivation & Decryption**  
   If the key passes validation, a secondary key is derived via SHA-256 combined with scrambled internal state. This derived key is used to decrypt a hidden 64-byte ciphertext with ChaCha20.

3. **Integrity Check**  
   A CRC-32 checksum is computed over the decrypted data.  
   - Match → the plaintext is printed.  
   - Mismatch → `"Frame Integrity Check Failed"`.

Only the correct key yields a payload that survives the checksum.

---

## Key Recovery

Manual solution of the 32 constraints is impractical. Symbolic execution with **angr** was used to collect all keys satisfying the validation equations. Thousands of solutions exist.

Filtering the candidate set for printable ASCII characters reduces the set to a single viable key:

```
Lun4R_0rbital_umbra_2026_key_7a9
```

---

## Verification

Execution of the binary with the recovered key produces:

```
Payload Decrypted Successfully
```

followed by the flag. Alternative keys that satisfy the initial checks correctly fail the CRC-32 validation, confirming that the recovered key is the intended solution.

---

## Final Flag

```
Lun4R{sh4d0w_c4lc_1n_th3_lunar_umbra_7a9f}
```
