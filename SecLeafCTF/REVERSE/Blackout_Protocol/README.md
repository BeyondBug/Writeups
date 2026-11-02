# Blackout Protocol

This was a solid 500-pointer by 5h1kh4r. The challenge zip came with a stripped ELF64 executable (`blackout_protocol`) and three forensic artifacts:
- `retained.mem` (16 KB raw memory dump)
- `incident.journal` (custom binary log with `JRN4` magic)
- `transmission.pcap` (290 UDP packets)

Firing up the binary prompts for a 48-byte password. If it passes validation, you get `Authenticated.`; otherwise, `Blackout.`.

### The Gimmick: Intentional Decoys Everywhere
Looking at the binary in IDA/Ghidra, I realized quickly that you couldn't just write a parser based on standard formats. The author purposefully seeded decoy headers in the memory dump, corrupted records in the journal, and spoofed UDP packets in the PCAP. Every file feeds cryptographic parameters into the next:

`retained.mem` -> `incident.journal` -> `transmission.pcap` -> S-box/seeds -> Invert 52 rounds -> Flag

### Reversing the Pipeline

1. **Memory Dump (`retained.mem`):**
   A decoy header sits at `0x220`, but the binary explicitly checks offset `0x180` for magic `M16B`. It pulls session tag `0x37` (`'7'`) and XORs two 64-bit words at `0x198` and `0x1a0` to produce constant `r14 = 0xd90ce44398978318`.

2. **Journal (`incident.journal`):**
   Contains 224 records, but the binary filters strictly on `tag == 0x37`, `idx < 48`, matching FNV-1a checksums, and takes only the *first* occurrence per index. Exactly 48 genuine records survive, populating `arr[48]` and collapsing into chaining hash `H = 0x0e733fa8595bfa24`.

3. **Packet Capture (`transmission.pcap`):**
   Packets must be processed in raw capture order (sorting by timestamp destroys the PRNG stream). The binary filters for UDP `10.64.0.1:2419 -> 10.64.0.2:31337` starting with `BKP5\x37`. 
   
   Here was the biggest trap: 72 forged packets pass a rolling 16-bit checksum, but fail a second 32-bit check (`chk32`) keyed by `arr[(7*slot + 3) % 48]` from the journal. Filtering strictly by `chk32` leaves exactly 32 genuine packets, which decrypt via SplitMix64 into a 384-byte keystream `K`.

### The 52-Round Cipher
Once all parameters are extracted, the binary hashes them into a master seed:
`seed = mix64(tag ^ r14 ^ H ^ K[0:8] ^ K[73:81]) = 0x98b5f1c61c260485`

This seed builds an S-box (via Fisher-Yates shuffle with `xorshift64*`) and runs 52 rounds of a Substitution-Permutation Network (SPN) on the 48-byte input:
1. S-box substitution: `S[j] = T[S[j] ^ f(round, j)]`
2. Affine byte permutation: `S'[(7*round + 11 + 17*k) % 48] = S[k]`

Since each round is strictly bijective, reversing the cipher was straightforward: start at the target ciphertext in the binary, invert the permutation, and apply the inverse S-box for rounds 51 down to 0.

### Solving
Put together the full inversion script:

```python
import struct
from scapy.all import rdpcap, UDP, IP

# Extract genuine packets and compute keystream
pcap = rdpcap("transmission.pcap")
H = 0x0e733fa8595bfa24

# Reconstruct 52 rounds backwards from binary target ciphertext
TARGET = bytes.fromhex(
    "3f9b2a7e11048bc8da54f16a09bc221844a2fe9071b563cd"
    "19e830f5a7cb8120e54d682ca05b9f71c43162ae84105d7b"
)

# ... (inverse S-box and round permutation inversion) ...
# Walking rounds 51 down to 0:
```

Ran the script to recover the 48-byte password:
```bash
$ python3 solve.py
[+] Recovered: SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}

$ ./blackout_protocol 'SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}'
Authenticated.
```

Flag:
```text
SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```
