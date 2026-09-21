## Lunar Abyss v2 - Crypto Write-up
### Challenge: Lunar Abyss v2 - Multi-Layer Cryptographic Vault
### Category: Crypto
###  Flag format: Lun4R{...}
## TL;DR
>The challenge is a 10-layer decryption chain. The only intentionally missing secret is the RSA private exponent RSA_D in Layer 5.
>The RSA modulus RSA_N is vulnerable to Fermat factorization because its two 1024-bit primes are extremely close. In this instance, Fermat succeeds on the first iteration.
>After recovering p and q, compute:
```phi(N) = (p - 1)(q - 1)
d = e^(-1) mod phi(N)
```


>Set RSA_D = d and run full_decrypt(CIPHERTEXT).
>There is also a major source-code disclosure: challenge.py literally contains the flag in the global FLAG variable. Therefore, from the supplied player file alone, the flag can be read directly without performing the cryptanalysis.
## Recovered flag:
```
Lun4R{7h3_m00n_n3v3r_l13s_bu7_y0u_d0}
```

## 1. Challenge overview
>The supplied archive contains a single file:
>lunar_abyss_v2_player/challenge.py
## The script defines a ten-stage encryption chain:
    1. 128-bit Galois LFSR
    2. 8×8 matrix cipher over GF(257)
    3. 6-round SPN
    4. 64-round Feistel
    5. Textbook RSA-2048
    6. BLAKE2s stream XOR
    7. Key-derived byte permutation + XOR
    8. HMAC-SHA3-512 XOR entanglement
    9. ChaCha20
    10. AES-256-GCM
## The decryption order is the reverse:
```
L10 → L9 → L8 → L7 → L6 → L5 → L4 → L3 → L2 → L1
```
>The script itself says that Layer 5 is locked because RSA_D is missing and gives the intended hint:
>RSA_D = None

```and later:
[+] RSA-2048 loaded...
[*] Core Layer 5 (RSA) is locked: RSA_D is missing!
[*] HINT: Inspect the primes P and Q of RSA_N (are they close?).
[*] Factor RSA_N using Fermat Factorization, compute RSA_D, and run full_decrypt()!
That tells us exactly where the cryptanalytic break is expected.
```
## 2. Immediate source-code leak
>Before doing any crypto, inspect the top of the file.
>The challenge contains:
```
FLAG = b"Lun4R{7h3_m00n_n3v3r_l13s_bu7_y0u_d0}"
```
>So the flag is directly embedded in the player-side source.
```
A minimal extraction is:
grep -n '^FLAG' lunar_abyss_v2_player/challenge.py
Expected result:
Lun4R{7h3_m00n_n3v3r_l13s_bu7_y0u_d0}
```

## 3. Finding the RSA weakness
>The relevant parameters are:
>RSA_N = 8318246423128085...1103
>RSA_E = 65537
>RSA_D = None

**The ciphertext is split into 256-byte RSA blocks, and each RSA plaintext block is only 32 bytes:**
```
CT_BLOCK = 256
MSG_BLOCK = 32
The challenge explicitly hints that the primes are close.
Why Fermat works
For an RSA modulus:
N = p × q
with p and q close together, write:
N = a² - b² = (a-b)(a+b)
where:
a = ceil(sqrt(N))
If a² - N is a perfect square, then:
p = a - b
q = a + b
This is Fermat factorization.
```
>In this challenge, the factors are exceptionally close, so no long search is required.

## 4. Recovering p and q
```
Use Python's standard library only:
from math import isqrt

N = RSA_N

a = isqrt(N)
if a * a < N:
    a += 1

b2 = a * a - N
b = isqrt(b2)

assert b * b == b2

p = a - b
q = a + b

print("p =", p)
print("q =", q)
For this challenge, Fermat succeeds at iteration 0.
The recovered factors are:
p = 91204421072270863308668902951464337274947728935662789631983662870401693349050217369565700767628738817496838205597601687991693546957695200248764391462029326460199324912091736943951430101959016113732754570447812863629064479903021445178934342691418057091350266676826602036768462838186514324634434941671585242671

q = 91204421072270863308668902951464337274947728935662789631983662870401693349050217369565700767628738817496838205597601687991693546957695200248764391462029326460199324912091736943951430101959016113732754570447812863629064479903021445178934342691418057091350266676826602036768462838186514324634441671854232793
The key observation is the difference:
q - p = 268990122
For 1024-bit RSA primes, a gap of only about 2.7×10^8 is tiny. That is exactly why Fermat factorization is devastating here.

5. Computing the private exponent
Once p and q are known:
phi = (p - 1) * (q - 1)
d = pow(RSA_E, -1, phi)
The recovered private exponent is:
d = 4411766291125762906540107006199598370466246589623750212780580830268315815027047366233462495144255223262870414403467124272546518334403268993897813712334002164915119098456414662623320121882423581324023943180537652802296830520044224010705231162610667806398190828171543374275813630445639630230402625126795356283883837306774855229802464144855233782552392190193776066823587987041871086374856561725689687989203187563734148286924715190356598559080191705530308093037983094574776723403494245314822762131496090325181419725192415431907729001653398859844192592884837311895762090472424517034145749560276445485818648003275150635953
```
## 6. Patching the challenge
```
The original script has:
RSA_P = None
RSA_Q = None
RSA_D = None
Replace these values after factoring:
RSA_P = p
RSA_Q = q
RSA_D = pow(RSA_E, -1, (p - 1) * (q - 1))
Then the existing:
flag = full_decrypt(CIPHERTEXT)
print(flag)
can be used to recover the final plaintext.

7. One-shot solver
The following script automates the RSA part and patches the challenge module.
Note: the challenge uses PyCryptodome (Crypto.Cipher, Crypto.Hash). Install it in your environment first if it is missing.
python3 -m pip install pycryptodome
Then:
#!/usr/bin/env python3

import importlib.util
from math import isqrt

CHALLENGE = "lunar_abyss_v2_player/challenge.py"

spec = importlib.util.spec_from_file_location("challenge", CHALLENGE)
challenge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(challenge)

# Recover p and q with Fermat factorization.
N = challenge.RSA_N
e = challenge.RSA_E

a = isqrt(N)
if a * a < N:
    a += 1

iterations = 0
while True:
    b2 = a * a - N
    b = isqrt(b2)
    if b * b == b2:
        break
    a += 1
    iterations += 1

p = a - b
q = a + b

print(f"[+] Fermat iterations: {iterations}")
print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] q-p = {q-p}")

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print(f"[+] d = {d}")

# Inject the recovered RSA private key.
challenge.RSA_P = p
challenge.RSA_Q = q
challenge.RSA_D = d

# Full reverse chain: L10 -> ... -> L1.
flag = challenge.full_decrypt(challenge.CIPHERTEXT)
print(f"[+] FLAG: {flag.decode()}")
Run it from the directory containing the challenge:
python3 solve.py
The final line should be:
[+] FLAG: Lun4R{7h3_m00n_n3v3r_l13s_bu7_y0u_d0}
```

## 8. Why the RSA construction is broken
```
The challenge uses textbook RSA:
m = bytes_to_long(block)
c = pow(m, RSA_E, RSA_N)
Textbook RSA itself is deterministic and unsuitable for real-world encryption, but that is not the primary break here.
The fatal issue is the RSA key generation: the two 1024-bit primes are far too close.
For balanced RSA primes, Fermat's method is effective when the difference between the primes is unusually small. Here:
q - p = 268,990,122
and Fermat finds the exact square immediately.
Once the factors are recovered, the entire RSA private key follows from elementary arithmetic.
```


## 9. Understanding the full chain

>The remaining layers are mostly distractions once Layer 5 is solved because the source already contains every symmetric/key-derivation secret needed to reverse them.


### The reverse path is:

```
CIPHERTEXT
   │
   ▼
L10 AES-256-GCM
   │
   ▼
L9 ChaCha20
   │
   ▼
L8 HMAC-SHA3-512 XOR
   │
   ▼
L7 byte permutation + XOR
   │
   ▼
L6 BLAKE2s XOR stream
   │
   ▼
L5 RSA-2048  ← missing d, recovered via Fermat
   │
   ▼
L4 64-round Feistel
   │
   ▼
L3 6-round SPN
   │
   ▼
L2 GF(257) matrix inverse
   │
   ▼
L1 LFSR XOR
   │
   ▼
FLAG
```
>The challenge's own implementation already supplies the inverse routine for every layer. Therefore the intended cryptanalytic work is concentrated almost entirely on factoring RSA_N and restoring RSA_D.

## 10. Useful shell commands

```
Extract the archive
unzip abyss.zip
cd lunar_abyss_v2_player
Instantly reveal the source-disclosed flag
grep -n '^FLAG' challenge.py
Locate the RSA parameters
grep -n 'RSA_N\|RSA_E\|RSA_D\|CT_BLOCK\|MSG_BLOCK' challenge.py
Quickly test Fermat manually
python3 - <<'PY'
from math import isqrt

N = int(input("N = ").strip())
a = isqrt(N)
if a*a < N:
    a += 1
b2 = a*a - N
b = isqrt(b2)
print("perfect square:", b*b == b2)
if b*b == b2:
    print("p =", a-b)
    print("q =", a+b)
PY
```
## 11. Final answer
>Lun4R{7h3_m00n_n3v3r_l13s_bu7_y0u_d0}

## 12. Takeaways
    1. Always inspect challenge source first. The strongest “crypto” attack may simply be an implementation mistake or secret disclosure.
    2. Check RSA prime quality. If the primes are too close, Fermat factorization can recover them rapidly.
    3. Do not assume a large RSA modulus is automatically secure. Key generation matters as much as modulus size.
    4. Layered crypto can hide a very small number of actual weaknesses. Once the missing RSA private key is recovered, the supplied inverse routines handle the rest of the chain.
