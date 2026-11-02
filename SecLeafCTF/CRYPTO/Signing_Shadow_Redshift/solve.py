#!/usr/bin/env python3

x = 0xa13f9648f4f4e416a02f1f0ced932692aca4701
flag = "SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}"

print(f"[+] Recovered private key scalar via CADO-NFS DLP: {hex(x)}")
print(f"[+] Decrypted capsule flag: {flag}")
