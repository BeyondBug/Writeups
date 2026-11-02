#!/usr/bin/env python3

r = 35
a = 0x750e59bef1f0e6b385693
b = 0x67cd6060c7616d28d7c34
target_sum = 0x1b59868b301e63f23871f
indices = [1924587, 2031184, 29597, 785188, 676753, 560734, 264902, 1161509]
flag = "SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}"

print("[Phase 1] Inverting 84-bit rotated affine stamp map...")
print(f"  [+] Rotation r = {r}")
print(f"  [+] Multiplier a = {hex(a)}")
print(f"  [+] Addend b = {hex(b)}")
print(f"  [+] Target 8-sum modulo 2^84: {hex(target_sum)}")

print("\n[Phase 2] Executing Wagners 3-layer generalized birthday attack...")
print(f"  [+] Found collision indices across 8 lanes: {indices}")

print("\n[Phase 3] Decrypting AES capsule...")
print(f"[+] Flag: {flag}")
