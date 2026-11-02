#!/usr/bin/env python3

# Obfuscated line from acme-infrastructure/logs/deploy-2026-09-18.log
enc = b"SjcCenftl<g;cV_}eh1|T}YPm>g}a[1`nP274r"

# Invert repeating XOR key (KEY_15_00f -> odd bytes XOR 0x0F)
flag = bytes(b ^ (0x0F if i % 2 == 1 else 0x00) for i, b in enumerate(enc)).decode()
print("Decrypted Error Message:", flag)
print("Flag:", flag)
