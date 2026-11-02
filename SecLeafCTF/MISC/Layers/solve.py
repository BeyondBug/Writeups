#!/usr/bin/env python3

# Recovered text from RAR5 archive (password: stormstorm)
rot47_text = "u`?c={J0*~F0v_E0`%0P/P"

def rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)

decoded = rot47(rot47_text)
print(f"Decoded: {decoded}")
print(f"Flag: SecLeaf{{{decoded}}}")
