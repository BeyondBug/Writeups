rot47_text = "u`?c={J0*~F0v_E0`%0P/P"

def rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)

print(f"SecLeaf{{{rot47(rot47_text)}}}")
