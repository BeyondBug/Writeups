s="u`?c={J0*~F0v_E0`%0P/P"
rot=lambda x:"".join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in x)
print(f"SecLeaf{{{rot(s)}}}")
