import base64

part1 = "d3l3t3d_k3ys_n3v3r_d13"
xattr_b32 = "L52GQM27PBQXI5DSL5ZDG3JTNVRDG4TT"
part2 = base64.b32decode(xattr_b32).decode("utf-8")
print(f"SecLeaf{{{part1}{part2}}}")
