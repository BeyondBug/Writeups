#!/usr/bin/env python3
import base64

# Part 1 carved from harvest.enc
part1 = "d3l3t3d_k3ys_n3v3r_d13"

# Part 2 recovered from user.leaf xattr on notes.txt
xattr_b32 = "L52GQM27PBQXI5DSL5ZDG3JTNVRDG4TT"
part2 = base64.b32decode(xattr_b32).decode("utf-8")

print(f"Part 1: {part1}")
print(f"Part 2: {part2}")
print(f"Flag: SecLeaf{{{part1}{part2}}}")
