#!/usr/bin/env python3
"""Eightfold Funeral - Reference stamp generation and lane setup."""

MASK84 = (1 << 84) - 1

def ROL84(x, r):
    r %= 84
    return ((x << r) | (x >> (84 - r))) & MASK84

def make_stamp(x, a, b, r):
    """Generates an 84-bit calibration stamp via affine transform and bitwise rotation."""
    return ROL84((a * x + b) & MASK84, r)

if __name__ == "__main__":
    print("[*] Eightfold Funeral model loaded.")
