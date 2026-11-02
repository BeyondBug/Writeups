#!/usr/bin/env python3
"""Reference AES-128 implementation with Round 9 fault injection hook."""

def sub_bytes(s): ...
def shift_rows(s): ...
def mix_columns(s): ...
def add_round_key(s, k): ...

def aes_encrypt_block(state, round_keys, fault=None):
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 11):
        state = sub_bytes(state)
        state = shift_rows(state)

        # Fault injection hook in Round 9 right before MixColumns
        if rnd == 9 and fault is not None:
            c, r, v = fault
            state[4 * c + r] ^= v

        if rnd < 10:
            state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    return state

if __name__ == "__main__":
    print("[*] Fault Atlas AES Model Loaded.")
