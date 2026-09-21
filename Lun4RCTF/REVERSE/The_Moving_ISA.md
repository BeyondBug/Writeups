# The Moving ISA

**Category:** Reverse Engineering  
**Points:** 80  

## Challenge Description

The challenge describes an ancient execution engine whose instruction meanings change with each phase of the Moon. The runes remain physically unchanged, but their interpretation shifts between phases. The machine is divided into multiple trials, and supplying an invalid input causes the execution path to fail.

We are given two stripped x86-64 ELF binaries:

- `moving_isa_spector`
- `moving_isa_lockley`

From the prompts embedded in the binaries, the intended flow is:

```
Phase I: Activation Seal
        |
        v
   Celestial Token
        |
        v
Phase II: Celestial Token + Sanctum Key
        |
        v
      Flag
```

At first glance this suggests a full reverse-engineering task involving a custom VM and phase-dependent opcode mappings. Before attempting to reconstruct the VM, however, the binaries should be fingerprinted with basic static-analysis techniques.

## 1. Identify the binaries

```bash
file moving_isa_spector moving_isa_lockley
```

**Expected result:**

```
ELF 64-bit LSB executable, x86-64, dynamically linked, ... stripped
```

The binaries are stripped, so normal symbol names are unavailable. That makes simple static reconnaissance especially useful.

## 2. Inspect embedded strings

Run `strings` against the Phase I binary first:

```bash
strings -n 8 moving_isa_spector
```

Then inspect Phase II:

```bash
strings -n 8 moving_isa_lockley
```

The Phase II binary contains its normal prompts as well as the success-path message.

A targeted search is enough:

```bash
strings -n 8 moving_isa_lockley | grep -i flag
```

This reveals:

```
[+] Access Granted! Flag: Lun4R{sh1ft1ng_s4nds_0f_0pc0d3s}
```

The flag is therefore stored directly in the executable as a plaintext string.

## 3. Confirm the finding directly from the binary

The same result can be verified without `strings` by searching the raw file bytes:

```bash
grep -a -o 'Lun4R{[^}]*}' moving_isa_lockley
```

**Output:**

```
Lun4R{sh1ft1ng_s4nds_0f_0pc0d3s}
```

Another useful check is:

```bash
xxd -g 1 moving_isa_lockley | less
```

and search for `Lun4R` inside the hex dump.

## 4. Automated solver

A small Python solver can reproduce the result without depending on the `strings` utility.

**`solve_moving_isa.py`**

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FLAG_RE = re.compile(rb"Lun4R\{[^\x00\r\n}]{1,200}\}")
ELF_MAGIC = b"\x7fELF"


def find_flags(path: Path) -> list[str]:
    data = path.read_bytes()
    if not data.startswith(ELF_MAGIC):
        raise ValueError(f"{path} is not an ELF file")

    matches = FLAG_RE.findall(data)
    return [m.decode("ascii") for m in matches]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract an embedded Lun4R flag from the Phase II binary"
    )
    parser.add_argument("binary", type=Path, help="Phase II ELF binary")
    args = parser.parse_args()

    if not args.binary.is_file():
        print(f"[-] File not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        flags = find_flags(args.binary)
    except (OSError, ValueError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    flags = list(dict.fromkeys(flags))
    if not flags:
        print("[-] No Lun4R{...} flag was found.")
        return 2

    print(f"[+] Found {len(flags)} candidate(s):")
    for flag in flags:
        print(f"    {flag}")

    if len(flags) == 1:
        print(f"\n[+] Flag: {flags[0]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run it with:

```bash
python3 solve_moving_isa.py moving_isa_lockley
```

<img width="929" height="136" alt="image" src="https://github.com/user-attachments/assets/4a4c9bb8-a396-40d1-8eb7-8f23fa3663e9" />


## 5. Why the intended reverse-engineering path is unnecessary

The challenge narrative points toward reversing a custom instruction set whose opcode semantics change between phases. The binary prompts support that interpretation: Phase I asks for an Activation Seal and produces a Celestial Token, while Phase II expects that token and a Sanctum Key.

A full intended solve would therefore involve tracing the validation logic, identifying the VM state, recovering the phase-specific opcode mapping, and solving both sets of constraints.

However, a challenge does not require following the intended path when the artifact itself leaks the secret.

In this case, the Phase II success message is embedded as a static string in the executable. Since the flag is already present in plaintext, no VM emulation, symbolic execution, or dynamic debugging is required to recover it.

This is the critical observation:

```
Custom VM complexity
        |
        v
   Intended puzzle
        |
        X  not necessary

Plaintext flag in Phase II .rodata / string data
        |
        v
   Direct extraction
        |
        v
       FLAG
```

The exact storage section can be confirmed with tools such as `readelf`/`objdump` if desired; the important fact for exploitation is simply that the printable flag bytes are present in the executable.

## 6. Minimal solve

The shortest practical solution is:

```bash
strings -n 8 moving_isa_lockley | grep -i flag
```

or:

```bash
grep -a -o 'Lun4R{[^}]*}' moving_isa_lockley
```

## 7. Lessons Learned

This challenge demonstrates why reversing should begin with low-cost static reconnaissance before investing time in complex analysis.

A stripped binary can still reveal sensitive information through:

- hard-coded strings
- format strings
- debug messages
- error/success paths
- constants stored in `.rodata`

Even when the program implements a complicated custom VM, an embedded secret completely bypasses that complexity.

From a secure-development perspective, flags, API secrets, passwords, keys, and other sensitive constants should never be compiled into a distributed binary in plaintext.

## Final Flag

```
Lun4R{sh1ft1ng_s4nds_0f_0pc0d3s}
```

## One-Line Solve

```bash
strings -n 8 moving_isa_lockley | grep -i flag
```


<img width="1124" height="151" alt="image" src="https://github.com/user-attachments/assets/37f4b123-ef7e-4f0f-a39c-e51cfe72bc3c" />
