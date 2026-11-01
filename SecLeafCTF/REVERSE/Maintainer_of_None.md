# Maintainer of None

I extracted the zip archive into a clean working directory. It contained
three stripped pie binaries, three shared libraries, three sqLite
databases, a Git bundle, a release tarball and custom containers such
as journal.vlg,fragments.dat,palinode.bin and riscv.rom.

The main executables were custodian,arbiter and conclave, with
libstamp.so,libpolicy.so and libisa.so supporting the stages.
Since the programs opened files through relative paths and hashed the
supplied evidence, i worked from a clean copy and kept the original
files unchanged.

## Step 2 (Recon)

I used strings to identify stage markers such as V3/JRNL,
V4/PALIN and V5/MMIZ.i also found the SecLeaf{ flag prefix,
which indicated that the executables built and validated flags
internally.

Because the binaries were stripped, i decompiled them with headless
ghidra and reviewed the relevant functions.i enabled pending
breakpoints in GDB for functions loaded dynamically from shared
libraries.

``` bash
analyzeHeadless gproj p_custodian \
  -import ex/custodian \
  -postScript Decomp.java dec/custodian.c \
  -deleteProject
```

``` gdb
set breakpoint pending on
```

## Step 3 (Inspect)

I started with custodian and libstamp.so.The command
./custodian --reconcile w3.bin expected a 576-byte witness containing
32 little-endian u16 values followed by 128 u32 journal ids.

I traced the validation flow and identified the evidence hashes used to
bind the witness to the challenge files.

## Step 4 (Calculated the evidence hashes)

The program calculated SHA-256 hashes for release.tar.xz,
forge.sqlite, the running executable, the three relevant tar members,
history.bundle and libstamp.so.

The lane and mark came from the first eight bytes of this digest:

``` text
lane || mark = SHA256("LANE/COMPROMISE/V2" || R || G || T)[0:8]
```

The twin key was derived as follows:

``` text
TWIN = SHA256("TWINFORGE-V2/" || R || F || X || T || G || S)
```

Using the supplied evidence,i recovered:

``` text
lane = 0xc4c0045a
mark = 0xca305c5d
```

These values were necessary for selecting the relevant database rows and
decrypting the journal.

## Step 5 (Recover the journal)

journal.vlg used the VLOG9C format and contained 0x6000 records of
0x60 bytes each. Each record was decrypted with a sha-256 counter
stream keyed by TWIN.

Instead of reimplementing the decryption,i used GDB to inspect the
process after the journal had been decrypted in memory.i stopped near
the missing-witness message and dumped the decrypted table, along with
the lane and mark values.

## Step 6 (solved the arithmetic system)

I queried reconciliation_ledger for records matching the recovered
lane. The witness values were defined by a 32-by-32 linear system over
the prime field modulo 65521:

``` text
sum(c[r,j] * w[j]) + b[r] == s[r] (mod 65521)
```

The blinding term b[r] was derived from the lane and row number using
sha-256, with the adjustment implemented by the binary for values above
0xfff0.

I solved the system using modular Gaussian elimination and checked that
every recovered value satisfied the accepted range.

## Step 7 (Resolved the journal twins)

Each of the 128 journal ids had two matching entries that differed by
one bit.i followed the masking and nonlinear feedback transformations
used by the program.

The chosen bits were packed into 16 bytes and constrained by the parity
checks in continuity_checks.i represented those checks as a GF(2)
system and solved them with XOR-based elimination. The system had full
rank, so it produced a unique solution.

I unmasked the solution to recover the correct journal twin for every
slot.

## Step 8 (Recovered the stamp leaves and route)

I traced stamp_restore, which used fragments.dat to solve eight
8-by-8 GF(2) systems and reconstruct the 16-byte leaves.

Then i inspected stamp_sequence, which decrypted eight chapters from
relay.cache.i placed a breakpoint at the chapter-tag comparison and
read the decrypted 16-byte value from the stack. Repeating this for each
chapter revealed the route:

``` text
14 0 13 15 9 6 12 7 5 2 8 4 11 1 3 10
```

I reordered the IDs using this route, derived K3, and decrypted
`seal.bin`. The result was a decoy audit receipt, so I continued to
stage 4.

``` text
SecLeaf{this_is_only_the_audit_receipt_keep_going}
```

## Step 9 (Prepared stage 4)

I moved to arbiter and libpolicy.so. The command expected a
1696-byte dossier beginning with the intact stage 3 witness.

The stage derived its ancestor hash and epoch from the witness and
evidence hashes:

``` text
ST1 = SHA256("V4/STAGE1" || w3 || H(release) || ... || H(libstamp))
epoch = u32(SHA256("V4/REAL/LANE" || ST1))
```

The epoch was `0xa8a713f6`.i retained the full stage 3 witness because
stage 4 depended on it.

## Step 10 (Solved the stage 4 recurrence)

Stage 4 mapped 48 values through a recurrence modulo 65521:

``` text
h0 = u0
h1 = u1
h2 = u1 * u0 + u2
hi = u(i-1) * u(i-2) + ui + u(i-3) (mod 65521)
```

I solved the 48-by-48 system for h, then inverted the recurrence to
recover u. I checked that the recovered values were within the allowed
range of 0 to 0xfff0.

## Step 11 (Recovered the stage 4 route data)

The library rebuilt 256 nodes with four slots per node using
palinode.bin and recovery.tape. The route was stored in
route4.cache and each branch depended on the previous value.

I used gdb to follow the librarys validation path and let the program
populate the expected values in memory.i captured the completed dossier
buffer before the library unloaded then saved it for validation.

## Step 12 (validate stage 4)

I ran the adjudication command against the completed dossier:

``` bash
./arbiter --adjudicate w4full.bin
```

The program accepted the dossier and printed this stage flag:

``` text
SecLeaf{m41nt41n3r_0f_n0n3_f0rg3d_th3_tru5t_ch41n_4c7f63ab}
```

Since the challenge had another stage, I continued rather than treating
this as the final answer.

## Step 13 (prepared stage 5)

I used conclave and libisa.so for the final stage. The command
expected a 2784-byte dossier that preserved the stage 4 data and
continued to pass policy_verify.

The program calculated the ancestor hash and epoch as follows:

``` text
ANC = SHA256("V5/ANCESTOR" || w4)
epoch = u32(SHA256("V5/AUDIT/LANE" || ANC))
```

The epoch was `0x1f381262`.

## Step 14 (solved the stage 5 recurrence)

Stage 5 used 64 values with a squared-term recurrence modulo 6552:

``` text
h0 = u0
h1 = u0^2 + u1
h2 = u1^2 + u2
hi = u(i-1)^2 + ui + u(i-3) (mod 65521)
```

I solved the 64-by-64 system for the intermediate sequence and inverted
the recurrence to recover the original values. I checked the recovered
sequence against the stage's range requirements.

## Step 15 (Identifying the correct RISC-V program)

The stage decrypted a bank from riscv.rom. i traced the selection
logic and checked the candidate programs final instruction. The
intended RV32I program ended with the ret instruction:

``` text
0x00008067
```

This helped me distinguish the correct bank from the decoys.

## Step 16 (Tracedd the custom virtual machine)

The interpreter implemented a small RV32I subset and three custom
rotate-XOR mixers. It processed 24 rounds with eight nodes per round.

For each node, the library built an MMIO window using a SHA-256-derived
value, morphed 12 custom opcodes, ran the VM, selected a slot, and
advanced the validation chain. I followed this execution path in GDB
instead of guessing the expected values.

## Step 17 (Recovered the final values)

I used breakpoints at the value check and checkpoint handling
instructions in `libisa.so`. At the value check, I captured the expected
node value and placed it into the corresponding dossier slot. At the
checkpoint, I copied the checkpoint value from the stack into the output
buffer.

I let the program process all rounds so that the 192 node values and 24
checkpoints were populated consistently with its own calculations. I
saved the completed dossier as w5full.bin.

## Step 18 (Final validation)

I ran the final attestation command with the completed dossier:

``` bash
./conclave --attest w5full.bin
```

The binary accepted the dossier and printed the final flag.

## Final Flag

``` text
SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}
```
