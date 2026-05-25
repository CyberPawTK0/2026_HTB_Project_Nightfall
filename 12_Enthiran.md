# Enthiran — Writeup

**Category:** Reversing (Insane)
**Flag:** `HTB{n3ur4l_r3v3rs3r_1337}`

---

## Going in

Things to be loosely familiar with before reading this:

- **ELF / x86-64 disassembly basics.** Reading objdump output, recognising calling conventions (SysV: `rdi, rsi, rdx, rcx, r8, r9`), spotting `endbr64` prologues.
- **`.rodata` layout.** Read-only data. Large `.rodata` is usually constants — strings, lookup tables, weights.
- **Neural network basics.** Matrix-multiply + bias + activation, repeated as layers. Activations like ReLU and sigmoid.
- **SplitMix64 / Murmur3 fmix64.** Two standard non-cryptographic mixing constructions. Their constants (`0x9e3779b97f4a7c15`, `0xff51afd7ed558ccd`, `0xbf58476d1ce4e5b9`) are recognisable on sight if you've seen them once.
- **`cvttsd2si`.** "Convert with truncation, scalar double to signed integer." This is what `int(x)` ends up as in floating-point assembly.

The challenge: a binary that claims to be a diagnostic tool, runs a real neural network embedded in `.rodata`, but the flag isn't actually computed from the network output. There's a *dead function* nobody ever calls that builds the flag from any 8 doubles you give it. The puzzle is finding the right 8 doubles.

---

## 1. First look

```
$ file enthiran
ELF 64-bit LSB pie executable, x86-64, ..., dynamically linked, ..., stripped

$ ./enthiran
Enthiran System Diagnostics v1.0
=================================

System: Linux 6.6.15-amd64 (x86_64)
CPUs:   4
RAM:    1968 MB
Uptime: 1245 seconds

[*] Running environment diagnostics...
  [+] Checking memory subsystem... OK
  ...

[*] Environment evaluation: score=0.992042
[*] Diagnostic profile:
    channel[0] = 1.3078755885
    ...
    channel[7] = 2.1054133037
```

Run it twice and the numbers shift slightly — the model is fed real environmental data.

Useful imports: `sin, exp, log2, fmod` (math), `sysconf, uname` (system info), `fopen, fgets, fscanf` (/proc), `clock_gettime` (timing), `__printf_chk, puts`.

Section sizes:

```
.text   0x1320 - 0x233c   ~4 KB code
.rodata 0x3000 - 0x4dd0   ~7.6 KB constants ← model lives here
```

7.6 KB of read-only data on a diagnostic tool is enormous. That's the embedded network plus encrypted blobs.

---

## 2. Mapping `.rodata`

```
0x3000 - 0x32a0   format strings, /proc paths, banner
0x32a0 - 0x3300   XOR-encoded strings + 17-byte encrypted blob + padding
0x3308            magic: deadbeef cafebabe
0x3310            single double (5.4111...)        ← L3 bias
0x3320 - 0x3360   8 doubles                        ← L3 weights
0x3360 - 0x33a0   8 doubles                        ← L2 bias
0x33a0 - 0x3ba0   256 doubles (32x8)               ← L2 weights
0x3ba0 - 0x3ca0   32 doubles                       ← L1 bias
0x3ca0 - 0x4ca0   512 doubles (16x32)              ← L1 weights
0x4ca0 - 0x4dd0   misc scalar constants
```

Identified by reading `main` and watching which addresses get passed as `bias`/`weights` to the matmul helper.

### XOR-encoded path strings

At `0x3004` there's a 4-byte key `a4 a4 a4 a4`. At `0x32d8`, `0x32e8`, `0x32f8` are three 16-byte blocks each starting `8b d4 d6 cb c7 8b`. XOR them against `0xa4a4a4a4`:

```
0x32d8 → "/proc/cpuinfo"
0x32e8 → "/proc/stat"
0x32f8 → "/proc/meminfo"
```

Why obfuscate these? Because `strings` on the binary would otherwise make the diagnostic theme obvious. The obfuscation hides the *real* nature of the binary just enough to look like a sandbox-evasion sample. (It isn't. It's decoration.)

### The 17-byte encrypted blob

At `0x32c0`, exactly 17 bytes then padding:

```
0x32c0: 33 d5 f5 55 07 f8 45 17 d0 7e 23 27 4e 3c 79 ef 78
0x32d1: 00 00 00 00 00 00 00
```

Remember these — they're `flag[8..24]`.

---

## 3. The matmul helper at `0x1ed0`

Clean reusable layer. Calling convention:

| reg | meaning |
|---|---|
| `rdi` | input vector pointer |
| `rsi` | input dimension |
| `rdx` | weight matrix pointer |
| `rcx` | bias vector pointer |
| `r8` | output buffer pointer |
| `r9d` | output dimension |
| `(rsp)` | ReLU flag (1 = clip) |

Inner loop: for each output index `j`, start `rcx = rdx` (current column pointer) and `rax = r10` (current input pointer). Inner step: `rax += 8`, `rcx += rdi` (with `rdi = out_dim*8`). So input goes one element forward, weights go `out_dim` doubles forward → layout is **row-major**, `W[i, j]` at `&W[0] + (i*out_dim + j)*8`.

```python
def matmul(x, W, B, in_dim, out_dim, relu):
    y = []
    for j in range(out_dim):
        s = B[j]
        for i in range(in_dim):
            s += x[i] * W[i*out_dim + j]
        if relu and s <= 0: s = 0
        y.append(s)
    return y
```

---

## 4. `main()` in three layers

The three matmul call sites:

```
0x19f4: L1 — in=16, out=32, ReLU=1, B=0x3ba0, W=0x3ca0
0x1bde: L2 — in=32, out=8,  ReLU=1, B=0x3360, W=0x33a0
0x1c0d: L3 — in=8,  out=1,  ReLU=0, B=0x3310, W=0x3320
```

Architecturally: **16 → 32 (ReLU) → 8 (ReLU) → 1 (linear) → sigmoid**.

The final scalar goes through `xorpd` with `-0.0` (sign flip) and `exp@plt`, then `1.0/(1.0+exp(-z))` — standard sigmoid. That's the `score=` value.

The 8-value L2 output is what gets printed as `channel[0..7]`.

### Building the 16-dim input

Before L1, 16 doubles are written to `rsp+0xd0..0x150`:

| slot | source |
|---|---|
| 0 | `min(1.0, 1.0 - MemAvailable/MemTotal)` |
| 1 | `sysconf(_SC_NPROCESSORS_ONLN) * 1/65536` |
| 2 | Shannon entropy of 64 bytes from `/dev/urandom`, scaled |
| 3 | `uptime / 2_592_000` (30 days) |
| 4 | `uptime % 1` |
| 5 | latency of a 500k-iteration loop, scaled |
| 6 | `processes_running / 5000` from `/proc/stat` |
| 7 | first field of `/proc/loadavg` |
| 8 | derived from process count |
| 9 | constant `0.72` |
| 10 | `PHYS_PAGES * PAGE_SIZE / 2^36` |
| 11 | constant `0.41` |
| 12 | constant `0.85` |
| 13 | constant `0.33` |
| 14 | constant `0.91` |
| 15 | constant `0.23` |

Then a normalization loop at `0x18d0` updates the first 9 in place:

```
x[i] = x[i] * 0.65 + NORM[i] * 0.35    for i in 0..8
NORM = [0.61, 0.55, 0.78, 0.29, 0.44, 0.67, 0.52, 0.38, 0.66]
```

### The fake sinusoidal activation

Between L1 and L2 the binary does this dance:

1. Copy L1's 32-double output from `rsp+0x150` to `rsp+0x250`.
2. Apply `z[i] = sin(pi * y[i]) * 0.5 + 0.5` *in place* at `rsp+0x250`.
3. Compute `sum = Σ z[i] * (i*0.12345 + 0.001) * 0.01 - 2.5` and compare to `-709.0` (the exp underflow threshold).
4. If `sum >= -709`, fall through. Otherwise call `exp@plt`.
5. **Discard the result.** Next instruction is `mov %rbp, %r8` — `xmm0` isn't preserved past a `call`. The exp value never leaves the function.

Then L2 is called with `r12` (`rsp+0x150`, the *original* L1 output) as input — **not** the sin-transformed copy. The whole sin/sum/exp block is a red herring designed to seduce you into believing this is a SIREN-style network. I confirmed in GDB: breakpoint at `0x1bde`, read the buffer L2 consumes, it equals L1's unmodified output exactly.

After L2 writes its 8 outputs over the sin buffer, four `movaps` copy them to a different stack slot (`rsp+0x90`) which is what the print loop reads. More movement for no reason.

### Why the model can't be the flag generator on its own

- Inputs depend on `/dev/urandom`, uptime, loadavg, latency — channels fluctuate run-to-run.
- In my environment `channel[3] = 0` (ReLU clipped a negative). But the flag begins `HTB{`, requiring channel[3] to encode `{` — impossible if it's zero.

So the model output is *not* the flag. Either the flag is encoded elsewhere, or I'm missing a code path.

---

## 5. The dead function at `0x2210`

`objdump` shows a complete function at `0x2210` with an `endbr64` prologue, but `grep` finds **no `call` reaching it** and no relocations referencing it either:

```python
import struct
d = open('enthiran','rb').read()
target = struct.pack('<Q', 0x2210)
print(any(d[i:i+8] == target for i in range(len(d)-7)))
# False
```

Dead code. But obviously a flag generator. Walking it:

```
0x2210: endbr64
0x2214: sub  $0x28, %rsp
0x2218: movsd 0x4cb8(%rip), %xmm1   ; xmm1 = 256.0
0x2220: mov  %rsi, %rcx              ; save output ptr
0x2223: lea  0x3308(%rip), %rsi      ; rsi = "deadbeef cafebabe" magic
```

Then three loops + a final XOR loop.

### Loop 1 — first 8 flag bytes

```
0x2240: movsd     (%rdi, %rax, 8), %xmm0   ; xmm0 = c[i]
0x2245: mulsd     %xmm1, %xmm0             ; xmm0 *= 256.0
0x2249: cvttsd2si %xmm0, %edx              ; edx = (int32)trunc(xmm0)
0x224d: xor       (%rsi, %rax, 1), %dl
0x2250: mov       %dl, (%rcx, %rax, 1)     ; out[i] = dl
0x2253: add $1, %rax ; cmp $8, %rax ; jne
```

So:

```
out[i] = (int(c[i]*256) & 0xff) XOR magic[i]
magic  = de ad be ef ca fe ba be
```

### Loop 2 — hashing the 8 doubles into a 64-bit seed

```
rax = 0x736f6d6570736575          ; "somepseu" — initial state
R8  = 0x9e3779b97f4a7c15          ; golden-ratio prime
RSI = 0xff51afd7ed558ccd          ; Murmur3 fmix64 constant

for i in 0..7:
    u   = *(uint64*)&c[i]         ; raw bit pattern of double i
    rax ^= u
    rdx  = rax
    rax  = rax * R8
    rdx  = rol(rdx, 17)
    rdx ^= rax
    rdx  = rol(rdx, 31)
    rax  = (rdx >> 33) * RSI
    rax ^= rdx
```

Custom mix using pieces of SplitMix64 and Murmur3 fmix64.

### Loop 3 — generating 17 PRNG bytes

```
R10 = 0x6c62272e07bb0142
R9  = 0x32849a0e836b1562
R11 = 0xbf58476d1ce4e5b9          ; SplitMix64 mix constant

rdx = 0
loop:
    rax ^= rdx
    rdx  = rdx + R10
    rax  = rol(rax, 13) * R11
    rax ^= rax >> 31
    *out++ = rax & 0xff
    cmp rdx, R9
    jne loop
```

`jne rdx, R9` looks scary — `R10` is even, so the orbit could in principle take `2^63` steps. But:

```
17 * R10 mod 2^64 = 17 * 0x6c62272e07bb0142 mod 2^64
                  = 0x32849a0e836b1562 = R9
```

Exactly 17 iterations. The author tuned `R9` so the loop produces precisely 17 bytes. Sneaky.

### Loop 4 — XOR with the encrypted blob

```
0x22fe: lea 0x32c0(%rip), %rsi          ; encrypted blob
for i in 0..16:
    out[8+i] = enc[i] ^ prng_bytes[i]
0x231d: movb $0, 0x19(%rcx)              ; null terminator at out[25]
```

So the function builds 25 ASCII bytes + null in the caller's buffer from any 8 doubles you point `rdi` at. **This is the flag generator.** It just needs the right input.

### Why all the obfuscation?

A typical reverser sees a learned model + custom hash + custom PRNG and spends days trying to invert the network or attack the hash. The actual solution requires:

1. Recognising the dead function exists despite never being called.
2. Recognising the 8 doubles can be *any* 8 doubles (the network is irrelevant).
3. Picking a sensible parameterisation and brute-forcing the unknowns.

---

## 6. Finding the 8 doubles

The function takes any 8 doubles. We need the 8 *the author chose*. There are no obvious "magic" 8-double blocks in the binary (I tried every 1-byte-aligned 8-double window). The author must have picked them by hand.

### Constraints from the flag format

The flag must start with `HTB{`, so loop 1 forces:

```
int(c[0]*256) & 0xff = 'H' ^ 0xde = 0x96   (150)
int(c[1]*256) & 0xff = 'T' ^ 0xad = 0xf9   (249)
int(c[2]*256) & 0xff = 'B' ^ 0xbe = 0xfc   (252)
int(c[3]*256) & 0xff = '{' ^ 0xef = 0x94   (148)
```

For each constraint there's an infinite family: `c[i] = (b[i] + 256·k) / 256` for any non-negative integer `k`.

### The "simple fraction" hypothesis

Doubles in `[0, 1)` of the form `b/256` (`k = 0`) are **exact** in IEEE 754 — the denominator is a power of two. The author probably picked these for a clean construction. So guess:

```
c[i] = byte[i] / 256.0
byte[0..3] = 0x96, 0xf9, 0xfc, 0x94    (forced)
byte[4..7] = ?, ?, ?, ?                (4 unknown bytes)
```

`byte[4..7]` are further constrained — `flag[i] = byte[i] ^ magic[i]` must be printable ASCII — that's 95 acceptable values per byte, ~81 million combinations total.

For each candidate, hash the 8 doubles, run the PRNG 17 times, XOR with the blob, accept if the resulting 17 bytes are all printable. A random hash producing 17 printable bytes has probability `~0.37^17 ≈ 1e-7`, so we expect a handful of survivors and likely one English-shaped result.

### Brute-force in C

```c
// gcc -O3 -o brute brute.c

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint8_t enc[17]   = {0x33,0xd5,0xf5,0x55,0x07,0xf8,0x45,0x17,
                            0xd0,0x7e,0x23,0x27,0x4e,0x3c,0x79,0xef,0x78};
static uint8_t magic[8]  = {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe};

static inline uint64_t rol(uint64_t x, int n){return (x<<n)|(x>>(64-n));}

static uint64_t hash_doubles(double *c) {
    uint64_t rax = 0x736f6d6570736575ULL;
    const uint64_t R8 = 0x9e3779b97f4a7c15ULL, RSI = 0xff51afd7ed558ccdULL;
    for (int i = 0; i < 8; i++) {
        uint64_t u; memcpy(&u, &c[i], 8);
        rax ^= u;
        uint64_t rdx = rax;
        rax  *= R8;
        rdx  = rol(rdx, 17);
        rdx ^= rax;
        rdx  = rol(rdx, 31);
        rax  = (rdx >> 33) * RSI;
        rax ^= rdx;
    }
    return rax;
}

static int decode(uint64_t h, uint8_t *out) {
    const uint64_t R11 = 0xbf58476d1ce4e5b9ULL, R10 = 0x6c62272e07bb0142ULL;
    uint64_t rdx = 0, rax = h; int ok = 1;
    for (int i = 0; i < 17; i++) {
        rax ^= rdx; rdx += R10;
        rax  = rol(rax, 13) * R11;
        rax ^= rax >> 31;
        uint8_t b = (uint8_t)(rax & 0xff) ^ enc[i];
        out[i] = b;
        if (!((b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a)) ok = 0;
    }
    return ok;
}

int main(void) {
    int need[4] = {0x96, 0xf9, 0xfc, 0x94};
    for (int b4 = 0; b4 < 256; b4++) {
        uint8_t f4 = b4 ^ magic[4]; if (f4<0x20||f4>0x7e) continue;
    for (int b5 = 0; b5 < 256; b5++) {
        uint8_t f5 = b5 ^ magic[5]; if (f5<0x20||f5>0x7e) continue;
    for (int b6 = 0; b6 < 256; b6++) {
        uint8_t f6 = b6 ^ magic[6]; if (f6<0x20||f6>0x7e) continue;
    for (int b7 = 0; b7 < 256; b7++) {
        uint8_t f7 = b7 ^ magic[7]; if (f7<0x20||f7>0x7e) continue;
        double c[8] = {
            need[0]/256.0, need[1]/256.0, need[2]/256.0, need[3]/256.0,
            b4/256.0,      b5/256.0,      b6/256.0,      b7/256.0,
        };
        uint8_t tail[17];
        if (decode(hash_doubles(c), tail)) {
            printf("HTB{%c%c%c%c%.17s\n", f4, f5, f6, f7, tail);
        }
    }}}}
}
```

A few seconds in:

```
HTB{n3ur4l_r3v3rs3r_1337}
```

`bytes[4..7] = 0xa4, 0xcd, 0xcf, 0xcc` decode against the magic to `n, 3, u, r` at positions 4..7. The rest comes from the hash → PRNG → XOR chain.

### Verification in Python

```python
import struct
M = (1 << 64) - 1
def rol(x, n): n &= 63; return ((x << n) | (x >> (64 - n))) & M

enc   = bytes.fromhex('33d5f55507f84517d07e23274e3c79ef78')
magic = bytes.fromhex('deadbeefcafebabe')
c = [b/256.0 for b in (0x96,0xf9,0xfc,0x94,0xa4,0xcd,0xcf,0xcc)]

out = bytearray(25)
for i in range(8):
    out[i] = (int(c[i]*256) ^ magic[i]) & 0xff

rax = 0x736f6d6570736575
for i in range(8):
    u = struct.unpack('<Q', struct.pack('<d', c[i]))[0]
    rax ^= u
    rdx  = rax
    rax  = (rax * 0x9e3779b97f4a7c15) & M
    rdx  = rol(rdx, 17)
    rdx ^= rax
    rdx  = rol(rdx, 31)
    rax  = ((rdx >> 33) * 0xff51afd7ed558ccd) & M
    rax ^= rdx

rdx = 0
for i in range(17):
    rax ^= rdx
    rdx  = (rdx + 0x6c62272e07bb0142) & M
    rax  = rol(rax, 13)
    rax  = (rax * 0xbf58476d1ce4e5b9) & M
    rax ^= rax >> 31
    out[8+i] = enc[i] ^ (rax & 0xff)

print(out.decode())   # HTB{n3ur4l_r3v3rs3r_1337}
```

The 8 doubles:

```
0.5859375, 0.97265625, 0.984375, 0.578125,
0.640625,  0.80078125, 0.80859375, 0.796875
```

All exact dyadic fractions in `[0, 1)`. Intermediate hash: `0x9ae5bdb66739af4d`.

---

## 7. What the author actually did

Reconstructing from the author's side:

1. Choose flag `HTB{n3ur4l_r3v3rs3r_1337}` (25 bytes).
2. Pick 8 doubles `c[i] = (flag[i] ^ magic[i]) / 256`. That fixes loop 1.
3. Run the custom hash → seed `0x9ae5bdb66739af4d`.
4. Run the PRNG 17 times → 17 stream bytes.
5. XOR with `flag[8..24]` to get the encrypted blob, write at `0x32c0`.
6. Train (or arbitrarily fill) the 16→32→8→1 network so output channels look plausible. The network's output is never used for anything that matters; it keeps the reverser busy.
7. Drop the flag-decoding routine into the binary as orphaned code so it stays in `.text` after linking.

The "mathematics of internal representations" line in the description is itself misdirection — it points at the model, when what mattered was a straightforward stream cipher whose seed came from a custom hash.

---

## 8. Things that took time and could have saved it

- **L2 sees raw L1 output, not the sin-transformed copy.** The sin block *looks* like a non-linearity but operates on a separate buffer and discards its result. Catching this by reading the assembly literally (or breaking in GDB) saved hours of trying to invert a SIREN-style network. The print loop reading from `rsp+0x90` while L2 wrote to `rsp+0x250` was also a rabbit hole — values get copied between them via four `movaps` in the score-printing setup. Easy to miss.
- **The "model is irrelevant" jump.** The function at `0x2210` is the entire payload. As soon as you see `cvttsd2si` + XOR-with-magic + custom hash + byte-stream XOR with `.rodata`, you know there is no neural network in the critical path. Spend your time on `0x2210`, not on the network.
- **`c[i] = b[i]/256` is the right ansatz.** Once you accept the 8 doubles can be anything, the question is what the author would pick. Exact power-of-two fractions in `[0, 1)` are the obvious choice; brute force takes seconds. Doubting that and trying to invert the model wastes hours.
- **The loop terminator at `0x22fa` (`jne rdx, R9`) is exactly 17 iterations.** Easy to mis-read as potentially infinite. `17 * R10 ≡ R9 (mod 2^64)` — always verify rather than panicking.

---

## Lessons

- **Stripped doesn't mean opaque.** A function at a fixed address with no call sites and no relocations is dead code — but if it's a flag generator, it's *the* code that matters. Always check whether `.text` contains unreferenced functions.
- **A real-looking neural network can be decoration.** Don't get hypnotised. Verify what the network's output is actually used for; if the answer is "printed and discarded", it isn't the flag.
- **Recognise the constants.** `0x9e3779b97f4a7c15`, `0xff51afd7ed558ccd`, `0xbf58476d1ce4e5b9` are SplitMix / Murmur fmix64 constants on sight. Knowing the family lets you reimplement the hash without reverse-engineering it bit by bit.
- **Pick the simplest parameterisation the author would have used.** When a brute force could be `2^128`, ask what *constraints* the author would have wanted (clean dyadic fractions, etc.) to make the construction tidy on their end. Those constraints usually shrink the search to seconds.
