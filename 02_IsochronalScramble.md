# Isochronal Scramble — Writeup

**Category:** Crypto (isogeny-based)
**Flag:** `HTB{0n_y0ur_w4y_t0_b3c0m3_4_CGL_h4sh_cr4ck3r_479e8935dc4502ed326b6296492d116c}`

---

## Going in

Things to have a passing familiarity with before tackling this:

- **Elliptic curves over a finite field** — equations like `y² = x³ + ax + b` with arithmetic mod some prime power.
- **Supersingular curves** — a special subclass with extra structure that isogeny-based crypto depends on. The challenge will reject any non-supersingular curve.
- **2-isogenies** — degree-2 maps from one curve to another. At a high level: a curve has 3 points of order 2, each one defines a 2-isogeny "out" of that curve to a new curve. So at each step you have three choices, and walking through them traces a path in a graph.
- **CGL hash** — Charles–Goren–Lauter hash. You start at curve `E0`, and use the bits of your input to choose left/right at each step of a 2-isogeny walk (the third direction is "back where you came from", so excluded). After many steps the final j-invariant becomes your hash output.
- **Continued fractions / convergent denominators** — don't matter here.

The challenge: find a *fixed point* of the CGL hash. `data` is a 64-character SHA-256 digest, the curve we start at is also user-controlled. We need `CGL_hash(E0, data) == data`.

---

## The server in one screen

```python
p = 2^49 * 3^36 - 1
K = GF(p^2)               # quadratic extension; element = a + b*x with x^2 = -1

# 1. You provide a4, a6
E0 = y^2 = x^3 + a4*x + a6 over K
assert E0.is_supersingular()

# 2. You provide data (64 hex chars = 256 bits, but treated as 512 bits via bytes)
bits = data_to_bits(data)
h = sha256(str(j(walk(E0, bits)))).hexdigest()

# 3. Win if h == data
```

Each step of `walk` uses one bit to pick which 2-isogeny to take. After 511 steps, hash the j-invariant of the final curve.

---

## The plan: walk *backward*

We can't easily invert SHA-256, so we can't pick the final j and read off the data. But we *can*:

1. Pick a target j-invariant we want to end up on (any one — `j = 1728` is convenient since `str(1728)` is short).
2. Compute `data = sha256(str(1728)).hexdigest()`. This freezes the 512 bits used in the walk.
3. Find a final state `(A_511, α_511)` whose curve has `j = 1728`.
4. Walk backward 511 steps, using `bits[511..1]` to disambiguate which predecessor to pick at each step.
5. Recover `(A_0, α_0)` and build `E0` so `α_0` is one of its 2-torsion x-coordinates.

If step 5 succeeds, hand the server `(a4, a6, data)` and win.

---

## The walk in detail

The server's `next_curve(A, α, b)` is:

```python
ξ  = α^2
ζ  = 3ξ + A
η  = deterministic_sqrt(ζ)         # min of the two square roots
A' = -(4A + 15ξ)
λ0, λ1 = α + 2η, α − 2η
α' = max(λ0, λ1) if b else min(λ0, λ1)
```

State is `(A, α)`: `A` is the current curve's coefficient, `α` is the x-coordinate of the 2-torsion point we're about to use as the kernel. The bit picks between the two predecessors of "back where we came from".

### Inverting one step

Given `(A_new, α_new, b)`, find `(A_old, α_old)`. From the algebra:

- `A_old = -(A_new + 15·α_old²) / 4`
- `(α_new − α_old)² = -(3·α_old² + A_new)`

Expand the second one: `4α_old² − 2·α_new·α_old + (α_new² + A_new) = 0`. Two roots ⇒ two candidate `α_old` values per step. Then check the bit-consistency:

- `b = 1` (`α_new` was max) ⇔ `α_old ≤ α_new`
- `b = 0` (`α_new` was min) ⇔ `α_old ≥ α_new`

Typically one or both candidates survive, so the backward search is a DFS with branching factor ≤ 2.

### The field-ordering trap

`deterministic_sqrt` and `select(... max/min ...)` need a total order on `GF(p²)`. Sage delegates to PARI's `cmp_universal`, which compares polynomial elements as **(degree, constant coefficient, linear coefficient)** — low-to-high. I burned hours self-consistent with the wrong ordering before catching this:

```python
def fp2_lift(c):
    a, b = c                          # c = a + b·x
    return (0 if b == 0 else 1, a, b)
```

Using anything else produces a backward walk that's internally consistent but doesn't match the server.

---

## Why the naive attempt fails

I started with `E_target: y² = x³ + x` (which has `j = 1728`), set `data = sha256("1728")`, and computed the three candidate `α_511` values from the cubic `8α³ + 2aα − b = 0`. **All three dead-end within a few backward steps** — either the discriminant isn't a quadratic residue, or both candidate predecessors fail the bit check.

The diagnosis: my chosen `(A_511, α_511)` has to be *forward-reachable* under these specific 512 bits from *some* valid `E_0`. The cubic-derived points aren't on that "manifold".

### The trick

Every twist `y² = x³ + a·x` has `j = 1728` for any non-zero `a`. So `str(j) = "1728"` and `data` is identical no matter which twist we pick — but different twists give different `(A_511, α_511)` pairs in state space. So just iterate over twists until one of them lands on the forward manifold.

---

## The solver

```python
data = sha256(b"1728").hexdigest()
bits = data_to_bits(data)

for a in candidate_twist_coefficients:
    for α_final in {(0,0)} ∪ sqrt(-a/4):
        A_final = -(a + 15·α_final^2)/4
        # DFS backward 511 steps using bits[511..1]
        result = dfs(511, A_final, α_final, budget=30_000)
        if result:
            A_0, α_0 = result
            a4 = A_0
            a6 = -(α_0^3 + a4·α_0)      # force α_0 to be on the curve as a 2-torsion x
            if select0_consistent_with(bits[0]):
                return (a4, a6, data)
```

Around the 90th random twist, DFS completes in ~14,000 calls. The winning artifact:

```
a4.0 = 78046431927334142069260442469775
a4.1 = 84170066960439874584816946497153
a6.0 = 29483658934234237538656280683214
a6.1 = 79742992703806008280553119797422
data = a0bd94956b9f42cde97b95b10ad65bbaf2a8d87142caf819e4c099ed75126d72
```

Pipe into the server:

```
[AUTH GRANTED] Identity confirmed. Welcome, operator.
HTB{0n_y0ur_w4y_t0_b3c0m3_4_CGL_h4sh_cr4ck3r_479e8935dc4502ed326b6296492d116c}
```

---

## Lessons

- **Fixed-point construction:** pick `j_target`, compute `data = sha256(str(j_target))`, walk backward. This is the meta-pattern for any "hash that loops through a deterministic state machine" challenge.
- **Inverting one step is usually a quadratic.** The bit picks one of two predecessors.
- **Match the server's ordering exactly.** PARI uses `cmp_universal` (degree, then constants low-to-high). Sage inherits it. Get this wrong and you'll debug for days while your local simulator says everything works.
- **Twists are free.** When the same target j-invariant has many curves giving it, iterate them — they're different state-space points and you only need one to land on the forward manifold.
- **You don't need Sage.** A 100-line pure-Python `GF(p²)` implementation is enough for this whole challenge.
