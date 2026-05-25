# Operator Silence — Writeup

**Category:** Hardware / Quantum
**Flag:** `HTB{sh0r_0rd3r_f0und_m0dul4r_p3r10d_r3c0v3r3d}`

---

## Going in

If you've never done a "quantum CTF" challenge before, the concepts:

- **Modular multiplicative order.** For a base `g` and modulus `N`, the smallest `r > 0` with `g^r ≡ 1 (mod N)` is the *order* of `g`. RSA security can be reduced to finding it.
- **Shor's order-finding algorithm.** A quantum algorithm that recovers `r` efficiently. The textbook recipe: prepare a uniform superposition on a "control" register, apply a controlled modular-exponentiation oracle (`|x⟩|y⟩ → |x⟩|y · g^x mod N⟩`), apply inverse QFT, measure.
- **What measurement gives you.** Each clean shot returns `m ≈ j · 2^n / r` for some random `j`. You don't get `r` directly; you get a *fraction* `m / 2^n` whose denominator (in lowest terms) is `r / gcd(j, r)`.
- **Continued fractions.** The standard way to recover that denominator from a measured `m`. Python's `fractions.Fraction(...).limit_denominator(...)` does it for you in one line.
- **The Quantum Zeno Effect** doesn't show up here. (Sister challenge — see ZenoLock.)

The challenge gives you an *oracle* that runs the order-finding circuit. You can submit a list of gates, get one measurement back per call. Budget: 16 circuit calls, 4 classical evaluations. Recover `r` and submit it.

---

## Public parameters

```
n_control                  = 512
n_target                   = 256
N_bits                     = 256                      # N and g are SECRET
shots_per_circuit          = 1
budget_circuits            = 16
budget_classical_evals     = 4
noise_probability          = 0.03
gate_vocabulary  = ["h", "x", "cx", "swap",
                    "controlled_modexp", "qft_inverse", "measure_all"]
notes            = "Little-endian bit order. Oracle: |x>|y> -> |x>|y * g^x mod N>.
                    /classical_eval returns only is_annihilator (g^x == 1)."
```

Four endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /params` | the params above |
| `POST /circuit` | submit gates, get one measurement |
| `POST /classical_eval` | boolean check: `g^x ≡ 1 (mod N)`? |
| `POST /verify` | submit `r`, get the flag |

`/classical_eval` is deliberately neutered — returns just a bit, so you can validate a candidate `r` without leaking smaller `r`'s, `g`, or `N`.

---

## The circuit

Textbook Shor:

```python
gates  = [{"op": "h", "qubit": i} for i in range(512)]    # uniform superposition
gates += [{"op": "x", "qubit": 512}]                      # |1> in target
gates += [{"op": "controlled_modexp"}]                    # oracle
gates += [{"op": "qft_inverse"}]
gates += [{"op": "measure_all"}]
```

The server's structural-validation errors are very helpful — and **don't cost budget** if the schema is wrong:

```
"circuit rejected: empty circuit"
"gate 0: h needs integer qubit"       ← field is 'qubit', not 'target'
"control register not in uniform superposition (H missing...)"
"no controlled_modexp applied"
"inverse QFT missing on control register"
"measure_all missing"
```

Iterate until everything validates. Then start spending shots.

---

## What I did wrong: convergent denominators looked like noise

With the circuit running, my first attempt produced random-looking denominators on every shot. Pairwise gcds were ~8 bits. That's the signature of essentially random bitstrings — *not* the "a few values, each repeated many times" pattern Shor's promises.

Two bugs:

### Bug 1 — `if k == 0: break` swallowed every shot

My first attempt at the continued-fractions recurrence:

```python
for h, k in convergents(m, denom):
    if k == 0 or k > max_r:
        break
    best = k
```

The first convergent (`a₀ = ⌊m / 2^512⌋ = 0`) has `k = 0`. The `break` exits immediately and `best` stays `None`. Fix: `continue` on `k == 0`.

### Bug 2 — I had `p` and `k` swapped

I was bounding the *numerator* of the convergent, not the *denominator*. The denominator is what carries the periodicity. Just use Python:

```python
fr = Fraction(m, 2**n_control).limit_denominator(2**n_target)
# fr.denominator is the candidate
```

Far less to get wrong.

---

## The signal, once the bugs were fixed

15 clean shots from a fresh session:

```
count= 6 bits=255  0x67ad0c672ed324f0...6c90       ← r
count= 2 bits=254  0x33d6863397699278...3648       ← r/2
count= 1 bits=253  0x19eb4319cbb4c93c...9b24       ← r/4
count= 1 bits=252  0xa5e1ad71...
count= 1 bits=252  0xcf5a18ce...
count= 1 bits=251  0x6e9673a1...
count= 1 bits=256  0xd2a98416...
count= 1 bits=256  0xfb3d1bb1...
count= 1 bits=250  0x228f0422...
```

The top three are exact halvings: `r`, `r/2`, `r/4`. That's the clean Shor signature — `j` was random across shots, and `gcd(j, r)` was 1, 2, 4 respectively.

The "one-off" denominators are mostly continued-fraction best-approximations that don't correspond to true Shor peaks. Once a peak resolves cleanly, `limit_denominator` will happily return a different rational on a different shot. **The only reliable signal is *clustering*.**

So `r = 0x67ad0c67...0c90` (255 bits).

---

## Confirming minimality (3 of 4 classical evals)

`g^r ≡ 1` is necessary; minimality is what `/verify` cares about. Three boolean checks:

| Probe | `is_annihilator` |
|---|---|
| `r` | **true** |
| `r / 2` | false |
| `r / 3` | false |
| `r / 5` | false |

Trial division gives `r = 2^4 · 3 · 5 · P` with `P` a 247-bit composite that isn't fully factorable in reasonable time. Knocking out 2, 3, 5 covers small primes; peeling `P` further would need ECM or another quantum factoring round. Good enough — submit `r` directly.

---

## Capture

```json
POST /verify  { "order": <r> }

{
  "status": "accepted",
  "flag": "HTB{sh0r_0rd3r_f0und_m0dul4r_p3r10d_r3c0v3r3d}",
  "next_stage": "white-horizon.htb:31338"
}
```

---

## Full solver

```python
import json, urllib.request
from fractions import Fraction
from collections import Counter

HOST   = "http://<host>:<port>"
SID    = "solver"
N_CTL  = 512
DENOM  = 1 << N_CTL
MAX_R  = 1 << 256

def post(path, payload):
    req = urllib.request.Request(
        HOST + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Session-Id": SID},
    )
    return json.loads(urllib.request.urlopen(req, timeout=180).read())

def shor_circuit():
    gates  = [{"op": "h", "qubit": i} for i in range(N_CTL)]
    gates += [{"op": "x", "qubit": N_CTL},
              {"op": "controlled_modexp"},
              {"op": "qft_inverse"},
              {"op": "measure_all"}]
    return {"gates": gates}

denoms = []
for _ in range(16):
    r = post("/circuit", shor_circuit())
    if r.get("noise_flag"):
        continue
    m = sum(int(b) << i for i, b in enumerate(r["shot"]))   # little-endian
    denoms.append(Fraction(m, DENOM).limit_denominator(MAX_R).denominator)

r = Counter(denoms).most_common(1)[0][0]

assert     post("/classical_eval", {"x": r       })["is_annihilator"]
assert not post("/classical_eval", {"x": r // 2 })["is_annihilator"]

print(post("/verify", {"order": r}))
```

---

## Lessons

- **Structural errors are free.** The server distinguishes structural rejection (no budget consumed) from execution. Use them to schema-discover for free; don't burn real circuit calls on schema mistakes.
- **Use `Fraction.limit_denominator`.** Right, one-liner, doesn't have the off-by-ones of hand-rolled continued-fraction state machines.
- **Cluster, don't LCM.** With random `j`, the *most common* convergent denominator is exactly `r`. LCM-ing every shot includes noise from CF best-approximations that aren't true Shor peaks and overshoots wildly.
- **Spend `/classical_eval` carefully.** Four bits is plenty to falsify `r/2`, `r/3`, `r/5` once the quantum stage hands you a candidate. Don't burn them on guesses.
