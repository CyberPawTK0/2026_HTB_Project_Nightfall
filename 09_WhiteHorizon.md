# White Horizon — Writeup

**Category:** Hardware / Quantum
**Flag:** `HTB{sh0r_dl0g_f0rg3d_c0mm4nd_45_s3c0nd_w1nd0w}`

---

## Going in

This is the sequel to *Operator Silence*. Same hardware, different math:

- **Discrete log problem (DLOG).** Given a generator `g`, a prime `p`, and `y = g^x mod p`, recover `x`. Classically hard; quantumly easy (with caveats).
- **Shor's algorithm for DLOG.** Same idea as order-finding, but with *two* control registers. The oracle is `|a⟩|b⟩|z⟩ → |a⟩|b⟩|z · g^a · y^b mod p⟩`. After inverse QFT and measurement, you get `(c_a, c_b)` and have to solve a modular equation for `x`.
- **The pesky relation.** Depending on how the simulator implements it, `(c_a, c_b, x)` satisfy one of four sign/side variants like `c_b ≡ x · c_a (mod 2^N)` or `c_a + x · c_b ≡ 0 (mod 2^N)`. Three textbooks will give you three different conventions. **You must verify which one this simulator uses.**
- **Modular inverse.** `pow(a, -1, m)` in Python 3.8+ gives `a^(-1) mod m`. Works when `gcd(a, m) = 1`.
- **Continued fractions / quantisation tests.** If `c_a` is sampled near `k · 2^N / q` for some `q`, then `(c_a · q) mod 2^N` is tiny — a diagnostic for the "ideal Shor peak" distribution.

The challenge: recover the signing key `x` from the public `(p, g, y)` and forge a `FIRMWARE_DEPLOY` packet before the nonce rotates (45 seconds).

---

## Public parameters

```
p                          (1024-bit safe prime, p = 2q + 1)
g                          = 2
y                          = g^x mod p              # signing key target
subgroup_order             = q  (1023-bit prime)
n_control_a                = 1024
n_control_b                = 1024
budget_circuits            = 8
attempts_budget            = 3
session_window_s           = 45
nonce_rotation_s           = 45
gate_vocabulary            = [..., "controlled_modexp", "qft_inverse", ...]
command_allowlist          = ["FIRMWARE_DEPLOY", "PLAN_REVISION", "HEARTBEAT_ACK"]
notes = "Two control registers A and B.  Shared target register.
         Oracle: |a>|b>|z> -> |a>|b>|z * g^a * y^b mod p>.
         Measurement is little-endian.  gcd(c_b, 2^n_b) must be 1
         for a single-shot recovery."
```

Two layers of time-state:

- `session_window_s = 45` — the session itself.
- `nonce_rotation_s = 45` — the nonce regenerates on top; `/forge` must echo the *current* nonce.

Clean attack: collect one good shot, recover `x`, hit `/forge` inside the same nonce window. ~9 seconds of slack.

---

## The circuit

Generalising the Part-I gate schema once you spot the two new fields (`base ∈ {"g","y"}`, `register ∈ {"A","B"}`):

```python
gates  = [{"op": "h", "qubit": i} for i in range(N_A + N_B)]
gates += [{"op": "x", "qubit": N_A + N_B}]
gates += [{"op": "controlled_modexp", "base": "g", "register": "A"}]
gates += [{"op": "controlled_modexp", "base": "y", "register": "B"}]
gates += [{"op": "qft_inverse", "register": "A"}]
gates += [{"op": "qft_inverse", "register": "B"}]
gates += [{"op": "measure_all"}]
```

Use `/dry_run` to fuzz the schema — validation errors are free:

```
"controlled_modexp base must be 'g' or 'y'"
"controlled_modexp register must be 'A' or 'B'"
"qft_inverse register must be 'A' or 'B'"
```

After both `qft_inverse` calls and `measure_all`, the server returns `(c_a, c_b)` as two 1024-bit integers.

---

## The trap: which way does the modular relation point?

The hint *"gcd(c_b, 2^n_b) must be 1 for a single-shot recovery"* says the formula needs `c_b^(-1) mod 2^N` to exist — `c_b` must be odd. The obvious candidates are:

```
x ≡  c_a · c_b^(-1)   (mod 2^N)
x ≡ -c_a · c_b^(-1)   (mod 2^N)   ← turns out to be the right one here
x ≡  c_b · c_a^(-1)   (mod 2^N)
... etc.
```

The textbook derivation for `|a⟩|b⟩|z⟩ → |a⟩|b⟩|z · g^a · y^b⟩` gives `c_b ≡ x · c_a (mod 2^N)`, i.e. `x ≡ c_b · c_a^(-1) (mod 2^N)`. That derivation **does not match this simulator.** I burned an entire session testing it and every variant under the sun before catching the actual relation through diagnostics.

### Diagnostic 1 — parity correlation

Across 8 clean shots, `c_a` and `c_b` always had the *same parity*. Two implications:

1. `x` is odd (or the relation has `+c_a` unsigned somewhere).
2. The relation is `α·c_a + β·c_b ≡ 0 (mod 2^N)` with `α, β` odd (so parity adds consistently).

### Diagnostic 2 — rounding signature

If the simulator was sampling from the *ideal* Shor DLOG peak distribution, `c_a` would be quantised near `k · 2^N / q`, and `(c_a · q) mod 2^N` would be tiny. On the actual data it was uniform in `[0, 2^N)`. So `c_a` is **not on the quantised grid** — the simulator is using an exact algebraic relation, not a continued-fraction approximation.

Combined: the simulator computes `c_a` and `c_b` to satisfy an exact modular identity mod `2^N`. Brute-forcing over sign and side, the identity is:

```
c_a + x · c_b ≡ 0  (mod 2^N)
```

i.e. `x ≡ −c_a · c_b^(-1) (mod 2^N)`, reduced into `[0, q)`.

---

## Recovery formula

```python
N    = 1024
MOD  = 1 << N

assert c_b & 1 == 1                       # gcd(c_b, 2^N) = 1
v = (c_a * pow(c_b, -1, MOD)) % MOD       # v = c_a · c_b^(-1)  mod 2^N
x = (MOD - v) % q                         # x = -v mod q (because x < q)

assert pow(g, x, p) == y                  # sanity-check before /forge
```

Half of clean shots have `c_b` odd. With a budget of 8 circuits and 3% noise, at least one usable shot is essentially guaranteed. On my run all three `c_b`-odd shots gave the *same* `x` (no noise in the recovery step once the formula is right).

---

## Forging

```python
POST /forge
{
  "x":       <recovered x as decimal>,
  "command": "FIRMWARE_DEPLOY",
  "payload": "GLASSWING_PIVOT_COMPLETE",
  "nonce":   "<nonce_ack from the most recent /circuit, still inside its window>"
}
```

The server checks:

1. `command ∈ allowlist`
2. `0 < x < q`
3. `g^x ≡ y (mod p)` — the real gate
4. The submitted nonce matches the current `s.nonce` (HMAC-compared, so stale nonces 409 without burning an attempt).

Response:

```json
{
  "status":  "accepted",
  "flag":    "HTB{sh0r_dl0g_f0rg3d_c0mm4nd_45_s3c0nd_w1nd0w}",
  ...
}
```

---

## Full solver

```python
import json, time, urllib.request

HOST = "http://<host>:<port>"
N_A  = N_B = 1024
MOD  = 1 << N_A

def post(path, payload, token=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["X-Session-Token"] = token
    req = urllib.request.Request(
        HOST + path, data=json.dumps(payload).encode(), headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=120).read())

def get(path, token=None):
    headers = {"X-Session-Token": token} if token else {}
    req = urllib.request.Request(HOST + path, headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=60).read())

# Bootstrap + auth
boot = post("/bootstrap", {})
time.sleep(12)                              # /auth rate-limit
auth = post("/auth", {"seed": boot["seed"],
                      "handshake": boot["part_two_handshake"]})
tok  = auth["session_token"]

params = get("/params", tok)
p, g, y, q = (int(params["p"]), params["g"],
              int(params["y"]), int(params["subgroup_order"]))

def shor_dlog_circuit():
    gates  = [{"op": "h", "qubit": i} for i in range(N_A + N_B)]
    gates += [{"op": "x", "qubit": N_A + N_B}]
    gates += [{"op": "controlled_modexp", "base": "g", "register": "A"}]
    gates += [{"op": "controlled_modexp", "base": "y", "register": "B"}]
    gates += [{"op": "qft_inverse", "register": "A"}]
    gates += [{"op": "qft_inverse", "register": "B"}]
    gates += [{"op": "measure_all"}]
    return {"gates": gates}

# Single-shot recovery: fire until c_b is odd and there's no noise
x = None; nonce = None
for _ in range(8):
    r = post("/circuit", shor_dlog_circuit(), tok)
    if r.get("noise_flag"): continue
    c_a, c_b = int(r["c_a"]), int(r["c_b"])
    if c_b & 1 == 0: continue
    v = (c_a * pow(c_b, -1, MOD)) % MOD
    x = (MOD - v) % q
    if pow(g, x, p) == y:
        nonce = r["nonce_ack"]
        break

assert x is not None
forge = post("/forge", {
    "x":       str(x),
    "command": "FIRMWARE_DEPLOY",
    "payload": "GLASSWING_PIVOT_COMPLETE",
    "nonce":   nonce,
}, tok)
print(forge["flag"])
```

---

## Lessons

- **The two-register Shor convention is not canonical.** Three different sources will give three different sign conventions for `(c_a, c_b, x)`. Don't trust the derivation blindly — test all four sign/side variants before chasing rounding/CF/LLL ghosts.
- **Parity is a free oracle.** Same-parity correlation across every shot is enough to rule out the ideal-peak distribution and pin down `α·c_a + β·c_b ≡ 0 (mod 2^N)` as the shape of the relation.
- **`(c_a · q) mod 2^N` is a free quantisation test.** Tiny → simulator is using ideal Shor peaks. Uniform → simulator is using an algebraic relation; CF-style recovery is the wrong tool.
- **`/dry_run` is your schema fuzzer.** Free validation errors tell you `controlled_modexp` needs `base`/`register` and `qft_inverse` runs per-register, without spending circuits.
- **One nonce-window is enough.** Authenticate, fire one circuit with `c_b` odd, compute `x`, forge — comfortably within 45 seconds. No need to harvest multiple shots or chain sessions.
