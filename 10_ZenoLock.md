# ZenoLock — Writeup

**Category:** Hardware / Quantum
**Final answer:** schedule `basis=Z, window=31.25, dt_ms=25`.

---

## Going in

A bit of physics that's worth grokking before the writeup:

- **Qubit, |0⟩ / |1⟩.** Two basis states of a two-level quantum system. A qubit can be in a superposition `α|0⟩ + β|1⟩`.
- **Rabi oscillation.** Under a continuous resonant drive, a qubit rotates smoothly back and forth between `|0⟩` and `|1⟩` at frequency `ω`. The probability of being measured as `|0⟩` after time `t` is `cos²(ωt/2)`.
- **Projective measurement.** When you measure in the Z basis, the qubit *collapses* into either `|0⟩` or `|1⟩` with probabilities determined by its current state. The collapse is real — the previous superposition is gone afterward.
- **Quantum Zeno Effect.** If you measure the qubit fast enough, every measurement collapses it back to (almost) `|0⟩` before any meaningful rotation can happen. Net effect: the rotation is *frozen*. This is the punchline of the challenge.
- **Anti-Zeno / tamper alarm.** Measuring too often can either physically heat the qubit or, in a hardware setting, raise an alarm on the sense line. Above some rate, the device detects the surveillance.

The challenge: a token rotates every 15.625 s. Don't let it. Freeze it long enough to replay a captured session.

---

## Challenge

> A rotational security buffer belonging to the Halcyon Dynamics HSM was identified during a network tap on their admin plane. The device uses a single-qubit Rabi oscillator to advance its authentication token — when the qubit rotates from `|0⟩` to `|1⟩`, all captured credentials are invalidated. GLASSWING has one valid session token left. You have tapped the oscillator's sense line. You cannot stop the Hamiltonian. You cannot read the qubit's state through the wire. You can only schedule measurements. Freeze the rotation long enough for the token to replay and extract the flag.

Two artifacts: `sim.py` (a local helper for testing schedules) and `OBSERVED.log` (a passive capture of the qubit rotating with no measurement schedule running).

---

## The physics in one paragraph

Each projective Z-basis measurement collapses the qubit to whichever eigenstate it's closest to. After a free evolution of time `Δt`, the probability of still being `|0⟩` is `cos²(ωΔt/2)`. Survival over a window `T` with `N = T/Δt` measurements:

```
P_survive(Δt) = cos²(ωΔt/2)^N   ≈   exp(- T · ω² · Δt / 4)
```

Two failure modes:

- **Δt too large** → `cos²(ωΔt/2)` is small, the qubit rotates between checks, survival collapses (server says `COLD`).
- **Δt too small** → measurement rate spikes on the sense line, anti-Zeno / tamper alarm fires (server says `DRIFT`).

The win condition is a Δt in the narrow band between them.

---

## Recovering parameters from OBSERVED.log

The passive log gives the rotation period directly:

```
[15.625000s] TOKEN ROTATED  credential advanced. captured session invalidated.
T_window = 31.250000 s (2 × T_rot)
```

So `T_rot = 15.625 s`, and `ω = π / T_rot ≈ 0.201062 rad/s`. Window `T = 31.25 s`.

`sim.py` (lines 84–88) also leaks a useful constraint: X-basis measurements collapse to `|±⟩`, which are *not* eigenstates of the rotation. So they don't preserve `|0⟩` and X-basis schedules return `ANTI_ZENO` on the live server. **Basis must be Z.**

---

## Δt sweep

Using the closed-form approximation with `T = 31.25`, `ω² ≈ 0.04043`:

| Δt (ms) | N steps | P_survive | verdict |
|---:|---:|---:|:---|
| 100 | 312 | 0.9690 | ✗ COLD |
| 50 | 625 | 0.9843 | ✗ COLD |
| 32 | 976 | 0.9900 | borderline |
| 25 | 1250 | 0.9922 | ✓ pass |
| 10 | 3125 | 0.9969 | ✓ pass |
| 5 | 6250 | 0.9984 | ✓ pass |
| 1 | 31250 | 0.99968 | ✓ pass (risk DRIFT) |

The local `sim.py` threshold (0.99) passes for any `Δt ≤ ~32 ms`. The hidden server-side detection threshold caps the other end.

---

## Solution

```
basis  = Z
window = 31.25       (= 2 × T_rot)
dt_ms  = 25
```

`P_survive ≈ 0.9922` — comfortably above the Zeno cutoff, sparse enough to stay under the tamper alarm. Server accepts, token replays, flag drops.

If `dt_ms = 25` had returned `COLD`, the binary-search ladder I had ready was 25 → 15 → 10 → 5 → 2 → 1, flipping direction on the first `DRIFT`.

---

## Lessons

- **Two log entries did all the work.** `T_window` and `TOKEN ROTATED at 15.625s` are the entire signal. Everything else (phases, midpoint warnings, flavour text) was atmosphere.
- **Local pass ≠ remote pass.** The "hidden detection threshold" in `sim.py`'s output isn't a bug in the helper — it's the puzzle. Naively driving Δt to zero will fail. The band is what you're looking for.
- **Read the flavour for clues.** Session name `eleatic-ancient-sigma-12`, chip `PARMENIDES-ω5` — Zeno of Elea was a student of Parmenides, born around 490 BCE. If the puzzle is named after a paradox, the technique is probably named after the paradox too.
- **When you have a closed-form for the success probability, sweep it on paper first.** A two-line table told me 25 ms was safe before I burned a single submission.
