# Stay Hydrated — Writeup

**Difficulty:** Insane
**Category:** Forensics
**Flag:** `HTB{d4t@_d3dupl1c4t10n_1s_sup3r_und3rRat3d}`

---

## Going in

If you're new to this kind of forensics challenge, the concepts that turn out to actually matter:

- **NTFS Data Deduplication** (Windows feature, not the same as compression) — Windows can split files into chunks, store the chunks once, and replace every file containing those chunks with a tiny stub + reparse point pointing to the chunk store. On a deduplicated volume, what looks like a "12 GB file" might actually be a few hundred bytes of metadata.
- **Reparse points** — NTFS pointers/stubs. Each one has a *tag* identifying what kind. Tag `0x80000013` is `IO_REPARSE_TAG_DEDUP`.
- **KAPE collections** — Eric Zimmerman's KAPE produces a triage image of a Windows system. It grabs registry, logs, prefetch — but **does not** grab per-user `Protect` (DPAPI) folders or KeePass config files in default modes. This matters.
- **KeePass** — password manager. Database files are `.kdbx`. Each one is unlocked by a master password (and optionally a key file).
- **MS-XPress** — a Microsoft-specific compression algorithm. Dedup chunks use it for non-archive file types.

The challenge title is the entire hint: **Stay Hydrated → Dehydrated files → NTFS Data Deduplication.**

---

## Challenge

> Horizon Trust Solutions is panicking after a disguised wiper attack encrypted deployment servers... Task Force Nightfall implores your expertise to recover the uncorrupted release package from the crippled staging environment.

Two artifacts:

| File | Format |
|---|---|
| `C.vhdx` | Hyper-V virtual disk — KAPE forensic triage from the DC |
| `D.E01` | EnCase image — file/staging share |

---

## Triage

```bash
qemu-img convert -p -O raw C.vhdx C.raw
ewfmount D.E01 ewf_mount/
```

`mmls C.raw` shows a normal MBR with one NTFS partition at sector 63. `fsstat` fails though — the boot sector's jump instruction and `0x55AA` magic are wiped. Almost certainly the "disguised wiper" calling card. Patch them back:

```bash
printf '\xEB\x52\x90' | dd of=C.raw bs=1 seek=$((63*512))     count=3 conv=notrunc
printf '\x55\xAA'     | dd of=C.raw bs=1 seek=$((63*512+510)) count=2 conv=notrunc
```

After the patch, `fsstat -o 63 C.raw` shows the volume label: **`KAPE (2025-12-23T11:58:17)`**.

That's huge: **C: is not a real OS drive** — it's a KAPE triage output volume. Which means KAPE's `!BasicCollection` did *not* grab the user's `Protect` folder, did *not* grab `KeePass.config.xml`, and the obvious DPAPI rail is dead before we even start.

D: has no MBR — it's a raw NTFS volume. Label: `Shared`.

---

## The wiper

Every interesting file on D: has a `.enc` sibling, and the originals are marked deleted in the MFT. At the root of D:, `main.exe` (12 MB, PyInstaller-packaged):

```bash
pyinstxtractor extracted_d/main.exe
python3 -c 'import marshal, dis; \
            dis.dis(marshal.loads(open("main.pyc","rb").read()[16:]))'
```

The Python source is unencrypted in the bytecode. Pseudocode:

```python
AES_KEY = urandom(32)
encrypted_key = PKCS1_OAEP(SERVER_PUBLIC_RSA_KEY).encrypt(AES_KEY)
crypt = AES.new(AES_KEY, MODE_CTR, counter=Counter.new(128))
for file in discoverFiles('.'):
    if file.endswith(".enc"): continue
    pt = open(file, 'rb').read()
    open(file + ".enc", 'wb').write(crypt.encrypt(pt) + encrypted_key)
    os.remove(file)
subprocess.run(['vssadmin', 'delete', 'shadows', '/all', '/quiet'])
```

So: AES-CTR with a random key, RSA-OAEP wraps the key with a baked-in public key, originals deleted, VSS nuked. Decrypting the `.enc` files needs the attacker's RSA private key — not happening.

**Conclusion: ignore the `.enc` files entirely.** Recovery has to find originals somewhere else on disk.

---

## Finding the deployment package

```bash
fls -r ewf_mount/ewf1 | grep -iE "release|package|deploy"
```

Two interesting MFT entries:

```
161-128-3:   StarlineTicketing_Release_1.0.0.7z   (deleted, sparse + reparse)
5104-128-7:  StarlineTicketing_Release_1.0.0.7z   (deleted, sparse + reparse)
```

`istat` on both: `Flags: Archive, Sparse, Reparse Point`, `Allocated Size: 0`. The `$DATA` attribute is 240,726 bytes of nothing — pure sparse — with a `$REPARSE_POINT` attribute hanging off the side.

Read the reparse data:

```
00000000: 1300 0080 ...
            ^^^^^^^^  IO_REPARSE_TAG_DEDUP  (0x80000013)
00000070: ... d762 f977 3215 cd4d 8ec9 224c 8b17 741f
                                                       Volume GUID
                                  → {77F962D7-1532-4DCD-8EC9-224C8B17741F}
```

That GUID is the dedup chunk store on D:, sitting at:

```
System Volume Information/Dedup/ChunkStore/{77F962D7-...}.ddp/
├── Data/   00000004.00010000.ccc  (10 MB) + 3 larger containers (~100 MB each)
├── Stream/ 00020000.00000002.ccc  + smaller stream maps
└── ...
```

This is "Stay Hydrated" in action. The file's bytes were chopped into chunks and stored in those `.ccc` containers; the file on the volume is a stub pointing at the chunks. **The wiper never touched the chunks because it didn't know to.**

---

## Rehydrating by hand

There's no good Linux tool for Microsoft Dedup. So we parse the format from the bytes.

### Container layout (`.ccc`)

Each container is a stream of records prefixed `Ckhr`:

| Offset | Field |
|---|---|
| 0x00 | `"Ckhr"` magic |
| 0x04 | version (4 bytes) |
| 0x08 | chunk ID (4 bytes, container-local) |
| 0x0C | chunk content length (4 bytes) |
| 0x28 | SHA-256 hash (32 bytes) |
| 0x58 | chunk data starts here |

### Stream map

The reparse point's first chunk hash refers to an entry in a Stream `.ccc` containing an `Smap` record that lists the file's chunks *in order*. For `StarlineTicketing_Release_1.0.0.7z` (entry 161, 240,726 bytes), the Smap had three chunks at container offsets `0xA07500`, `0xA23330`, `0xA31BF0` — all in `Data/00000004.00010000.ccc`. Sizes 114,134 + 59,493 + 67,099 = 240,726 ✓.

### Critical detail: when chunks are compressed

The dedup config (`dedupConfig.01.xml`) has `noCompressionFileExtensions = "...7z|zip|gz..."`. So archives are deduplicated but **not** LZ-compressed at the chunk level — the bytes at `chunk_start + 0x58` are the raw file content. For other file types they'd be XPress-compressed. (This will matter again in a few sections.)

```python
chunks = [(0xA07500, 114134), (0xA23330, 59493), (0xA31BF0, 67099)]
out = bytearray()
with open(container, "rb") as f:
    data = f.read()
for off, size in chunks:
    assert data[off:off+4] == b"Ckhr"
    out.extend(data[off+0x58 : off+0x58+size])
open("StarlineTicketing_Release_1.0.0.7z.recovered", "wb").write(out)
```

First bytes: `37 7A BC AF 27 1C` — 7z magic. `7z l`: 46 files, `Method = LZMA2:19 7zAES`. The archive is recovered intact.

---

## The password problem

`7zAES` with 524,288 iterations. No practical break, no point trying to crack it directly. Listing works (filenames aren't encrypted) but extraction needs the password.

Things I tried that *didn't* work:

- `ADMIN_KEY` from `.env` files — wrong (that's the app's admin key, not the archive password).
- Project terms (`Starline`, `Horizon`, `St4y_Hydr4t3d`, l33t variants) — no.
- All six `.kdbx` files in `D:\Password Manager\` were locked.
- Cracking `Dev.kdbx` against rockyou — too slow.
- DPAPI / domain-backup-key path — KAPE didn't collect the user's `Protect` folder, so even with the domain backup key from NTDS.dit there's nothing to feed it.

The password had to be sitting somewhere on disk. The forensic question: *where*.

---

## The keylogger

In `D:\Tool\Process Lasso\` (a folder Process Lasso doesn't actually use):

```
log.exe        (7.3 MB,   dehydrated)
dev01.dat      (46 KB,    dehydrated)
dev02.dat      (72 KB,    dehydrated)
hr01.dat       (29 KB,    recoverable directly)
it01.dat       (8 KB,     recoverable directly)
qa01.dat       (24 KB,    recoverable directly)
```

`hr01.dat` is readable:

```
["2025-12-21 11:13:33,954", Key.ctrl_l pressed]
["2025-12-21 11:13:34,267", '\x01' released]
["2025-12-21 11:13:34,392", '\x16' released]
...
```

Each `.dat` is the keylog output of a different user account on the box. The two large ones — `dev01.dat` and `dev02.dat` — are sparse + dedup. That's where a developer typed the archive password.

---

## Decompressing the dedup chunks for the `.dat` files

The reparse point on `dev02.dat` points (via Smap chains) to chunk `0x9B` at offset `0xA42400` in `Data/00000004.00010000.ccc`. Size 13,071 compressed → 72,616 uncompressed. This time `.dat` is **not** in the no-compression list, so the chunk data is MS XPress.

I built `coderforlife/ms-compress` and wrote a small C wrapper around `ms_decompress(MSCOMP_XPRESS, ...)`:

```bash
git clone https://github.com/coderforlife/ms-compress /tmp/mc2
cd /tmp/mc2 && bash build.sh
gcc -I /tmp/mc2/include test_decomp.c -L /tmp/mc2 -lMSCompression -o /tmp/test_decomp
/tmp/test_decomp 3 /tmp/chunk_9b.bin 72616 > /tmp/dev02_full.dat
```

Replay the events as typed text:

```python
text = ""
for line in open('/tmp/dev02_full.dat'):
    m = re.match(r'\["[^"]+", (.+) pressed\]', line.rstrip())
    if not m: continue
    key = m.group(1).strip()
    if key in ('Key.shift', 'Key.shift_r', 'Key.ctrl_l', 'Key.ctrl_r'): continue
    if key == 'Key.space': text += ' '
    elif key == 'Key.enter': text += '\n'
    elif key == 'Key.backspace': text = text[:-1]
    elif key.startswith("'"): text += key[1:-1]
    elif len(key) == 1: text += key
    else: text += f'<{key[4:]}>'
print(text)
```

```
telegram
Hey man, is the Project Starline done yet? The PM team has been pinging me ...
ok let me check xD
...
Whats the project password again?
=))))))) i told u to take care of this one for me. Ill buy you a beer later, deal?
OK
keepass
ED6zY3HDy1CLR<Ctrl+C><Ctrl+V><Ctrl+C><Ctrl+A><Ctrl+V>Hey, has this build been ...
```

The dev typed `keepass`, then `ED6zY3HDy1CLR`, then copy-pasted out of KeePass. So `ED6zY3HDy1CLR` is the **KeePass master password**, not the archive password — the archive password is whatever they copied next.

---

## Opening KeePass

```python
from pykeepass import PyKeePass
for db in ['Dev','PM','Tester-api-key','HelpdeskCreds','HRdatabase','Marketing-passwords']:
    try:
        kp = PyKeePass(f'Password Manager/{db}.kdbx', password='ED6zY3HDy1CLR')
        for e in kp.entries:
            print(f"  {e.title}: {e.password}")
    except: pass
```

`Dev.kdbx` opens:

```
AuroraMart    lsWHSj9ptDoNOkH0zvhU
FinEdge       2a2kIJ65CtXSLODeCdL9
Starline      cydbF8oGVU2dgXAamqFD
NovaHealth    FkoCYj85gbUj0ANAM0C0
```

---

## Extract

```bash
7z x -p"cydbF8oGVU2dgXAamqFD" StarlineTicketing_Release_1.0.0.7z.recovered
```

46 files, no errors. The flag is in `.env`:

```
PORT=3000
ADMIN_KEY=HTB{d4t@_d3dupl1c4t10n_1s_sup3r_und3rRat3d}
```

---

## The full chain

```
NTFS reparse tag 0x80000013 → Dedup chunk store on D:
                ↓
Parse Smap, pull chunks 0x98/0x99/0x9A from Data/00000004.00010000.ccc
                ↓
Concatenate raw bytes (7z in noCompressionFileExtensions → no LZ at chunk level)
                ↓
Recovered .7z (7zAES, uncrackable)
                ↓
Find log.exe + dev02.dat in D:\Tool\Process Lasso\ — also dehydrated
                ↓
Pull dev02's chunk 0x9B, decompress with MS XPress (this one IS compressed)
                ↓
Replay keypress timeline → KeePass master "ED6zY3HDy1CLR"
                ↓
Open Dev.kdbx → Starline entry "cydbF8oGVU2dgXAamqFD"
                ↓
Extract archive → .env → flag
```

---

## Why this was rated Insane

Three pivots stacked:

1. **Dedup rehydration.** No off-the-shelf Linux tool. Read the chunk-store format from the bytes.
2. **Knowing which chunks are compressed and which aren't.** The archive came out raw (7z is in `noCompressionFileExtensions`); the keylog data needed an XPress decompressor. Treat them the same and you get garbage or nothing.
3. **The password isn't in any password store you can open directly.** It's in a KeePass DB whose master password was typed on a keylogger whose output is dehydrated by the same dedup mechanism the challenge is about.

The "wiper" never really mattered for the recovery. It was a distraction pointing you at the `.enc` files instead of at NTFS metadata, which is where the answer always was.

---

## Lessons

- **Read the title.** "Stay Hydrated" → dehydrated files → dedup. It really was that direct.
- **`fsstat` failing is a clue, not a blocker.** Patching the boot-sector jump instruction and `0x55AA` magic is a quick fix and gives you the volume label, which here told us we were looking at a KAPE output, which told us DPAPI wouldn't work.
- **Sparse + reparse + 0 allocated** is the signature of dedup. Always check `istat` for the reparse-point tag.
- **The same data structure (dedup) was reused for both the package and the keylogger.** When you build the rehydration tool, expect to apply it more than once — but with different compression decisions per file type.
- **Distractions can be loud.** An entire encrypted-wiper substory existed to make you spend hours on a dead-end.

**Flag:** `HTB{d4t@_d3dupl1c4t10n_1s_sup3r_und3rRat3d}`
