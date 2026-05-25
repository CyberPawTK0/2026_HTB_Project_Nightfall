# Comfortable Exfiltration — Writeup

**Category:** Forensics
**Final answer:** `admin-03:yiz9yzf3HAnhw49hRCtxXEtsL` from `http://dash.night-fall.htb:9080/`

---

## Going in (skip if you've done memory forensics before)

Things you should be at least loosely familiar with before reading this:

- **Volatility 3** — the Swiss-army knife for memory dumps. You feed it a `.elf`/`.raw` and it parses out processes, services, registry, file objects, the works.
- **AD1** — FTK's logical-image format. It stores file *content* inside the image as zlib-compressed streams. You don't just `dd` it open.
- **DPAPI** — Windows' per-user secret-storage API. Chromium and friends use it to wrap their own AES keys. To decrypt a DPAPI blob you need the user's *master key*, which itself is encrypted with a key derived from their password + SID.
- **COM hijacking** — a persistence technique where an attacker registers a CLSID under HKCU pointing to their DLL. Any legitimate code that `CoCreateInstance`s that CLSID then loads the attacker's DLL.
- **IL2CPP / "managed" PE** — a .NET DLL embedded inside a native loader. ilspycmd decompiles the .NET part.

You'll see all five in this one challenge.

---

## What we got

```
mem.elf      4.1 GB   Windows 10/11 memory dump (ELF core)
User.ad1     1.5 GB   FTK AD1 logical image of m.thorne's user profile
User.ad2     189 MB   AD1 continuation segment
```

Eight questions to answer, all of which trace a single kill-chain through this machine.

---

## Step 0 — Recon the dump

```bash
vol -q -f mem.elf windows.info
```

Confirms Windows build 26100 (Win11), capture time 2026-05-09 22:49 UTC. `windows.pslist` looks completely normal — `services.exe`, `lsass.exe`, the usual `svchost` swarm, Edge WebView, nothing obviously suspicious running. That tells us the malware finished its install + exfil and exited before capture. Everything useful is in *registry hives* and *file objects on disk*, not in live process memory.

---

## Q1 — The fake service

The textbook persistence on Windows is registering yourself as a service. We dump the SYSTEM hive and look for services with weird ImagePaths or recent registration times.

```bash
vol -q -f mem.elf windows.registry.hivelist
# SYSTEM hive at 0xa58c8c28c000

vol -q -f mem.elf windows.registry.printkey \
    --offset 0xa58c8c28c000 \
    --key 'ControlSet001\Services'
```

Out of ~760 services, one is timestamped `2026-05-09 22:22:22` — minutes before capture — and it's called **Microsoft Updater**. Drilling into the key:

```
ImagePath    REG_EXPAND_SZ    "C:\Temp\Microsoft Cache\updater.exe"
ObjectName   REG_SZ           LocalSystem
Start        2 (auto-start)
```

A real Microsoft service doesn't live in `C:\Temp\`. **Answer:** `C:\Temp\Microsoft Cache\updater.exe`.

---

## Q2 — The shadow CLSID in HKCU

COM hijacking lives in the user's `UsrClass.dat` hive. So:

```bash
vol -q -f mem.elf windows.registry.printkey \
    --offset 0xa58c92ac1000 \
    --key 'CLSID'
```

Three CLSIDs registered under HKCU. One has the same install timestamp as the service:

```
{00000566-0000-0010-8000-00AA006D2EA4}   2026-05-09 22:21:35
```

That CLSID is **`ADODB.Stream`** — a classic COM-hijack target because plenty of legitimate code auto-loads it.

---

## Q3 — The secondary dropped file

`updater.exe` is the loader. We need to know what *else* it dropped. So: carve it out of memory and read its strings.

```bash
vol -q -f mem.elf windows.filescan | grep -i 'Microsoft Cache'
# 0xbc8fe107e180   \Temp\Microsoft Cache\updater.exe

vol -q -f mem.elf -o /tmp/dumps windows.dumpfiles --virtaddr 0xbc8fe107e180
file /tmp/dumps/file.*.updater.exe.img
# PE32+ executable (console) x86-64
```

ASCII strings:

```
C:\Users\user\source\repos\NativLoader\x64\Release\NativLoader.pdb
GrumpyFisherman.dll
```

So the project is called "NativLoader" and it carries a payload DLL called `GrumpyFisherman.dll`. But that's not what the question asks — it asks about a *secondary file*. UTF-16 strings (`strings -e l`) tell the real story:

```
C:\Temp\Microsoft Cache\
updater.exe                                   ← copy of itself
C:\ProgramData\WindowsSupport\Packages\Drivers
\kathcjaz.quh                                 ← secondary file
RAW_DLL                                       ← resource name = GrumpyFisherman.dll
```

The flow: drop self at `updater.exe`, then drop the embedded `RAW_DLL` resource (which *is* `GrumpyFisherman.dll`) to a disguised filename.

**Answer:** `kathcjaz.quh`.

---

## Q4 — The COM-exposed C# class

That embedded RAW_DLL is a .NET assembly. We carve it out of `updater.exe` by scanning for a second `MZ` header:

```python
data = open('updater.exe.img','rb').read()
positions = [i for i in range(len(data)-1) if data[i:i+2] == b'MZ']
# [0, 86192]
open('GrumpyFisherman.dll','wb').write(data[86192:])
```

```bash
file GrumpyFisherman.dll
# PE32 ... Mono/.Net assembly
```

`ilspycmd` decompiles it:

```csharp
[Guid("b3ccd9d8-ffec-4de0-8005-185a6364cedb")]
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
public class GrumpyFisherman {
    public int OrangeDucky()   { /* disable BitLocker via FveUi */ }
    public void CryoPez(...)   { /* install Windows service */ }
    public int HyperAlan(...)  { /* exfil Chromium credentials */ }
}
```

**Answer:** `GrumpyFisherman:{b3ccd9d8-ffec-4de0-8005-185a6364cedb}`.

---

## Q5 — The CLSID that triggers the service install

My first answer was the *class* CLSID (`b3ccd9d8-…`) because `CryoPez` is a method on `GrumpyFisherman`. **Wrong.**

Going back to the wide-char strings inside `updater.exe`, the loader actually publishes *one CLSID per method*:

```
{0128ad20-af37-4421-851c-5c06de5c2b2c}   CryoPez       ← install service
{4785f458-4230-48a1-b813-b16094c16acc}   OrangeDucky   ← disable BitLocker
{9133cefd-fe20-47f5-85f0-d560b6e740c5}   HyperAlan     ← exfil
```

Each per-method CLSID points to the same DLL. `CoCreateInstance({0128ad20-…})` triggers the `CryoPez` install path.

**Answer:** `{0128ad20-af37-4421-851c-5c06de5c2b2c}`.

> *Lesson for future you:* when a class exposes multiple methods over COM, look for per-method CLSIDs — many loaders publish them so a caller can pick which behavior to invoke without naming the method.

---

## Q6 — The Windows CLSID for disabling BitLocker

Straight from the decompile:

```csharp
[ComImport]
[Guid("A7A63E5C-3877-4840-8727-C1EA9D7A4D50")]
public class FveUi { }
```

`FveUi` is the BitLocker UI dispatch class; `IFveUiDispatch::DoTurnOffDeviceEncryption()` (DispID 791) is what `OrangeDucky` calls.

**Answer:** `{A7A63E5C-3877-4840-8727-C1EA9D7A4D50}`.

---

## Q7 — The exfiltration URL

`GrumpyFisherman.dll` has obfuscated strings going through a custom XOR routine:

```csharp
public static string Decode(string s) {
    int length = s.Length;
    char[] arr = new char[length];
    for (int i = 0; i < arr.Length; i++) {
        char c = s[i];
        byte b  = (byte)((c & 0xFF) ^ (length - i));
        byte b2 = (byte)((c >> 8) ^ i);
        arr[i] = (char)((b2 << 8) | b);
    }
    return new string(arr);
}
```

Reimplement in Python, run it over every encrypted string constant:

```python
def decode(s):
    L = len(s); out = []
    for i, c in enumerate(s):
        v  = ord(c)
        b  = (v & 0xFF) ^ (L - i)
        b2 = (v >> 8)   ^ i
        out.append(chr((b2 << 8) | b))
    return ''.join(out)
```

Decoded strings include the URL template, header names, the Chromium paths, and the JSON marker the malware looks for:

```
http://check.microsoftcloudservices.htb:8000/update/
Thorium\User Data\Local State
Thorium\User Data\Default\Login Data
"encrypted_key":"
```

**Answer:** `http://check.microsoftcloudservices.htb:8000/update/`.

---

## Q8 — The exfiltrated credential

This is the multi-step one. The malware grabs Chromium's `Local State` (which contains the DPAPI-wrapped AES key) and `Login Data` (the SQLite DB with encrypted passwords). To reproduce the decryption, we need:

1. The encrypted `Local State` JSON
2. The encrypted `Login Data` SQLite
3. The user's DPAPI master key
4. Which means: the user's password, the SID, and the master-key file from disk

### Step 1 — Pull both Thorium files out of memory

```bash
vol -q -f mem.elf windows.filescan | grep -i 'Thorium\\User Data'
# 0xbc8fe30c00d0   Login Data
# 0xbc8fe30ba180   Local State

vol -q -f mem.elf -o /tmp/dumps2 windows.dumpfiles --virtaddr 0xbc8fe30c00d0
vol -q -f mem.elf -o /tmp/dumps2 windows.dumpfiles --virtaddr 0xbc8fe30ba180
```

### Step 2 — Read the encrypted password from the SQLite

```bash
sqlite3 'Login Data.dat' \
  "SELECT origin_url, username_value, hex(password_value) FROM logins;"
```

```
http://dash.night-fall.htb:9080/ | admin-03 | 7631304601...
                                              └ "v10" Chromium prefix
```

### Step 3 — Pull the AES key blob from Local State

```json
"os_crypt":{"encrypted_key":"RFBBUEkBAAAA..."}
```

Base64-decode, strip the 5-byte `DPAPI` prefix — that's the DPAPI blob, bound to master key `{5915b1e9-…}`.

### Step 4 — Recover the DPAPI master key

The master key is itself encrypted with a key derived from `m.thorne`'s password + SID. We need both:

- **Password:** `windows.hashdump` gives `m.thorne 3716e9804c41b32fe09dcb2aa4c98071`. John + rockyou cracks it in ~5 seconds → `BlueAngel25`.
- **Master-key file:** searching memory for the UUID gives a reference, but the file content itself is in AD1. AD1 stores files as zlib streams, so scan for `0x78 0x9c` headers near the metadata and try decompressing each:

```python
import re, zlib
data = open('User.ad1','rb').read()[0x3493a000:0x3493e000]
for m in re.finditer(b'\x78\x9c', data):
    try:
        out = zlib.decompress(data[m.start():m.start()+0x800])
        if out[:4] == b'\x02\x00\x00\x00':   # DPAPI master-key file magic
            open('masterkey','wb').write(out)
    except: pass
```

468 bytes, starts with `02 00 00 00` + UUID in UTF-16 — that's a valid master-key file.

Decrypt it with impacket:

```bash
dpapi.py masterkey -file masterkey \
    -password BlueAngel25 \
    -sid S-1-5-21-1291622023-1877101182-1066255875-1001
# Decrypted key: 0xcdbf3b9143ba3613e5b95f901e229c74...
```

### Step 5 — Use the master key to decrypt the Chromium AES key

```python
from impacket.dpapi import DPAPI_BLOB
mk = bytes.fromhex('cdbf3b91...dac6ea3')
chromium_key = DPAPI_BLOB(open('encrypted_key.bin','rb').read()).decrypt(mk)
# e426086a6228b05155eb618838d2c8e629406ba5dd195bae661983495c0d6114
```

I tried hand-rolling the `CryptDeriveKey` step first and got a wrong key — the blob declared `CALG_AES_256` + `CALG_SHA_512` and I bungled the derivation. Switching to impacket's implementation fixed it. *Lesson: when impacket has a tested implementation, use it.*

### Step 6 — AES-GCM decrypt the password

Chromium v10 format: `"v10" || IV(12) || ciphertext || tag(16)`.

```python
from Crypto.Cipher import AES
key = bytes.fromhex('e426086a...c0d6114')
AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
# b'yiz9yzf3HAnhw49hRCtxXEtsL'
```

**Answer:** `admin-03:yiz9yzf3HAnhw49hRCtxXEtsL`.

---

## The kill-chain, one paragraph

`m.thorne` ran something. That dropper copied itself to `C:\Temp\Microsoft Cache\updater.exe` (a native C++ "NativLoader"), and extracted its embedded `RAW_DLL` resource — a .NET assembly called `GrumpyFisherman` — to a junk path. It registered shadow CLSIDs under HKCU (hijacking `ADODB.Stream` plus three per-method CLSIDs of its own), then called itself through COM: `CryoPez` to install the "Microsoft Updater" service as LocalSystem, `OrangeDucky` to disable BitLocker via the Windows `FveUi` dispatch class, and `HyperAlan` to DPAPI-decrypt Thorium's saved-password key and POST the gzipped login DB to its C2.

## Lessons

- When `pslist` looks normal but the brief says "incident", everything's in registry + on-disk artifacts. Time spent on running processes is wasted.
- Service install times in the registry are a great pivot — they cluster around install, so one weird timestamp gives you the whole campaign.
- Wide-char strings (`strings -e l`) hide things ASCII strings miss. Always run both.
- For per-method COM publishing, the *method CLSID* triggers the behavior, not the class CLSID.
- AD1 files store content as zlib streams. If a tool says it can't read AD1, scan for `78 9c` and `inflate` it yourself.
- DPAPI chains are long but mechanical. Have impacket installed and don't try to be clever.
