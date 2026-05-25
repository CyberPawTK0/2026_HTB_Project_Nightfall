# Stay Hydrated — Forensics Playbook

> **What this document is:** the scratchpad I built *before* solving the challenge — the recon plan, the hypothesis tree, the commands I expected to need. If you've never approached a "two-image forensic" challenge before, treat this as a worked example of how to triage one. The actual solution writeup is in a separate doc.

---

## Going in

If you're new to this kind of challenge, the things worth being comfortable with:

- **VHDX vs E01** — VHDX is Hyper-V's virtual disk. E01 is EnCase / EWF, a forensic image format with embedded hashes and acquisition metadata. They mount differently.
- **NTFS internals** — `$MFT` (the master file table) lists every file and directory; `$UsnJrnl:$J` is the change journal (a chronological log of writes/renames/deletes); `$LogFile` is the transaction log. All three persist after a file is deleted.
- **Volume Shadow Copies (VSS)** — Windows' built-in snapshot system. They live on the volume itself; even if a file was wiped on the live filesystem, prior versions may sit in a shadow copy.
- **OneDrive Files-On-Demand** — files that look full size in the file listing but are actually 0-byte placeholders with a reparse point pointing at OneDrive cloud storage. The actual bytes may live in a *cache* somewhere else on disk.
- **Reparse points and sparse files** — file-system features where the "file" on disk isn't actually the file content but a pointer or stub.

The challenge's title — "Stay Hydrated" — hints at *dehydrated* files: things that look normal but aren't really there on the volume you can see.

---

## Evidence

| File | Format | Likely role |
|---|---|---|
| `C.vhdx` | Hyper-V virtual disk | Windows system drive (registry, logs, profiles) |
| `D.E01` | EnCase image | Data/staging drive — almost certainly where the deployment package lived |

**Strategy:** the deployment package most likely lived on D:. C: provides context — registry, event logs, OneDrive cache, scheduled tasks, wiper footprint. Cross-reference between them.

## Narrative → technical hints

Always read the brief looking for technical breadcrumbs:

| Story element | Likely meaning |
|---|---|
| Title: **Stay Hydrated** | Dehydrated files — OneDrive Files-On-Demand, sparse, reparse points, WIM/ESD hydration |
| "disguised wiper" | Headers/MFT overwritten but data clusters survive — carve |
| "no ransom note, exposing motive" | The wiper's own artifacts are the lead |
| "deployment / staging / pristine deployment package" | `.wim` / `.esd` / `.msix` / `.appx` / `.zip` on D: |
| "core validation framework" | Code signing / Authenticode / `.cat` files |
| "eleventh hour" | Last writes before wipe — `$UsnJrnl`, `$LogFile` |
| "federation trusts / credentials harvest" | Probably a decoy, or used to decrypt something (BitLocker/EFS) |

---

## Setup

```bash
cd ~/Desktop/forensics_stay_hydrated
sha256sum C.vhdx D.E01 > hashes.txt           # hash everything before touching it

sudo apt update
sudo apt install -y qemu-utils libguestfs-tools sleuthkit \
  ntfs-3g libfsntfs-utils libvshadow-utils libbde-utils \
  ewf-tools libewf-dev kpartx \
  bulk-extractor foremost binwalk testdisk p7zip-full xxd \
  wimtools osslsigncode python3-pip
pip3 install --user analyzeMFT
```

The Eric Zimmerman tools (`MFTECmd`, `EvtxECmd`, `RECmd`) need .NET — run on Windows or via `dotnet` on Linux. Strongly recommended for MFT / event-log work.

---

## Phase 1 — image triage (don't modify anything)

```bash
qemu-img info C.vhdx                      # type, virtual size, parent locator?
ewfinfo D.E01                             # EWF metadata, hashes
xxd C.vhdx | head -40                     # check VHDX header
xxd C.vhdx | grep -i "parent" | head      # any differencing-disk parent?
```

If `qemu-img info` shows a backing file/parent for `C.vhdx`, that's a differencing disk — note it down or you'll mount an incomplete view.

### Convert / expose as raw

```bash
# C.vhdx → raw
qemu-img convert -p -O raw C.vhdx C.raw
mmls C.raw

# D.E01 → virtual raw via ewfmount
mkdir -p ewf_mount
ewfmount D.E01 ewf_mount/                  # creates ewf_mount/ewf1
mmls ewf_mount/ewf1
```

Record the partition offsets from both `mmls` outputs — almost everything below needs them.

---

## Phase 2 — mount both, read-only

### C:

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd -r -c /dev/nbd0 C.vhdx
sudo mkdir -p /mnt/c
sudo mount -o ro,noload,show_sys_files,streams_interface=windows \
  /dev/nbd0p2 /mnt/c                       # adjust partition number from fdisk -l /dev/nbd0
```

### D:

Three options:

```bash
# A) kpartx
sudo kpartx -av ewf_mount/ewf1
sudo mount -o ro,show_sys_files,streams_interface=windows \
  /dev/mapper/loop0p1 /mnt/d

# B) offset mount
sudo mount -o ro,loop,offset=$((<sector>*512)),show_sys_files,streams_interface=windows \
  ewf_mount/ewf1 /mnt/d

# C) guestmount (handles both natively, no root)
guestmount -a C.vhdx -i --ro /mnt/c
guestmount -a D.E01  -i --ro /mnt/d
```

`show_sys_files` + `streams_interface=windows` exposes `$MFT`, `$UsnJrnl`, and Alternate Data Streams (the metadata you almost always need on NTFS forensics).

**If NTFS won't mount**, the wiper damaged it. Skip mounting; work raw with sleuthkit:

```bash
fls -r -o <offset> ewf_mount/ewf1 | less       # D: tree incl. deleted
fls -rd -o <offset> ewf_mount/ewf1             # D: deleted only
fls -r -o <offset> C.raw | less                # same for C:
```

Cleanup when done:

```bash
sudo umount /mnt/c /mnt/d
sudo qemu-nbd -d /dev/nbd0
sudo kpartx -dv ewf_mount/ewf1
fusermount -u ewf_mount
```

---

## Phase 3 — Volume Shadow Copies on BOTH (high priority)

The pre-wipe state often lives here. Check D: first.

```bash
# D: VSS
vshadowinfo -o $((<d_offset>*512)) ewf_mount/ewf1
mkdir -p /mnt/d_vss
vshadowmount -o $((<d_offset>*512)) ewf_mount/ewf1 /mnt/d_vss
ls /mnt/d_vss/                          # vss1, vss2, ...

mkdir -p /mnt/d_snap1
sudo mount -o ro,loop,show_sys_files,streams_interface=windows \
  /mnt/d_vss/vss1 /mnt/d_snap1

# C: VSS
vshadowinfo -o $((<c_offset>*512)) C.raw
mkdir -p /mnt/c_vss
vshadowmount -o $((<c_offset>*512)) C.raw /mnt/c_vss
```

Check *every* snapshot on both drives — they may capture different stages of the package.

---

## Phase 4 — hunt the deployment package

```bash
# Likely paths on D:
for p in DeploymentShare RemoteInstall Staging Builds Packages \
         inetpub Sources Releases Artifacts Repo SCCM WSUS \
         "Program Files/Microsoft Deployment Toolkit"; do
  find /mnt/d -ipath "*${p}*" -type f 2>/dev/null | head
done

# Package extensions on D:, sorted by mtime
find /mnt/d \( -iname "*.wim" -o -iname "*.esd" -o -iname "*.swm" \
  -o -iname "*.msix" -o -iname "*.msixbundle" -o -iname "*.appx" \
  -o -iname "*.appxbundle" -o -iname "*.cab" -o -iname "*.msi" \
  -o -iname "*.nupkg" -o -iname "*.zip" -o -iname "*.7z" \
  -o -iname "*.iso" -o -iname "*.vhd" -o -iname "*.vhdx" \) \
  -printf "%T@ %s %p\n" 2>/dev/null | sort -n

# Same scan on C: (cache may live there)
find /mnt/c \( -iname "*.wim" -o -iname "*.esd" -o -iname "*.msix" \
  -o -iname "*.appx" -o -iname "*.zip" -o -iname "*.nupkg" \) \
  -printf "%T@ %s %p\n" 2>/dev/null | sort -n

# C: deployment-tool footprints
find /mnt/c -ipath "*ccmcache*" -o -ipath "*SoftwareDistribution*" \
  -o -ipath "*DeploymentShare*" -o -ipath "*MDT*" 2>/dev/null | head
```

Recently-written candidates float to the bottom of the sorted output.

---

## Phase 5 — "Hydrate" check (the title hint)

### OneDrive / Files-On-Demand placeholders

A package on D: may be a 0-byte placeholder whose real content lives in a OneDrive cache on C:.

```bash
# Files with reparse points on D:
fls -r -o <d_offset> ewf_mount/ewf1 | awk '$1 ~ /r\/r/' | head -50
istat -o <d_offset> ewf_mount/ewf1 <inode> | grep -i "Reparse"

# OneDrive cache + logs on C:
find /mnt/c -ipath "*OneDrive*" -type f 2>/dev/null | head
find /mnt/c -name "SyncEngineDatabase.db" 2>/dev/null
find /mnt/c -ipath "*OneDrive/setup/logs*" -type f 2>/dev/null
find /mnt/c -ipath "*OneDrive*logs*" -name "*.odl" 2>/dev/null
```

Reparse tags worth knowing: `0xA000001A` (generic cloud), `0x9000001A` (OneDrive). A sparse placeholder on D: + a OneDrive cache on C: + the title "Stay Hydrated" is a very plausible solution shape.

### WIM/ESD hydration

```bash
7z l package.wim                          # 7z handles WIM/ESD/MSIX
7z x package.wim -o./wim_contents

# wimlib
wiminfo package.wim
wimmount package.wim 1 /mnt/wim
```

### Sparse files

```bash
# Logical size much larger than physical block count
find /mnt/d -type f -printf "%s %b %p\n" 2>/dev/null | \
  awk '$1 > 1000000 && $2*512 < $1/2 {print}'
```

---

## Phase 6 — wiper recovery

### MFT analysis (both drives)

```bash
# D: MFT
icat -o <d_offset> ewf_mount/ewf1 0 > MFT_D.bin
analyzeMFT.py -f MFT_D.bin -o mft_d.csv

# C: MFT
icat -o <c_offset> C.raw 0 > MFT_C.bin
analyzeMFT.py -f MFT_C.bin -o mft_c.csv
```

Look for:

- Recently-deleted entries with intact `$DATA`.
- Resident files (small files where the data fits inside the MFT entry — survives data-cluster wipes).
- Timestomping: `$STANDARD_INFORMATION` vs `$FILE_NAME` mismatch.
- Filenames matching the deployment-package theme.

### USN journal — the eleventh-hour timeline

```bash
sudo cp '/mnt/d/$Extend/$UsnJrnl:$J' ./UsnJrnl_D_J.bin
sudo cp '/mnt/c/$Extend/$UsnJrnl:$J' ./UsnJrnl_C_J.bin
# On Windows: MFTECmd.exe -f UsnJrnl_D_J.bin --csv . --csvf usn_d.csv
```

Filter for the wipe window — `CREATE → WRITE → RENAME → DELETE` chains often reveal where the pristine file briefly lived before destruction.

### Carving from unallocated / raw

```bash
# Unallocated space from D:
blkls -o <d_offset> ewf_mount/ewf1 > unalloc_D.bin

foremost -t zip,exe,doc,pdf,all -i unalloc_D.bin -o foremost_D
photorec /d photorec_D ewf_mount/ewf1

# Raw signatures across the whole D: image
grep -aboP "MSWIM\x00\x00\x00" ewf_mount/ewf1 | head     # WIM
grep -aboP "PK\x03\x04" ewf_mount/ewf1 | head            # ZIP/MSIX/APPX/NUPKG
grep -aboP "MSCF" ewf_mount/ewf1 | head                  # CAB

bulk_extractor -o be_out_D ewf_mount/ewf1
bulk_extractor -o be_out_C C.raw
```

### TSK recover everything

```bash
tsk_recover -e -o <d_offset> ewf_mount/ewf1 recovered_D/
tsk_recover -e -o <c_offset> C.raw            recovered_C/
```

---

## Phase 7 — context on C: (registry / logs)

Once you have candidates on D:, use C: to verify which was "pristine":

```bash
ls -la /mnt/c/Windows/System32/config/        # SAM, SYSTEM, SOFTWARE, SECURITY
find /mnt/c/Users -name NTUSER.DAT 2>/dev/null

ls /mnt/c/Windows/System32/winevt/Logs/        # event logs — parse with EvtxECmd/chainsaw
ls /mnt/c/Windows/System32/Tasks/              # scheduled tasks
find /mnt/c -path "*PSReadLine/ConsoleHost_history.txt" 2>/dev/null
ls /mnt/c/Windows/Prefetch/ 2>/dev/null        # what ran
```

Specific registry keys to look at (offline with `reglookup` or RECmd):

- `SYSTEM\CurrentControlSet\Services\` — services pointing at D: paths
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` — installed tooling
- `NTUSER.DAT → Software\Microsoft\OneDrive\` — OneDrive account/sync state
- `C:\Windows\System32\inetsrv\config\applicationHost.config` — IIS

---

## Phase 8 — verify "uncorrupted"

The brief says "pristine" — verify by signature or hash.

```bash
osslsigncode verify recovered.msix
osslsigncode verify recovered.wim
osslsigncode verify recovered.cab

find /mnt/c -ipath "*CatRoot*" -name "*.cat" 2>/dev/null
sha256sum recovered_D/*.{wim,msix,zip,esd,cab,nupkg} 2>/dev/null > candidates.sha256
```

Pristine = signature verifies AND hash matches (if one's given) AND extraction is clean.

---

## Phase 9 — where the flag likely is

In rough order of likelihood:

1. **String inside the recovered package**:
   ```bash
   strings -a recovered.wim | grep -iE "flag\{|ctf\{|hydrate"
   7z x recovered.wim -o./inside && grep -riE "flag\{|ctf\{" ./inside
   ```
2. **SHA-256 of the recovered file**, wrapped in flag format
3. **Inside the digital signature / catalog metadata** of the package
4. **In an ADS** on the recovered file: `getfattr -d -m - file`, or `icat`/`fls` with sleuthkit

---

## Quick decision tree

```
ewfinfo / qemu-img info clean? ──no→ check parent disks, repair, hash
        │ yes
        ▼
vshadowinfo on D: shows snapshots? ──yes→ mount each, hunt package pre-wipe
        │ no
        ▼
Deployment package found intact on D:? ──yes→ Phase 8 verify, Phase 9 flag
        │ no
        ▼
Placeholder/sparse file on D: + OneDrive cache on C:? ──yes→ hydrate from C:
        │ no
        ▼
MFT readable? ──yes→ USN journal → recently-deleted package → icat recover
        │ no (MFT wiped)
        ▼
Carve raw image: photorec + grep for MSWIM/PK signatures → reconstruct
```

---

## Common gotchas

- Always mount **read-only**. Hash before and after to prove integrity.
- E01 can be multi-part (`D.E01`, `D.E02`, …). `ewfmount` chains them automatically if all segments are in the same directory.
- The wiper may have overwritten the boot sector but not the backup at the end of the partition — `ntfsfix --no-action` will tell you.
- A "corrupted" WIM may just be missing the integrity table — `wimlib-imagex optimize --check` or extract with `7z` (more permissive).
- BitLocker: look for `*.bek`, recovery keys, or keys in memory dumps / hiberfil.
- Sparse files: logical size ≠ physical. Compare `stat` blocks vs size.
- `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` on C: — run `strings` + `bulk_extractor` over them.
- If D: was BitLocker-encrypted, the key/recovery info often lives on C: in the registry. *That* is where "federation trusts and credentials" might actually matter.

---

## When you ping the team for help, share these

- `qemu-img info C.vhdx`
- `ewfinfo D.E01`
- `mmls C.raw` and `mmls ewf_mount/ewf1`
- `vshadowinfo` for both
- Output of the package-extension `find` on D:
- Candidate filenames + their MFT status (allocated/deleted/resident)

That's enough for anyone on the team to slot in and help without re-running the recon.
