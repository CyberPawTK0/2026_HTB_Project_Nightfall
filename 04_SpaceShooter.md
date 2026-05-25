# Space Shooter — Writeup

**Category:** Mobile / Reversing
**Flag:** `HTB{darkvector_runtime_invoke_pwned}`

---

## Going in

If you haven't reversed a Unity game before:

- **Unity** ships its scripts compiled via **IL2CPP**: C# → C++ → native code in `libil2cpp.so`. There's no `.dll` to throw at dnSpy.
- **IL2CPP metadata** lives in `assets/bin/Data/Managed/Metadata/global-metadata.dat`. Without it the native code has no type names, no method names — it's basically stripped C++. With it, you can rebuild stub .NET assemblies.
- **`Il2CppDumper`** is the classic tool. It reads the metadata + binary and emits "dummy DLLs" with full type/method/field signatures but empty bodies.
- **`Cpp2IL`** (Samboy063 fork) does the same, but supports newer metadata versions (`Il2CppDumper` lags behind). It also has an **ISIL** mode that gives you a readable disassembly of method bodies.

The challenge: an Android game claims to embed an "operational key" used for C2 authentication. Find it.

---

## First look

```
$ file spaceshooter.apk
Android package (APK), with gradle app-metadata.properties
```

Unpacking shows the Unity layout:

```
lib/arm64-v8a/libil2cpp.so      34 MB   compiled C# code
lib/arm64-v8a/libunity.so               engine
assets/.../global-metadata.dat   4 MB   IL2CPP metadata
classes.dex                              Unity bootstrap only
```

Confirmed by `jadx`: `classes.dex` is just the stock Unity Player loader, no game logic. All the C# is inside `libil2cpp.so`.

Engine version (from `libunity.so` strings):

```
6000.4.2f1 (7a4c1aeef971)        ← Unity 6
```

---

## Tooling: `Il2CppDumper` is too old, `Cpp2IL` works

Check the metadata version:

```
$ xxd global-metadata.dat | head -1
00000000: af1b b1fa 2700 0000 ...
                   ^^^^ version 0x27 = 39
```

Unity 6 introduced metadata format v39. Latest `Il2CppDumper` (v6.7.46) only supports up to v31:

```
ERROR: Metadata file supplied is not a supported version[39].
```

`Cpp2IL` does v39, so I switch:

```
$ cpp2il \
    --force-binary-path   libil2cpp.so \
    --force-metadata-path global-metadata.dat \
    --force-unity-version 6000.4.2 \
    --output-to cpp2il_out \
    --output-as dummydll
```

This produces stub `.NET` assemblies with all the type/method/field signatures but no method bodies. Good for finding *what* to look at — not good for *how it works*. For that I'll re-run with `--output-as isil`.

---

## Finding the suspicious class

```
$ strings Assembly-CSharp.dll | grep -E "^[A-Z][a-z]"
Asteroid, Enemy, Explosion, GameManager, Laser, MainMenu,
NightfallCore, Player, Powerup, SpawnManager, UIManager
```

Everything except `NightfallCore` matches normal Space Shooter gameplay. That's the planted module. Decompile its stub with `ilspycmd`:

```csharp
public static class NightfallCore
{
    private static readonly byte[] _operationalKey;
    private const byte _opKey = 78;

    public static string GetClearanceToken()         { return null; }
    public static bool   VerifyBuildIntegrity(string agentId) { return false; }
    private static string DecodeOperationalKey()     { return null; }
}
```

The signatures alone tell me almost everything I need to know:

- A 36-byte `_operationalKey` field, initialized in `.cctor`.
- A constant XOR key of `0x4E` (decimal 78).
- `DecodeOperationalKey()` presumably reads the bytes, XORs with `0x4E`, returns a string.

Method bodies are empty (dummydll mode), so for confirmation I need ISIL.

---

## ISIL: confirm the algorithm

Re-running with `--output-as isil` dumps the actual ARM64 disassembly plus Cpp2IL's stack-machine IR. The `DecodeOperationalKey` body:

```
Move W22, 78                          ; XOR key
...
Move W8, [X8+32]                      ; load encrypted byte
Xor  W8, W8, W22                      ; XOR with 78
NotImplemented "Instruction STRH..."  ; store char
...
Call String.CreateString, X0, X1      ; build managed string
```

And `.cctor`:

```
Move W1, 36                           ; size = 36
Call 0xDD5948                         ; new byte[36]
Move X1, [X19]                        ; field handle → data pointer
Call RuntimeHelpers.InitializeArray, X0, X1
```

`VerifyBuildIntegrity` just does `agentId.Equals(DecodeOperationalKey())`. So the decoded key string is exactly the comparison target — and that's the flag.

---

## Finding the encrypted blob

IL2CPP stores static array initializers as raw blobs inside `global-metadata.dat`, referenced by field-default-value entries. I could parse the metadata header to find the offset, but there's a faster way: known plaintext.

The decoded string starts with `HTB{`. So the encrypted blob starts with `HTB{` XOR'd with `0x4E`:

```
'H' ^ 0x4E = 0x06
'T' ^ 0x4E = 0x1A
'B' ^ 0x4E = 0x0C
'{' ^ 0x4E = 0x35
```

Search the metadata file for `06 1A 0C 35`:

```python
target = b'HTB{'
needle = bytes([b ^ 78 for b in target])

data = open('global-metadata.dat', 'rb').read()
idx = data.find(needle)
print(f'Found at offset 0x{idx:08X}')
print(bytes([b ^ 78 for b in data[idx:idx+36]]))
```

```
Found at offset 0x0020D080
b'HTB{darkvector_runtime_invoke_pwned}'
```

---

## Flag

```
HTB{darkvector_runtime_invoke_pwned}
```

---

## Lessons

- For modern Unity 6 / IL2CPP metadata v39: skip `Il2CppDumper`, reach for `Cpp2IL` (Samboy063) with `--force-unity-version`.
- **dummydll mode for signatures, ISIL mode for semantics.** Use both in sequence — signatures point at the interesting class, ISIL tells you how the method works.
- **Single-byte XOR with a known plaintext prefix** is the laziest path to recovering the rest of a static blob. You almost never need to parse IL2CPP's static-array table when you can just `grep` for the encrypted form of `HTB{`.
- When a class is named after the operation theme of the CTF ("NightfallCore" in a "Project Nightfall" CTF), that's not a coincidence — it's the planted module.
