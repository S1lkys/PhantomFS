# PhantomFS

ProjFS provider for EDR evasion research. Projects files where the content depends on which process reads them. Payload is stored AES-256-CBC encrypted on disk, decrypted only in memory at runtime.

## Workflow

```
1) Generate key:     PhantomFS.exe -keygen
2) Encrypt payload:  PhantomFS.exe -encrypt mimikatz.exe -key <key> -out mimikatz.enc
3) Serve:            PhantomFS.exe C:\Staging -file mimikatz.enc -key <key> -decoy C:\Windows\System32\calc.exe
```

Result: `C:\Staging\calc.exe` appears in the filesystem.
- `powershell.exe` reading it gets decrypted mimikatz bytes
- Everything else (Defender, CrowdStrike, ...) gets real calc.exe bytes
- Delete/rename attempts from non-allowed processes are blocked

## Build

VS2022, open `PhantomFS.sln`, build x64 Release. Requires Windows SDK (ProjFS headers + libs).

## Prerequisites

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart
```

Provider runs at medium integrity, no admin needed (ProjFS feature activation does require admin).

## CLI Reference

### Keygen
```
PhantomFS.exe -keygen
```

### Encrypt
```
PhantomFS.exe -encrypt <input> -key <64_hex_chars> -out <output.enc>
```
Format: `[16 byte random IV][AES-256-CBC ciphertext with PKCS7 padding]`

### Serve
```
PhantomFS.exe <root_dir> -file <payload.enc> -key <hex> -decoy <benign_file>
    [-name <virtual_filename>]
    [-allow <process_substring>]  (repeatable, default: powershell.exe, pwsh.exe, cmd.exe)
    [-deny-read <process_substring>]  (repeatable)
    [-quiet]
```

## How It Works

ProjFS callbacks receive `TriggeringProcessImageFileName` on every file access:
- `GetFileDataCallback`: Checks process against rules, serves payload or decoy bytes
- `NotificationCallback PRE_DELETE`: Blocks non-allowed processes from deleting
- `FILE_HANDLE_CLOSED`: Calls `PrjDeleteFile` to force re-hydration

The re-hydration trick is necessary because ProjFS caches file content after first read.
Without it, the second reader would get whatever the first reader received.

## Detection Surface

- `PrjStartVirtualizing` API call
- `IO_REPARSE_TAG_PROJFS` reparse points
- ProjFS Windows feature enabled
- `PrjFlt` minifilter at altitude 189800 (`fltmc.exe`)
- `Microsoft-Windows-ProjFS` ETW provider
- Frequent file state transitions (hydrated -> placeholder)
