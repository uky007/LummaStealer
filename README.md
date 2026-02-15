# Lumma Stealer Deobfuscator

IDA Pro Python scripts for deobfuscating [Lumma Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma) (a.k.a. LummaC2), an information-stealing malware.

## Target Sample

| Property | Value |
|----------|-------|
| SHA-256 | `de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874` |
| Malware | Lumma Stealer (LummaC2) |
| Build Date | Jan 14 2026 |
| Architecture | x86 (32-bit PE), with Heaven's Gate transitions to x64 |

## Deobfuscation Results

**610 call sites** processed across **460 unique decrypt functions**, with a **100% success rate** (0 extraction failures, 0 decryption failures).

### Summary by Data Type

| Type | Count | Description |
|------|------:|-------------|
| UTF-16LE strings | 128 | Wide strings (Windows API arguments, URLs, paths, commands) |
| UTF-8 strings | 73 | Narrow strings (HTML parsing patterns, HTTP headers, keywords) |
| GUID | 8 | COM interface / CLSID identifiers |
| Shellcode | 3 | Executable code blobs (x64 syscall stubs, Heaven's Gate) |
| DWORD | 271 | 4-byte constants (port numbers, status codes, API hashes, timeouts) |
| Other binary | 125 | Raw binary data (encryption keys, small code fragments) |
| Layer 2 encoded | 1 | Double-encrypted string requiring second-pass decoding |
| UTF-16BE | 1 | Rare big-endian string variant |
| **Total** | **610** | |

### Algorithm Types

10 distinct decryption algorithms were identified. All use MBA (Mixed Boolean-Arithmetic) obfuscation to hide XOR and ADD operations.

| Algorithm | Count | Description |
|-----------|------:|-------------|
| Type 1 | 490 | `(byte ^ (i ^ xor_key)) + add_value` |
| Type 3 | 44 | Inner XOR loop variant |
| Type 5 | 47 | Subtraction-based variant |
| Type 4 | 10 | Double-key variant |
| Type 7 | 13 | Shift-XOR variant |
| Types 6, 8-12 | 6 | Rare/unique algorithm variants (1 each) |

### Representative Decrypted Samples

#### Strings (UTF-16LE / UTF-8)

```
0x0280FC35: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
0x0281090C: "https://steamcommunity.com/profiles/76561199880317058"
0x028122CB: "cmd.exe \"start /min cmd.exe \"/c timeout /t 3 /nobreak & del \""
0x0281808A: "powershell -exec bypass"
0x0281CE27: "\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
0x0280ECDB: "<div class=\"tgme_page_title\" dir=\"auto\">\n  <span dir=\"auto\">"
0x0280CCC7: "Content-Disposition: form-data; name=\""
```

#### GUIDs

```
0x0282A448: {00021401-0000-0000-C000-000000000046}  (CLSID_ShellLink)
0x0282A48C: {000214F9-0000-0000-C000-000000000046}  (IShellLinkA)
0x0282A4D0: {0000010B-0000-0000-C000-000000000046}  (IPersistFile)
0x02844341: {4590F811-1D3A-11D0-891F-00AA004B2E24}  (IWbemObjectSink)
0x02844391: {DC12A687-737F-11CF-884D-00AA004B2E24}  (IClassFactory2)
```

#### DWORDs

```
0x028103FF: 443    (0x000001BB)  -- HTTPS port
0x0280FF9E: 200    (0x000000C8)  -- HTTP 200 OK
0x0280FFBB: 403    (0x00000193)  -- HTTP 403 Forbidden
0x0280F97F: 300000 (0x000493E0)  -- 300-second timeout
0x02811B62: 0x7FFE0000           -- KUSER_SHARED_DATA address
```

#### Shellcode

```
0x0282065A: [SHELLCODE (x64) 21 bytes]
0x0284C326: [SHELLCODE (x64) 16 bytes]       -- indirect syscall stub
0x0284C7CC: [SHELLCODE (Heaven's Gate) 90 bytes]
```

## Scripts

| Script | Environment | Description |
|--------|-------------|-------------|
| `lumma_deobfuscator.py` | IDA Pro | Main deobfuscator. Identifies decrypt functions, extracts encrypted stack data, decrypts, and annotates IDA comments. |
| `lumma_fix_cff.py` | IDA Pro | Patches Control Flow Flattening (CFF) — resolves register-indirect jump dispatchers back to direct jumps. |
| `lumma_fix_code_obfuscation.py` | IDA Pro | Patches `jmp [dword_XXXXXXXX]` indirect jumps (~264 sites) — restores IDA code flow analysis. |
| `lumma_layer2_decoder.py` | Standalone | Applies second-layer decoding to double-encrypted entries. |
| `lumma_apply_layer2.py` | IDA Pro | Writes Layer 2 decoded results back to IDA comments. |

## Usage

### Recommended execution order in IDA Pro

1. **`lumma_fix_code_obfuscation.py`** — Fix indirect jumps so IDA can analyze code flow
2. **`lumma_fix_cff.py`** — Flatten CFF dispatchers into direct jumps
3. **`lumma_deobfuscator.py`** — Deobfuscate all encrypted strings/data
4. **`lumma_layer2_decoder.py`** (standalone) — Decode Layer 2 entries from exported JSON
5. **`lumma_apply_layer2.py`** — Apply Layer 2 results to IDA comments

Each script is run via **File > Script file** in IDA Pro (except `lumma_layer2_decoder.py`, which runs standalone with Python 3).

## Future Work

### 1. Recover code hidden behind register-indirect jumps

`lumma_fix_code_obfuscation.py` currently handles `jmp [dword_XXXXXXXX]` (FF 25) memory-indirect jumps. However, **register-indirect jumps** such as `jmp eax`, `jmp ecx`, and `call eax` also break IDA's control flow analysis, leaving subsequent bytes as undefined data (`db`/`dd`). A future pass would:

- Resolve register values via backward slicing or emulation to determine jump targets
- Convert the orphaned data regions back to code (`ida_auto.plan_and_wait` / `idc.create_insn`)
- Rebuild function boundaries so the decompiler can produce correct pseudocode

### 2. Re-scan newly recovered code for obfuscated strings

After converting data regions to code (step 1 above), additional decrypt function call sites may become visible that were previously hidden in undefined data. A **two-pass workflow** would:

- Run the code recovery pass first
- Re-scan the entire `.text` section for new `call` instructions targeting known decrypt functions
- Apply the string deobfuscator to any newly discovered call sites

### 3. Dead branch elimination in CFF-flattened functions

`lumma_fix_cff.py` resolves the CFF dispatcher into direct jumps, but the resulting control flow graph still contains **unreachable branches** — switch cases that are never dispatched. These dead paths clutter the decompiler output. A future improvement would:

- Perform reachability analysis on the patched CFG to identify branches with no incoming edges
- Gray out or NOP-fill unreachable basic blocks
- Allow the decompiler to produce cleaner, more readable pseudocode

### 4. Generalize for Lumma Stealer variants

The current tools are tuned to a single sample. To support other Lumma Stealer builds and versions:

- **Auto-detect decrypt algorithm parameters**: Instead of relying on `KNOWN_DECRYPT_FUNCTIONS` with hardcoded `(xor_key, add_value, loop_count)` tuples, improve the MBA pattern recognition engine to algebraically solve arbitrary MBA expressions (e.g., generalized `((x << N) & MASK) - (x ^ CONST)` → `x + ADD`) without manual analysis
- **Auto-detect image base and section layout**: Remove hardcoded `IMAGE_BASE`, `TEXT_VA`, and stack frame assumptions; derive them from the PE header at runtime
- **Handle relocated samples**: Support ASLR-rebased binaries where absolute addresses differ from the on-disk PE
- **Version-specific algorithm tables**: Lumma Stealer evolves across versions — maintain a registry of known algorithm signatures that can be matched against new samples, while falling back to heuristic detection for unknown variants
