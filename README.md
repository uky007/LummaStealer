# Lumma Stealer Deobfuscator

IDA Pro Python scripts for deobfuscating [Lumma Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma) (a.k.a. LummaC2), an information-stealing malware.

## Target Sample

We unpacked the Lumma Stealer sample from a Go-based loader, then deobfuscated the unpacked Lumma Stealer payload.

| Property | Value |
|----------|-------|
| SHA-256 |  `de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874` |
| Malware | Go-based Loader |
| Build Date | Jan 14 2026 |
| Architecture | x86_64 |


| Property | Value |
|----------|-------|
| SHA-256 |  `37fc0dc17d6168506a7584654495b5a77d915981e9a0fda2e17f8b219c4415eb`|
| Malware | Lumma Stealer (LummaC2) |
| Build Date | Jan 14 2026 |
| Architecture | x86 |

## Deobfuscation Results

### String & Data Deobfuscation

**610 call sites** processed across **460 unique decrypt functions**, with a **100% success rate** (0 extraction failures, 0 decryption failures).

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

10 distinct decryption algorithms (MBA-obfuscated XOR/ADD operations) were identified and implemented.

### Code Deobfuscation

| Technique | Count | Tool |
|-----------|------:|------|
| Indirect jumps (FF 25 → E9) | 288 | `lumma_fix_code_obfuscation.py` |
| CFF dispatchers (contiguous) | 399 | `lumma_fix_cff_v2.py` |
| CFF dispatchers (split) | 74 | `lumma_fix_cff_v2.py` |
| Zeroed switch tables | 7 | `fix_zeroed_switches.py` |
| jmp/call reg code recovery | 12 | `lumma_code_deobfuscator.py` (Phase A) |
| Dead code removal | 1170 | `lumma_code_deobfuscator.py` (Phase D) |
| Junk instruction pairs | 16 | `lumma_code_deobfuscator.py` (Phase C) |

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

## Scripts

### IDA Pro Scripts (run in order)

| # | Script | Description |
|---|--------|-------------|
| 1 | `lumma_fix_code_obfuscation.py` | Patches `jmp [dword_XXXXXXXX]` indirect jumps (FF 25 → E9 direct). Restores IDA code flow analysis across ~288 sites. |
| 2 | `lumma_fix_cff_v2.py` | Patches CFF (Control Flow Flattening) dispatchers. Handles both contiguous (`mov reg,[reg+reg*4]; jmp reg`) and split patterns. ~467 dispatchers across 4 clusters. |
| 3 | `fix_zeroed_switches.py` | Fixes 7 zeroed switch tables that cause "switch analysis failed" in Hex-Rays. Patches each to jump to default case. |
| 4 | `lumma_code_deobfuscator.py` | Multi-phase cleanup: (A) jmp/call reg code recovery, (B) data-to-code in CFF regions, (C) junk instruction removal, (D) dead code elimination. |
| 5 | `lumma_deobfuscator.py` | Main string/data deobfuscator. Identifies 460 decrypt functions, extracts encrypted stack data, decrypts with 10 MBA algorithm types, annotates IDA comments. |
| 6 | `lumma_apply_layer2.py` | Writes Layer 2 decoded results back to IDA comments. |

### Standalone Scripts

| Script | Description |
|--------|-------------|
| `lumma_layer2_decoder.py` | Applies second-layer decoding to double-encrypted entries. |
| `capstone_scan_obfuscation.py` | Offline Capstone-based scanner that detects obfuscation patterns without IDA. |

## Usage

### Recommended execution order in IDA Pro

```
1. lumma_fix_code_obfuscation.py   # Fix indirect jumps (FF 25 → E9)
2. lumma_fix_cff_v2.py             # Fix CFF dispatchers (NOP sequences)
3. fix_zeroed_switches.py          # Fix zeroed switch tables
4. lumma_code_deobfuscator.py      # Cleanup: jmp reg, junk, dead code
5. lumma_deobfuscator.py           # Decrypt strings and data
6. lumma_layer2_decoder.py         # (standalone) Decode Layer 2 entries
7. lumma_apply_layer2.py           # Apply Layer 2 to IDA comments
```

Each script is run via **File > Script file** in IDA Pro (except standalone scripts which run with Python 3).

All scripts provide `revert_*()` functions to undo patches. Note that `revert_all_patches()` in script 4 reverts ALL byte patches from all scripts.

## CFF Obfuscation Analysis

The binary uses a CFF variant where each conditional branch is replaced by a table-based dispatch:

```
[setcc reg]                       ; compute branch condition (0/1)
mov [esp+INDEX_OFF], reg          ; store as index
mov REG_A, [esp+TABLE_OFF]       ; load jump table pointer
mov REG_B, [esp+INDEX_OFF]       ; load index
mov REG_A, [REG_A+REG_B*4]      ; dereference table[index]
jmp REG_A                        ; dispatch
```

Each dispatcher has its own table/index pair on the stack (not a shared state variable). 85 dispatchers use constant indices (always jump to the same target), 126 use `setcc`-based indices (obfuscated conditional branches), and ~250 use computed indices.

The fix strategy NOPs the entire setup+dispatch sequence (avg 21.4 bytes per dispatcher), allowing code to fall through. This is viable because 98% of dispatchers have valid code immediately after them.

## Results

The `results/` directory contains analysis outputs in JSON format:

| File | Description |
|------|-------------|
| `deobf_results.json` | All 610 decrypted strings, binary data, GUIDs, DWORDs, and shellcode with addresses, algorithm types, and decrypted values. |
| `obfuscation_scan_results.json` | Capstone offline scan results: 467 CFF dispatchers, 288 indirect jumps, 16 junk pairs, 346 MBA clusters, and anti-disassembly patterns. |
| `cff_cluster3_resolved.json` | Resolved CFF dispatcher targets for Cluster 3 (181/228 dispatchers, with jump table entries and setcc types). |
| `cff_cluster2_resolved.json` | Resolved CFF dispatcher targets for Cluster 2 (63/94 dispatchers). |

## Future Work

- **MBA expression simplification**: 346 MBA expression clusters remain in the binary. These produce correct but complex pseudocode in Hex-Rays. A simplification pass could reduce `((x & m) | (~x & ~m)) + k` back to `x ^ m + k`.
- **Generalize for Lumma variants**: Auto-detect algorithm parameters, section layout, and version-specific patterns for other builds.
- **Layer 2 low-confidence entries**: 8 decoded entries with confidence < 0.60 need IDA runtime verification.
- **Cross-cluster CFF flow tracing**: Enumerate all inter-cluster jumps and trace register values to resolve remaining Cluster 0/1 dispatchers. See `CFF_CROSS_CLUSTER_ANALYSIS.md` for details.
