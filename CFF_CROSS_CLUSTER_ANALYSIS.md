# CFF Cross-Cluster Structure Analysis

**Date**: 2026-03-21
**Analysts**: uky + Claude Opus 4.6

---

## Summary

The 4 CFF clusters (Cluster 0-3) are not independent functions but **parts of a single large CFF-protected function**. CFF control flow jumps between clusters, carrying register values across boundaries.

This discovery resolves why the Cluster 0/1 table entries are not valid .text addresses.

---

## Background

### Initial Observation

When reading CFF dispatcher jump tables from the .data section:

| Cluster | Table Address | Entry Contents |
|---------|--------------|----------------|
| Cluster 0 | 0x028530F0 | 0x2B882412, 0xBD8EA00A... (not valid addresses) |
| Cluster 1 | 0x028532D0 | 0x62AFA4D9, 0x5B3B48EC... (not valid addresses) |
| Cluster 2 | 0x02854600- | 0x0281E64A, 0x0281E678... (**valid .text addresses**) |
| Cluster 3 | 0x028547E0 | 0x0281D188, 0x0281D284... (**valid .text addresses**) |

Cluster 2/3 tables could be read directly, but Cluster 0/1 were assumed to be "encrypted."

### Hypotheses Tested and Rejected

| Hypothesis | Verification Method | Result |
|------------|-------------------|--------|
| Table XOR/ADD encrypted | Brute-force key search | No valid key found |
| Loader decrypts tables | WriteProcessMemory dump comparison | Tables identical (unchanged) |
| Entry point decrypts | Unicorn 100K instruction emulation | Zero writes to table region |
| .reloc fixes up entries | Relocation analysis | Zero relocations in .data |
| Decode instructions exist | Scan mov-jmp gap for eax modification | No eax modification found |
| Dead code (never called) | Cross-reference analysis | **Has callers (rejected)** |

All hypotheses were rejected.

---

## Resolution: Cross-Cluster Jumps

### Decisive Evidence

IDA xref analysis revealed an external reference to `0x02827467` (inside Cluster 0):

```
.text:0284040B    jmp     loc_2827467     ; Cluster 3 → Cluster 0 jump
.text:02840410    nop                      ; (NOP padding from CFF patch)
.text:02840411    nop
```

Address `0x0284040B` is within **Cluster 3's range** (0x0283A9CE-0x02840A69).

### Actual Control Flow

```
┌──────────────────────────────────────────────────┐
│ Cluster 3 code                                    │
│   ... sets eax to a valid .text address ...        │
│   0x0284040B: jmp loc_2827467                      │
└──────────────────────┬─────────────────────────────┘
                       │ eax = valid .text address
                       ▼
┌──────────────────────────────────────────────────┐
│ Cluster 0 table initialization code               │
│   0x02827467: mov [esp+X], offset unk_28530F0     │
│   0x02827472: mov [esp+X], 0Ch                    │
│   ... (70+ mov [esp+X], imm instructions) ...     │
│   ※ eax is NEVER modified                         │
│   0x028276B9: jmp eax  ← jumps using Cluster 3's  │
│                           valid eax value!         │
└──────────────────────────────────────────────────┘
```

### Why Linear Analysis Failed

In linear code flow (sequential execution from function entry):

```
0x028272B9: sub esp, 0x348          ; function prologue
...
0x028273F3: mov eax, [esp+0x2b0]    ; eax = 4 (index)
0x028273FA: mov ecx, [esp+0x2b4]    ; ecx = 0x028530F0 (table)
0x02827401: mov eax, [ecx+eax*4]    ; eax = table[4] = 0xBD8EA00A ★ INVALID!
0x02827404: mov [esp+X], ...        ; table init begins
...                                  ; 70+ instructions (eax unchanged)
0x028276B9: jmp eax                 ; jmp 0xBD8EA00A → crash?
```

However, in the actual CFF control flow, `0x02827467` is reached via a `jmp` from Cluster 3.
At that point, eax holds a **valid address** set by Cluster 3's dispatcher resolution.

### True Role of Table at 0x028530F0

The table entries (0x2B882412, 0xBD8EA00A, etc.) are **NOT jump targets**.

Table initialization code structure:
```
mov [esp+0x2b4], 0x028530F0    ; table base pointer
mov [esp+0x2b0], 4              ; parameter
...
mov [esp+0x2a4], 0x028530F0    ; another pair
mov [esp+0x2a0], 6              ; another parameter
...
```

These (pointer, integer) pairs are **CFF routing table configuration data**.
Each pair corresponds to one CFF dispatcher, encoding "this dispatcher should use table X at index Y."

The `mov eax, [ecx+eax*4]` at `0x02827401` reads a value as part of the initial setup,
but that value is overwritten by cross-cluster jumps before `jmp eax` executes.

---

## Overall CFF Structure

### Relationship Between 4 Clusters

```
                    ┌──────────────┐
                    │  Cluster 0   │
                    │ 0x028272B9-  │
              ┌────→│ 0x02828921   │←────┐
              │     └──────────────┘     │
              │                           │
  ┌──────────────┐                 ┌──────────────┐
  │  Cluster 1   │                 │  Cluster 3   │
  │ 0x0282A3C0-  │                 │ 0x0283A9CE-  │
  │ 0x0282DF72   │                 │ 0x02840A69   │
  └──────────────┘                 └──────────────┘
              │                           │
              │     ┌──────────────┐     │
              └────→│  Cluster 2   │←────┘
                    │ 0x02835C40-  │
                    │ 0x02836F5D   │
                    └──────────────┘
```

Confirmed links (from resolved dispatcher targets + binary scan):

| Source → Destination | Count | Type |
|---------------------|-------|------|
| Cluster 3 → Cluster 1 | 141 | CFF dispatchers (conditional + unconditional) |
| Cluster 3 → Cluster 0 | 7 | CFF dispatchers (unconditional) |
| Cluster 2 → Cluster 3 | 2 | E9 jmp (original binary) |
| Cluster 3 → Cluster 0 | 1 | E8 call (0x0283C7E1 → 0x02828830) |

Cluster 3 acts as the **hub** of the CFF structure, with 141 jumps into Cluster 1.
This explains why Cluster 1's table entries appear "encrypted" — its code is primarily
reached via Cluster 3 dispatchers, not through Cluster 1's own table lookups.

### The "Giant CFF Function"

| Attribute | Value |
|-----------|-------|
| Function entry | 0x028272B9 (Cluster 0) |
| Full range | 0x028272B9 - 0x02840A69 |
| Total size | 0x197B0 = 104,368 bytes (~102KB) |
| Dispatcher count | 467 (all clusters combined) |
| Table types | 2: plaintext (Cluster 2/3) and routing data (Cluster 0/1) |

---

## Analysis Methodology Summary

### What Worked

1. **Capstone static scan**: Detected all 467 dispatchers (contiguous + split)
2. **Plaintext table reading**: Resolved 244/322 dispatchers from Cluster 2/3 tables
3. **jcc/jmp rewriting**: Restored if/else branch structure (itoa, wtoa, etc.)
4. **IDA xref analysis**: Discovered cross-cluster jumps that explained "encrypted" tables

### What Was Difficult

1. **Cluster 0/1 table interpretation**: Linear analysis showed invalid values; actual CFF flow provides valid ones
2. **Cross-cluster structure discovery**: Only revealed through IDA xref after exhaustive hypothesis testing
3. **"Encrypted table" hypothesis**: Required 5 different verification methods to reject, leading to the correct structural explanation

### Future Improvement Path

To resolve remaining Cluster 0/1 dispatchers:
1. Enumerate all cross-cluster jumps (Cluster 3 → 0, 0 → 1, etc.)
2. Track eax values at each jump point using Unicorn emulation
3. Reconstruct the full CFF control flow graph

---

## File References

| File | Description |
|------|-------------|
| `cff_cluster3_resolved.json` | Resolved Cluster 3 dispatchers (181/228) |
| `cff_cluster2_resolved.json` | Resolved Cluster 2 dispatchers (63/94) |
| `obfuscation_scan_results.json` | Capstone scan results (all dispatchers) |
| `dbg_dump/` | WriteProcessMemory dumps (loader verification) |
| `LOADER_ANALYSIS.md` (parent directory) | Go loader analysis report |
