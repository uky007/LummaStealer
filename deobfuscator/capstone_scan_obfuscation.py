"""
capstone_scan_obfuscation.py - Offline obfuscation pattern scanner using Capstone

Scans the Lumma Stealer payload's .text section for remaining code obfuscation
patterns that need to be addressed for clean IDA Pro decompilation.

Detected patterns:
  1. Opaque predicates (always-true/false conditional branches)
  2. Junk instruction pairs (identity operations)
  3. CFF dispatchers (mov reg,[reg+reg*4]; jmp reg)
  4. Indirect jumps (FF 25 - jmp [mem])
  5. Dead code after unconditional jumps (no incoming refs heuristic)
  6. Anti-disassembly tricks (junk bytes after jmp/call reg)

Usage:
    python3 capstone_scan_obfuscation.py
"""

import struct
import json
import os
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import *

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_PATH = os.path.join(SCRIPT_DIR, "sample",
    "de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874_payload.exe")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "obfuscation_scan_results.json")

if not os.path.exists(PAYLOAD_PATH):
    print(f"[!] Payload not found: {PAYLOAD_PATH}")
    print(f"[!] Download the sample from MalwareBazaar (SHA256: de67d471...) and")
    print(f"[!] extract the payload PE, then set PAYLOAD_PATH to its location.")
    raise SystemExit(1)

IMAGE_BASE = 0x02800000
TEXT_VA     = 0x02801000
TEXT_OFFSET = 0x400
TEXT_SIZE   = 0x4E200

DATA_VA_START = 0x02852000
DATA_VA_END   = 0x02856000

# ============================================================================
# Load binary and disassemble
# ============================================================================

def load_text_section():
    with open(PAYLOAD_PATH, "rb") as f:
        pe_data = f.read()
    text_bytes = pe_data[TEXT_OFFSET:TEXT_OFFSET + TEXT_SIZE]
    return pe_data, text_bytes


def disassemble_linear(text_bytes, base_va):
    """Linear sweep disassembly of entire .text section."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(text_bytes, base_va))
    return insns


def build_insn_index(insns):
    """Build addr -> index mapping for fast lookup."""
    addr_to_idx = {}
    for i, insn in enumerate(insns):
        addr_to_idx[insn.address] = i
    return addr_to_idx


# ============================================================================
# Pattern 1: Opaque Predicates
# ============================================================================

def scan_opaque_predicates(insns, addr_to_idx):
    """
    Detect opaque predicates - conditional branches that always/never fire.

    Patterns:
      A) xor reg,reg → jnz/jne (never taken) or jz/je (always taken)
      B) sub reg,reg → same as xor reg,reg
      C) test reg,reg right after xor reg,reg → same
      D) or reg,0xFFFFFFFF → jz (never) or jnz (always)
      E) and reg,0 → jnz (never) or jz (always)
      F) cmp reg,reg (same) → jne (never) or je (always)
      G) push imm; pop reg; cmp reg,imm; jne (never)
      H) mov reg,imm; cmp reg,same_imm; jne (never)
    """
    results = []
    JCC_MNEMS = {
        'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe',
        'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno',
        'jp', 'jnp',
    }

    for i in range(len(insns) - 1):
        a = insns[i]
        b = insns[i + 1]

        # --- Pattern A/B: xor/sub reg,reg → jcc ---
        if a.mnemonic in ('xor', 'sub') and len(a.operands) == 2:
            op0, op1 = a.operands[0], a.operands[1]
            if (op0.type == X86_OP_REG and op1.type == X86_OP_REG
                    and op0.reg == op1.reg):
                # reg is now 0, ZF=1, SF=0, OF=0, CF=0
                # Check if next is jcc
                target_b = b
                target_idx = i + 1
                # Could have test reg,reg in between
                if (b.mnemonic == 'test' and len(b.operands) == 2
                        and b.operands[0].type == X86_OP_REG
                        and b.operands[1].type == X86_OP_REG
                        and b.operands[0].reg == op0.reg
                        and b.operands[1].reg == op0.reg):
                    if i + 2 < len(insns):
                        target_b = insns[i + 2]
                        target_idx = i + 2

                if target_b.mnemonic in JCC_MNEMS:
                    always = None
                    if target_b.mnemonic in ('jne', 'jnz', 'ja', 'jb', 'js', 'jo'):
                        always = 'never_taken'
                    elif target_b.mnemonic in ('je', 'jz', 'jae', 'jbe', 'jns', 'jno'):
                        always = 'always_taken'
                    if always:
                        results.append({
                            'type': 'opaque_pred',
                            'subtype': f'{a.mnemonic}_reg_reg',
                            'ea': a.address,
                            'jcc_ea': target_b.address,
                            'jcc_mnem': target_b.mnemonic,
                            'jcc_target': target_b.operands[0].imm if target_b.operands else 0,
                            'behavior': always,
                            'setup': f'{a.mnemonic} {a.op_str}',
                            'size': (target_b.address + target_b.size) - a.address,
                        })

        # --- Pattern E: and reg, 0 → jcc ---
        if a.mnemonic == 'and' and len(a.operands) == 2:
            op0, op1 = a.operands[0], a.operands[1]
            if op0.type == X86_OP_REG and op1.type == X86_OP_IMM and op1.imm == 0:
                if b.mnemonic in JCC_MNEMS:
                    always = None
                    if b.mnemonic in ('jnz', 'jne', 'ja', 'js'):
                        always = 'never_taken'
                    elif b.mnemonic in ('jz', 'je', 'jbe', 'jns'):
                        always = 'always_taken'
                    if always:
                        results.append({
                            'type': 'opaque_pred',
                            'subtype': 'and_zero',
                            'ea': a.address,
                            'jcc_ea': b.address,
                            'jcc_mnem': b.mnemonic,
                            'jcc_target': b.operands[0].imm if b.operands else 0,
                            'behavior': always,
                            'setup': f'{a.mnemonic} {a.op_str}',
                            'size': (b.address + b.size) - a.address,
                        })

        # --- Pattern F: cmp reg, reg (same) → jcc ---
        if a.mnemonic == 'cmp' and len(a.operands) == 2:
            op0, op1 = a.operands[0], a.operands[1]
            if (op0.type == X86_OP_REG and op1.type == X86_OP_REG
                    and op0.reg == op1.reg):
                if b.mnemonic in JCC_MNEMS:
                    always = None
                    if b.mnemonic in ('jne', 'jnz', 'ja', 'jb', 'js', 'jo'):
                        always = 'never_taken'
                    elif b.mnemonic in ('je', 'jz', 'jae', 'jbe', 'jns', 'jno'):
                        always = 'always_taken'
                    if always:
                        results.append({
                            'type': 'opaque_pred',
                            'subtype': 'cmp_reg_reg',
                            'ea': a.address,
                            'jcc_ea': b.address,
                            'jcc_mnem': b.mnemonic,
                            'jcc_target': b.operands[0].imm if b.operands else 0,
                            'behavior': always,
                            'setup': f'{a.mnemonic} {a.op_str}',
                            'size': (b.address + b.size) - a.address,
                        })

        # --- Pattern H: mov reg, imm; cmp reg, same_imm → jcc ---
        if a.mnemonic == 'mov' and len(a.operands) == 2 and i + 2 < len(insns):
            op0, op1 = a.operands[0], a.operands[1]
            if op0.type == X86_OP_REG and op1.type == X86_OP_IMM:
                c = insns[i + 2]
                if (b.mnemonic == 'cmp' and len(b.operands) == 2
                        and b.operands[0].type == X86_OP_REG
                        and b.operands[0].reg == op0.reg
                        and b.operands[1].type == X86_OP_IMM
                        and (b.operands[1].imm & 0xFFFFFFFF) == (op1.imm & 0xFFFFFFFF)):
                    if c.mnemonic in JCC_MNEMS:
                        always = None
                        if c.mnemonic in ('jne', 'jnz', 'ja', 'jb'):
                            always = 'never_taken'
                        elif c.mnemonic in ('je', 'jz', 'jae', 'jbe'):
                            always = 'always_taken'
                        if always:
                            results.append({
                                'type': 'opaque_pred',
                                'subtype': 'mov_cmp_imm',
                                'ea': a.address,
                                'jcc_ea': c.address,
                                'jcc_mnem': c.mnemonic,
                                'jcc_target': c.operands[0].imm if c.operands else 0,
                                'behavior': always,
                                'setup': f'{a.mnemonic} {a.op_str}; {b.mnemonic} {b.op_str}',
                                'size': (c.address + c.size) - a.address,
                            })

    return results


# ============================================================================
# Pattern 2: Junk Instruction Pairs
# ============================================================================

def scan_junk_pairs(insns, addr_to_idx):
    """
    Detect junk instruction pairs that have no net effect.

    Patterns:
      1. push reg; pop reg (same register)
      2. mov reg, reg (same src/dst)
      3. add reg, imm; sub reg, imm (and reverse)
      4. xor reg, imm; xor reg, imm (self-canceling)
      5. not reg; not reg
      6. neg reg; neg reg
      7. ror reg, N; rol reg, N (and reverse)
      8. inc reg; dec reg (and reverse)
      9. stc; clc and clc; stc
     10. bswap reg; bswap reg
     11. lea reg, [reg+0] or lea reg, [reg]
     12. pushfd; popfd (no flag-modifying insn between)
    """
    results = []

    for i in range(len(insns)):
        a = insns[i]

        # --- Pattern 11: lea reg, [reg+0] (single instruction NOP) ---
        if a.mnemonic == 'lea' and len(a.operands) == 2:
            op0, op1 = a.operands[0], a.operands[1]
            if op0.type == X86_OP_REG and op1.type == X86_OP_MEM:
                mem = op1.mem
                if (mem.base == op0.reg and mem.index == 0
                        and mem.disp == 0 and mem.scale <= 1):
                    results.append({
                        'type': 'junk',
                        'subtype': 'lea_nop',
                        'ea': a.address,
                        'size': a.size,
                        'desc': f'lea {a.op_str}',
                    })

        if i + 1 >= len(insns):
            continue

        b = insns[i + 1]

        # --- Pattern 1: push reg; pop reg ---
        if a.mnemonic == 'push' and b.mnemonic == 'pop':
            if (len(a.operands) == 1 and len(b.operands) == 1
                    and a.operands[0].type == X86_OP_REG
                    and b.operands[0].type == X86_OP_REG
                    and a.operands[0].reg == b.operands[0].reg):
                results.append({
                    'type': 'junk',
                    'subtype': 'push_pop',
                    'ea': a.address,
                    'size': a.size + b.size,
                    'desc': f'push {a.op_str}; pop {b.op_str}',
                })

        # --- Pattern 2: mov reg, reg (same) ---
        if a.mnemonic == 'mov' and len(a.operands) == 2:
            op0, op1 = a.operands[0], a.operands[1]
            if (op0.type == X86_OP_REG and op1.type == X86_OP_REG
                    and op0.reg == op1.reg):
                results.append({
                    'type': 'junk',
                    'subtype': 'mov_self',
                    'ea': a.address,
                    'size': a.size,
                    'desc': f'mov {a.op_str}',
                })

        # --- Pattern 3: add/sub canceling ---
        if a.mnemonic in ('add', 'sub') and b.mnemonic in ('add', 'sub'):
            if a.mnemonic != b.mnemonic:  # add+sub or sub+add
                if (len(a.operands) == 2 and len(b.operands) == 2
                        and a.operands[0].type == X86_OP_REG
                        and b.operands[0].type == X86_OP_REG
                        and a.operands[0].reg == b.operands[0].reg
                        and a.operands[1].type == X86_OP_IMM
                        and b.operands[1].type == X86_OP_IMM
                        and (a.operands[1].imm & 0xFFFFFFFF) == (b.operands[1].imm & 0xFFFFFFFF)):
                    results.append({
                        'type': 'junk',
                        'subtype': f'{a.mnemonic}_{b.mnemonic}',
                        'ea': a.address,
                        'size': a.size + b.size,
                        'desc': f'{a.mnemonic} {a.op_str}; {b.mnemonic} {b.op_str}',
                    })

        # --- Pattern 4: xor reg,imm; xor reg,imm ---
        if a.mnemonic == 'xor' and b.mnemonic == 'xor':
            if (len(a.operands) == 2 and len(b.operands) == 2
                    and a.operands[0].type == X86_OP_REG
                    and b.operands[0].type == X86_OP_REG
                    and a.operands[0].reg == b.operands[0].reg
                    and a.operands[1].type == X86_OP_IMM
                    and b.operands[1].type == X86_OP_IMM
                    and (a.operands[1].imm & 0xFFFFFFFF) == (b.operands[1].imm & 0xFFFFFFFF)):
                # Exclude xor reg,reg (that's zero-setting, not junk)
                if a.operands[1].type == X86_OP_IMM:
                    results.append({
                        'type': 'junk',
                        'subtype': 'xor_xor',
                        'ea': a.address,
                        'size': a.size + b.size,
                        'desc': f'xor {a.op_str}; xor {b.op_str}',
                    })

        # --- Pattern 5: not reg; not reg ---
        if a.mnemonic == 'not' and b.mnemonic == 'not':
            if (len(a.operands) == 1 and len(b.operands) == 1
                    and a.operands[0].type == X86_OP_REG
                    and b.operands[0].type == X86_OP_REG
                    and a.operands[0].reg == b.operands[0].reg):
                results.append({
                    'type': 'junk',
                    'subtype': 'not_not',
                    'ea': a.address,
                    'size': a.size + b.size,
                    'desc': f'not {a.op_str}; not {b.op_str}',
                })

        # --- Pattern 6: neg reg; neg reg ---
        if a.mnemonic == 'neg' and b.mnemonic == 'neg':
            if (len(a.operands) == 1 and len(b.operands) == 1
                    and a.operands[0].type == X86_OP_REG
                    and b.operands[0].type == X86_OP_REG
                    and a.operands[0].reg == b.operands[0].reg):
                results.append({
                    'type': 'junk',
                    'subtype': 'neg_neg',
                    'ea': a.address,
                    'size': a.size + b.size,
                    'desc': f'neg {a.op_str}; neg {b.op_str}',
                })

        # --- Pattern 7: ror/rol canceling ---
        if a.mnemonic in ('ror', 'rol') and b.mnemonic in ('ror', 'rol'):
            if a.mnemonic != b.mnemonic:  # ror+rol or rol+ror
                if (len(a.operands) == 2 and len(b.operands) == 2
                        and a.operands[0].type == X86_OP_REG
                        and b.operands[0].type == X86_OP_REG
                        and a.operands[0].reg == b.operands[0].reg
                        and a.operands[1].type == X86_OP_IMM
                        and b.operands[1].type == X86_OP_IMM
                        and a.operands[1].imm == b.operands[1].imm):
                    results.append({
                        'type': 'junk',
                        'subtype': f'{a.mnemonic}_{b.mnemonic}',
                        'ea': a.address,
                        'size': a.size + b.size,
                        'desc': f'{a.mnemonic} {a.op_str}; {b.mnemonic} {b.op_str}',
                    })

        # --- Pattern 8: inc/dec canceling ---
        if a.mnemonic in ('inc', 'dec') and b.mnemonic in ('inc', 'dec'):
            if a.mnemonic != b.mnemonic:
                if (len(a.operands) == 1 and len(b.operands) == 1
                        and a.operands[0].type == X86_OP_REG
                        and b.operands[0].type == X86_OP_REG
                        and a.operands[0].reg == b.operands[0].reg):
                    results.append({
                        'type': 'junk',
                        'subtype': f'{a.mnemonic}_{b.mnemonic}',
                        'ea': a.address,
                        'size': a.size + b.size,
                        'desc': f'{a.mnemonic} {a.op_str}; {b.mnemonic} {b.op_str}',
                    })

        # --- Pattern 9: stc;clc / clc;stc ---
        if (a.mnemonic == 'stc' and b.mnemonic == 'clc') or \
           (a.mnemonic == 'clc' and b.mnemonic == 'stc'):
            results.append({
                'type': 'junk',
                'subtype': f'{a.mnemonic}_{b.mnemonic}',
                'ea': a.address,
                'size': a.size + b.size,
                'desc': f'{a.mnemonic}; {b.mnemonic}',
            })

        # --- Pattern 10: bswap reg; bswap reg ---
        if a.mnemonic == 'bswap' and b.mnemonic == 'bswap':
            if (len(a.operands) == 1 and len(b.operands) == 1
                    and a.operands[0].type == X86_OP_REG
                    and b.operands[0].type == X86_OP_REG
                    and a.operands[0].reg == b.operands[0].reg):
                results.append({
                    'type': 'junk',
                    'subtype': 'bswap_bswap',
                    'ea': a.address,
                    'size': a.size + b.size,
                    'desc': f'bswap {a.op_str}; bswap {b.op_str}',
                })

        # --- Pattern 12: pushfd; popfd ---
        if a.mnemonic == 'pushfd' and b.mnemonic == 'popfd':
            results.append({
                'type': 'junk',
                'subtype': 'pushfd_popfd',
                'ea': a.address,
                'size': a.size + b.size,
                'desc': 'pushfd; popfd',
            })

    return results


# ============================================================================
# Pattern 3: CFF Dispatchers
# ============================================================================

def scan_cff_dispatchers(text_bytes, base_va):
    """
    Raw byte scan for CFF dispatcher pattern:
        8B [ModRM: mod=00, rm=100] [SIB: scale=10, base!=5]
        FF [E0+reg]
    = mov reg, [reg+reg*4]; jmp reg  (5 bytes)
    """
    results = []
    for i in range(len(text_bytes) - 5):
        if text_bytes[i] != 0x8B:
            continue

        modrm = text_bytes[i + 1]
        mod = (modrm >> 6) & 3
        dest_reg = (modrm >> 3) & 7
        rm = modrm & 7

        if mod != 0 or rm != 4:
            continue

        sib = text_bytes[i + 2]
        scale = (sib >> 6) & 3
        index_reg = (sib >> 3) & 7
        base_reg = sib & 7

        if scale != 2 or base_reg == 5:
            continue

        if text_bytes[i + 3] != 0xFF or text_bytes[i + 4] != (0xE0 + dest_reg):
            continue

        ea = base_va + i
        reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

        # Look for constant-index init before
        has_const = False
        const_val = -1
        for back in range(11, 45):
            if i < back:
                break
            ci = i - back
            if (text_bytes[ci] == 0xC7 and text_bytes[ci + 1] == 0x84
                    and text_bytes[ci + 2] == 0x24):
                imm = struct.unpack_from('<I', text_bytes, ci + 7)[0]
                if imm <= 16:
                    has_const = True
                    const_val = imm
                    break

        # Check if already NOPed
        is_nopped = all(text_bytes[i + j] == 0x90 for j in range(5))

        results.append({
            'type': 'cff_dispatcher',
            'ea': ea,
            'dest_reg': reg_names[dest_reg],
            'base_reg': reg_names[base_reg],
            'index_reg': reg_names[index_reg],
            'has_const_init': has_const,
            'const_value': const_val,
            'is_nopped': is_nopped,
        })

    return results


# ============================================================================
# Pattern 4: Indirect Jumps (FF 25)
# ============================================================================

def scan_indirect_jumps(text_bytes, base_va):
    """
    Scan for jmp [dword_ptr] (FF 25 xx xx xx xx) targeting .data section.
    """
    results = []
    for i in range(len(text_bytes) - 6):
        if text_bytes[i] != 0xFF or text_bytes[i + 1] != 0x25:
            continue

        target_mem = struct.unpack_from('<I', text_bytes, i + 2)[0]
        ea = base_va + i

        # Check if target is in .data
        in_data = DATA_VA_START <= target_mem < DATA_VA_END

        # Check if already patched (E9 at this location in original)
        is_patched = False  # Can't tell from raw bytes alone

        results.append({
            'type': 'indirect_jmp',
            'ea': ea,
            'target_mem': target_mem,
            'in_data': in_data,
        })

    return results


# ============================================================================
# Pattern 5: Suspicious Instruction Sequences
# ============================================================================

def scan_suspicious_sequences(insns, addr_to_idx):
    """
    Detect longer suspicious patterns:
      - MBA (Mixed Boolean-Arithmetic) expressions used for obfuscation
        (beyond what's used for string decryption)
      - Unusual instruction sequences that look like obfuscation glue
    """
    results = []

    # Detect sequences of bitwise ops that could be MBA identity transforms
    # e.g., ((x & m) << 1) + ((x | ~m) - (x & m)) = x + 1 (obfuscated increment)
    # Look for: and, or, xor, not, shl, shr, add, sub in dense clusters

    BITWISE_MNEMS = {'and', 'or', 'xor', 'not', 'shl', 'shr', 'sar', 'sal',
                     'rol', 'ror', 'neg', 'bswap'}
    ARITH_MNEMS = {'add', 'sub', 'imul', 'lea'}
    MBA_MNEMS = BITWISE_MNEMS | ARITH_MNEMS

    window = 8  # Look for clusters of 8+ MBA ops within 12 instructions
    threshold = 6

    for i in range(len(insns) - window):
        mba_count = 0
        for j in range(min(window + 4, len(insns) - i)):
            if insns[i + j].mnemonic in MBA_MNEMS:
                mba_count += 1

        if mba_count >= threshold:
            # Check this isn't a string decryption function (those are expected)
            # Heuristic: if there's a loop (backward jump), might be decrypt
            has_back_jmp = False
            for j in range(min(20, len(insns) - i)):
                ins = insns[i + j]
                if ins.mnemonic.startswith('j') and ins.mnemonic != 'jmp':
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        target = ins.operands[0].imm
                        if target < ins.address:
                            has_back_jmp = True
                            break

            results.append({
                'type': 'mba_cluster',
                'ea': insns[i].address,
                'mba_count': mba_count,
                'has_loop': has_back_jmp,
                'first_few': '; '.join(f'{insns[i+j].mnemonic} {insns[i+j].op_str}'
                                       for j in range(min(6, len(insns) - i))),
            })

    # Deduplicate overlapping MBA clusters (keep only first in each group)
    if results:
        deduped = [results[0]]
        for r in results[1:]:
            if r['ea'] - deduped[-1]['ea'] >= 20:
                deduped.append(r)
        results = deduped

    return results


# ============================================================================
# Pattern 6: NOP sleds and alignment padding
# ============================================================================

def scan_nop_regions(text_bytes, base_va):
    """
    Find large NOP (0x90) regions that might indicate already-patched areas
    or alignment padding.
    """
    results = []
    i = 0
    while i < len(text_bytes):
        if text_bytes[i] == 0x90:
            start = i
            while i < len(text_bytes) and text_bytes[i] == 0x90:
                i += 1
            count = i - start
            if count >= 5:  # Only report 5+ NOPs
                results.append({
                    'type': 'nop_region',
                    'ea': base_va + start,
                    'size': count,
                })
        else:
            i += 1

    return results


# ============================================================================
# Pattern 7: jmp/call reg followed by suspicious bytes
# ============================================================================

def scan_jmp_call_reg(text_bytes, base_va, insns, addr_to_idx):
    """
    Find jmp reg / call reg followed by bytes that don't decode as valid code.
    These are anti-disassembly tricks.
    """
    results = []

    for i in range(len(text_bytes) - 2):
        b0 = text_bytes[i]
        b1 = text_bytes[i + 1]

        is_jmp_reg = (b0 == 0xFF and 0xE0 <= b1 <= 0xE7)
        is_call_reg = (b0 == 0xFF and 0xD0 <= b1 <= 0xD7)

        if not (is_jmp_reg or is_call_reg):
            continue

        ea = base_va + i
        next_ea = ea + 2

        # Skip CFF dispatchers (already handled)
        if is_jmp_reg and i >= 3:
            if text_bytes[i - 3] == 0x8B:
                modrm = text_bytes[i - 2]
                if (modrm >> 6) & 3 == 0 and modrm & 7 == 4:
                    continue

        # Check if bytes after are valid code by trying to decode 5+ instructions
        md_check = Cs(CS_ARCH_X86, CS_MODE_32)
        after_bytes = text_bytes[i + 2:i + 2 + 50]
        decoded = list(md_check.disasm(after_bytes, next_ea))

        if len(decoded) < 3:
            results.append({
                'type': 'anti_disasm',
                'subtype': 'jmp_reg' if is_jmp_reg else 'call_reg',
                'ea': ea,
                'next_ea': next_ea,
                'decoded_after': len(decoded),
                'reg_idx': b1 & 7,
            })

    return results


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("Lumma Stealer Offline Obfuscation Pattern Scanner")
    print("=" * 70)

    print(f"\n[*] Loading {PAYLOAD_PATH}")
    pe_data, text_bytes = load_text_section()
    print(f"    .text: {len(text_bytes)} bytes (0x{TEXT_VA:08X} - 0x{TEXT_VA + TEXT_SIZE:08X})")

    print(f"\n[*] Disassembling .text with Capstone (linear sweep)...")
    insns = disassemble_linear(text_bytes, TEXT_VA)
    print(f"    Decoded {len(insns)} instructions")

    addr_to_idx = build_insn_index(insns)

    all_results = {}

    # --- Scan 1: Opaque Predicates ---
    print(f"\n[1/7] Scanning for opaque predicates...")
    opaque = scan_opaque_predicates(insns, addr_to_idx)
    all_results['opaque_predicates'] = opaque
    if opaque:
        subtypes = Counter(r['subtype'] for r in opaque)
        behaviors = Counter(r['behavior'] for r in opaque)
        print(f"    Found: {len(opaque)}")
        for st, cnt in subtypes.most_common():
            print(f"      {st}: {cnt}")
        for bh, cnt in behaviors.most_common():
            print(f"      {bh}: {cnt}")
    else:
        print(f"    Found: 0")

    # --- Scan 2: Junk Pairs ---
    print(f"\n[2/7] Scanning for junk instruction pairs...")
    junk = scan_junk_pairs(insns, addr_to_idx)
    all_results['junk_pairs'] = junk
    if junk:
        subtypes = Counter(r['subtype'] for r in junk)
        print(f"    Found: {len(junk)}")
        for st, cnt in subtypes.most_common():
            print(f"      {st}: {cnt}")
    else:
        print(f"    Found: 0")

    # --- Scan 3: CFF Dispatchers ---
    print(f"\n[3/7] Scanning for CFF dispatchers...")
    cff = scan_cff_dispatchers(text_bytes, TEXT_VA)
    all_results['cff_dispatchers'] = cff
    nopped = sum(1 for r in cff if r['is_nopped'])
    const = sum(1 for r in cff if r['has_const_init'])
    print(f"    Found: {len(cff)} ({const} const-index, {nopped} already NOPed)")

    # Cluster CFF dispatchers
    if cff:
        sorted_cff = sorted(cff, key=lambda d: d['ea'])
        clusters = [[sorted_cff[0]]]
        for d in sorted_cff[1:]:
            if d['ea'] - clusters[-1][-1]['ea'] < 0x1000:
                clusters[-1].append(d)
            else:
                clusters.append([d])
        cff_clusters = [c for c in clusters if len(c) >= 5]
        print(f"    CFF clusters: {len(cff_clusters)}")
        for ci, cluster in enumerate(cff_clusters):
            cc = sum(1 for d in cluster if d['has_const_init'])
            nn = sum(1 for d in cluster if d['is_nopped'])
            print(f"      Cluster {ci}: 0x{cluster[0]['ea']:08X}-0x{cluster[-1]['ea']:08X} "
                  f"({len(cluster)} dispatchers, {cc} const, {nn} NOPed)")

    # --- Scan 4: Indirect Jumps ---
    print(f"\n[4/7] Scanning for indirect jumps (FF 25)...")
    indirect = scan_indirect_jumps(text_bytes, TEXT_VA)
    all_results['indirect_jumps'] = indirect
    in_data = sum(1 for r in indirect if r['in_data'])
    print(f"    Found: {len(indirect)} ({in_data} targeting .data)")

    # --- Scan 5: MBA Clusters ---
    print(f"\n[5/7] Scanning for MBA expression clusters...")
    mba = scan_suspicious_sequences(insns, addr_to_idx)
    all_results['mba_clusters'] = mba
    with_loop = sum(1 for r in mba if r['has_loop'])
    without_loop = len(mba) - with_loop
    print(f"    Found: {len(mba)} ({with_loop} with loops [likely decrypt], "
          f"{without_loop} without loops [likely obfuscation])")

    # --- Scan 6: NOP Regions ---
    print(f"\n[6/7] Scanning for NOP regions...")
    nops = scan_nop_regions(text_bytes, TEXT_VA)
    all_results['nop_regions'] = nops
    total_nop_bytes = sum(r['size'] for r in nops)
    large_nops = [r for r in nops if r['size'] >= 20]
    print(f"    Found: {len(nops)} regions ({total_nop_bytes} bytes total, "
          f"{len(large_nops)} regions >= 20 bytes)")

    # --- Scan 7: Anti-disassembly ---
    print(f"\n[7/7] Scanning for anti-disassembly tricks...")
    anti = scan_jmp_call_reg(text_bytes, TEXT_VA, insns, addr_to_idx)
    all_results['anti_disasm'] = anti
    print(f"    Found: {len(anti)}")

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    total = sum(len(v) for v in all_results.values())
    print(f"  Total patterns detected:     {total}")
    print(f"  Opaque predicates:           {len(opaque)}")
    print(f"  Junk instruction pairs:      {len(junk)}")
    print(f"  CFF dispatchers:             {len(cff)}")
    print(f"  Indirect jumps (FF 25):      {len(indirect)}")
    print(f"  MBA clusters:                {len(mba)}")
    print(f"  NOP regions:                 {len(nops)}")
    print(f"  Anti-disassembly:            {len(anti)}")
    print(f"{'=' * 70}")

    # --- Priority recommendations ---
    print(f"\n[*] RECOMMENDATIONS FOR IDA DECOMPILATION:")
    if indirect and in_data > 0:
        print(f"  [HIGH] {in_data} indirect jumps → .data: run lumma_fix_code_obfuscation.py")
    if cff and nopped < len(cff):
        print(f"  [HIGH] {len(cff) - nopped} un-NOPed CFF dispatchers: run lumma_fix_cff.py")
    if opaque:
        print(f"  [HIGH] {len(opaque)} opaque predicates: need new script to remove")
    if junk:
        print(f"  [MED]  {len(junk)} junk pairs: extend Phase C in lumma_code_deobfuscator.py")
    if mba and without_loop > 0:
        print(f"  [LOW]  {without_loop} non-loop MBA clusters: review for obfuscation")

    # --- Export results ---
    # Convert addresses to hex strings for JSON
    export = {}
    for key, items in all_results.items():
        export[key] = []
        for item in items:
            entry = {}
            for k, v in item.items():
                if isinstance(v, int) and k in ('ea', 'jcc_ea', 'jcc_target',
                                                  'next_ea', 'target_mem'):
                    entry[k] = f"0x{v:08X}"
                else:
                    entry[k] = v
            export[key].append(entry)

    export['summary'] = {
        'total_instructions': len(insns),
        'opaque_predicates': len(opaque),
        'junk_pairs': len(junk),
        'cff_dispatchers': len(cff),
        'indirect_jumps': len(indirect),
        'mba_clusters': len(mba),
        'nop_regions': len(nops),
        'anti_disasm': len(anti),
    }

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(export, f, indent=2)

    print(f"\n[*] Full results saved to: {OUTPUT_FILE}")

    return all_results


if __name__ == "__main__":
    main()
