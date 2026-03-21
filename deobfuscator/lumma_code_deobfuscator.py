"""
lumma_code_deobfuscator.py - IDA Python Script
Comprehensive code deobfuscation for Lumma Stealer.

Resolves anti-disassembly patterns and removes junk code to enable
correct decompilation (Hex-Rays F5).

Run AFTER:
    1. lumma_fix_code_obfuscation.py  (FF 25 indirect jumps)
    2. lumma_fix_cff_v2.py            (CFF dispatchers)
    3. fix_zeroed_switches.py         (zeroed switch tables)

Phases:
    A - jmp reg / call reg code recovery (hidden code becomes visible)
    B - Data-to-code conversion in CFF cluster regions
    C - Junk code detection and NOP-out (cleaner pseudocode)
    D - Dead code after unconditional jumps (unreachable code removal)

Usage in IDA:
    File -> Script file -> lumma_code_deobfuscator.py

    Or from the Python console:
        exec(open("lumma_code_deobfuscator.py").read())

    Individual phases:
        fix_code_obfuscation(phases="A")       # Phase A only
        fix_code_obfuscation(phases="CD")       # Phases C+D only
        fix_code_obfuscation(dry_run=True)      # Preview all phases
        fix_code_obfuscation()                  # Run all phases

    Scan-only functions:
        scan_jmp_reg()                          # Phase A scan
        scan_data_in_cff_regions()              # Phase B scan
        scan_junk_patterns()                    # Phase C scan
        scan_dead_code()                        # Phase D scan
        revert_all_patches()                    # Undo everything
"""

import struct
import json
import os
import datetime
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_auto
import ida_ua
import ida_segment
import ida_xref

# Output directory (same as script location)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUTPUT_FILE = os.path.join(SCRIPT_DIR, 'code_deobfuscation_results.json')
DEBUG_FILE = os.path.join(SCRIPT_DIR, 'debug_diagnostics.json')


# ============================================================================
# Configuration
# ============================================================================

# Minimum valid instructions to consider a block as code
MIN_VALID_INSNS = 5

# Maximum bytes to scan for code block end
MAX_CODE_SCAN = 0x2000

# Maximum bytes to scan for junk sequences
MAX_JUNK_SCAN = 128

# Mnemonics that indicate invalid/rare instructions (not expected in normal code)
INVALID_MNEMS = frozenset({
    'ljmp', 'into', 'out', 'in', 'hlt', 'popfd', 'insd',
    'insb', 'outsb', 'outsd', 'lds', 'les', 'bound',
    'arpl', 'daa', 'das', 'aaa', 'aas', 'aam', 'aad',
    'icebp', 'salc',
})

# Mnemonics that serve as proper block terminators
TERMINATOR_MNEMS = frozenset({'ret', 'retn', 'jmp', 'call', 'int'})

# Mnemonics indicating recognizable code-start patterns
CODE_START_MNEMS = frozenset({
    'push', 'mov', 'sub', 'lea', 'xor', 'and', 'or', 'cmp', 'test',
    'add', 'shl', 'shr', 'sar', 'sal', 'not', 'neg', 'inc', 'dec',
    'movzx', 'movsx', 'cdq', 'nop',
})


# ============================================================================
# Helpers
# ============================================================================

def _get_text_seg():
    """Get .text segment bounds."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        print("[!] .text segment not found")
        return None, None
    return seg.start_ea, seg.end_ea


def _count_valid_insns(ea, max_count):
    """Decode up to max_count instructions at ea, return valid count."""
    count = 0
    cur = ea
    for _ in range(max_count):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, cur)
        if size == 0:
            break
        mnem = insn.get_canon_mnem()
        if mnem in INVALID_MNEMS:
            break
        count += 1
        cur += size
    return count


def _has_terminator(ea, max_insns=50):
    """Check if decoded instructions eventually reach a terminator."""
    cur = ea
    for _ in range(max_insns):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, cur)
        if size == 0:
            return False
        mnem = insn.get_canon_mnem()
        if mnem in TERMINATOR_MNEMS:
            return True
        cur += size
    return False


def _is_cff_dispatcher_at(ea):
    """
    Check if ea is part of a CFF dispatcher pattern:
        mov reg, [reg+reg*4]; jmp reg  (5 bytes)
    Returns True if ea falls within such a pattern.
    """
    # Check at ea and ea-1, ea-2, ea-3, ea-4 for the 5-byte pattern start
    for offset in range(5):
        check = ea - offset
        if check < 0:
            continue
        b0 = ida_bytes.get_byte(check)
        if b0 != 0x8B:
            continue
        b1 = ida_bytes.get_byte(check + 1)
        mod = (b1 >> 6) & 3
        rm = b1 & 7
        if mod != 0 or rm != 4:
            continue
        b2 = ida_bytes.get_byte(check + 2)
        scale = (b2 >> 6) & 3
        base_reg = b2 & 7
        if scale != 2 or base_reg == 5:
            continue
        dest_reg = (b1 >> 3) & 7
        b3 = ida_bytes.get_byte(check + 3)
        b4 = ida_bytes.get_byte(check + 4)
        if b3 == 0xFF and b4 == (0xE0 + dest_reg):
            return True
    return False


def _nop_range(start_ea, end_ea):
    """NOP out a range of bytes. Returns count of actually changed bytes."""
    count = 0
    for ea in range(start_ea, end_ea):
        if ida_bytes.get_byte(ea) != 0x90:
            ida_bytes.patch_byte(ea, 0x90)
            count += 1
    return count


def _recreate_as_code(start_ea, end_ea):
    """Delete data items and create instructions in a range."""
    if end_ea <= start_ea:
        return 0
    ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, end_ea - start_ea)
    ea = start_ea
    created = 0
    while ea < end_ea:
        size = idc.create_insn(ea)
        if size == 0:
            ea += 1
        else:
            created += 1
            ea += size
    return created


def _make_code_range(start_ea, max_size=MAX_CODE_SCAN):
    """
    Delete data items and create code instructions from start_ea.
    Returns the end address of the created code block.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return start_ea
    end_scan = min(start_ea + max_size, seg_end)

    # Find extent of non-code bytes
    data_end = start_ea
    while data_end < end_scan:
        flags = ida_bytes.get_full_flags(data_end)
        if ida_bytes.is_code(flags):
            break
        next_head = idc.next_head(data_end, end_scan)
        if next_head == idaapi.BADADDR:
            data_end = end_scan
            break
        data_end = next_head

    # Delete data items
    if data_end > start_ea:
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, data_end - start_ea)

    # Create instructions
    ea = start_ea
    code_end = start_ea
    while ea < end_scan:
        size = idc.create_insn(ea)
        if size == 0:
            break
        code_end = ea + size
        ea += size
    return code_end


def _fix_function_boundary(func_start, new_code_start, new_code_end):
    """Ensure new code block is part of the function."""
    func = ida_funcs.get_func(func_start)
    if not func:
        return False

    # Already within function
    if func.contains(new_code_start):
        return True

    # Try append_func_tail
    if ida_funcs.append_func_tail(func, new_code_start, new_code_end):
        return True

    # Try extending function end
    if new_code_start <= func.end_ea + 0x100:
        if ida_funcs.set_func_end(func_start, max(func.end_ea, new_code_end)):
            return True

    # Force reanalysis
    ida_auto.plan_range(func_start, new_code_end)
    return True


def _get_switch_info(ea):
    """Get switch_info_t for ea. Compatible with IDA 7.x and 9.x."""
    try:
        si = idaapi.get_switch_info(ea)  # IDA 9.x: returns switch_info_t or None
        return si
    except TypeError:
        si = idaapi.switch_info_t()      # IDA 7.x: takes (si, ea), returns bool
        if idaapi.get_switch_info(si, ea):
            return si
        return None


def _has_xrefs_to(ea):
    """Check if any code cross-references point to ea."""
    for _ in idautils.CodeRefsTo(ea, 0):
        return True
    for _ in idautils.CodeRefsTo(ea, 1):
        return True
    # Also check data refs (e.g., from jump tables)
    for _ in idautils.DataRefsTo(ea):
        return True
    return False


# ============================================================================
# Phase A: jmp reg / call reg Code Recovery
# ============================================================================

def scan_jmp_reg():
    """
    Find all `jmp reg` / `call reg` in .text where bytes immediately after
    are classified as data but decode as valid x86 instructions.

    Excludes CFF dispatcher patterns (handled by lumma_fix_cff.py).

    Returns list of dicts with ea, next_ea, opcode_type, reg, func_start, valid_insns.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return []

    results = []
    ea = seg_start

    while ea < seg_end - 2:
        b0 = ida_bytes.get_byte(ea)

        # FF E0-FF E7: jmp eax..edi
        # FF D0-FF D7: call eax..edi
        if b0 != 0xFF:
            ea += 1
            continue

        b1 = ida_bytes.get_byte(ea + 1)

        if 0xE0 <= b1 <= 0xE7:
            optype = 'jmp'
            reg_idx = b1 - 0xE0
        elif 0xD0 <= b1 <= 0xD7:
            optype = 'call'
            reg_idx = b1 - 0xD0
        else:
            ea += 1
            continue

        reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        reg_name = reg_names[reg_idx]
        next_ea = ea + 2

        # Skip if this is part of a CFF dispatcher
        if _is_cff_dispatcher_at(ea):
            ea += 2
            continue

        # Check if the bytes after are NOT code
        next_flags = ida_bytes.get_full_flags(next_ea)
        if ida_bytes.is_code(next_flags):
            ea += 2
            continue

        # Validate: try decoding bytes after as x86 instructions
        valid_count = _count_valid_insns(next_ea, MIN_VALID_INSNS + 10)
        if valid_count < MIN_VALID_INSNS:
            ea += 2
            continue

        # Additional heuristic: first instruction should look like code start
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, next_ea)
        if size > 0:
            first_mnem = insn.get_canon_mnem()
            # Reject if first instruction is rare/suspicious
            if first_mnem in INVALID_MNEMS:
                ea += 2
                continue

        # Check that we eventually reach a terminator
        if not _has_terminator(next_ea, max_insns=80):
            ea += 2
            continue

        func = ida_funcs.get_func(ea)
        func_start = func.start_ea if func else 0

        results.append({
            'ea': ea,
            'next_ea': next_ea,
            'optype': optype,
            'reg': reg_name,
            'func_start': func_start,
            'valid_insns': valid_count,
        })

        ea += 2

    return results


def fix_jmp_reg_code_recovery(sites=None, dry_run=False):
    """
    Phase A: Convert data after jmp reg / call reg to code.

    Args:
        sites: List from scan_jmp_reg(), or None to scan automatically.
        dry_run: Preview only.

    Returns: list of fixed sites.
    """
    if sites is None:
        sites = scan_jmp_reg()

    print(f"\n[Phase A] jmp reg / call reg code recovery")
    print(f"  Found: {len(sites)} sites with hidden code after jmp/call reg")

    if not sites:
        return sites

    # Print details
    print(f"\n  {'Address':>12} {'Type':>5} {'Reg':>4} {'NextAddr':>12} {'FuncStart':>12} {'Insns':>5}")
    print(f"  {'-'*12} {'-'*5} {'-'*4} {'-'*12} {'-'*12} {'-'*5}")
    for s in sites:
        func_str = f"0x{s['func_start']:08X}" if s['func_start'] else "   (none)   "
        print(f"  0x{s['ea']:08X} {s['optype']:>5} {s['reg']:>4} "
              f"0x{s['next_ea']:08X} {func_str} {s['valid_insns']:5}")

    if dry_run:
        return sites

    # Fix each site
    fixed = 0
    for s in sites:
        next_ea = s['next_ea']

        # Check if already code now
        flags = ida_bytes.get_full_flags(next_ea)
        if ida_bytes.is_code(flags):
            fixed += 1
            continue

        code_end = _make_code_range(next_ea)
        if code_end > next_ea:
            fixed += 1
            # Fix function boundary
            if s['func_start']:
                _fix_function_boundary(s['func_start'], next_ea, code_end)

    print(f"  Fixed: {fixed}/{len(sites)} sites")
    ida_auto.auto_wait()
    return sites


# ============================================================================
# Phase B: Data-to-Code Conversion in CFF Regions
# ============================================================================

def _find_cff_cluster_ranges():
    """
    Find CFF cluster address ranges by scanning for dispatcher patterns.
    Returns list of (cluster_start, cluster_end) tuples.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return []

    # Find all CFF dispatcher locations
    dispatchers = []
    ea = seg_start
    while ea < seg_end - 5:
        b0 = ida_bytes.get_byte(ea)
        if b0 != 0x8B:
            ea += 1
            continue
        b1 = ida_bytes.get_byte(ea + 1)
        mod = (b1 >> 6) & 3
        rm = b1 & 7
        if mod != 0 or rm != 4:
            ea += 1
            continue
        b2 = ida_bytes.get_byte(ea + 2)
        scale = (b2 >> 6) & 3
        base_reg = b2 & 7
        if scale != 2 or base_reg == 5:
            ea += 1
            continue
        dest_reg = (b1 >> 3) & 7
        b3 = ida_bytes.get_byte(ea + 3)
        b4 = ida_bytes.get_byte(ea + 4)
        if b3 == 0xFF and b4 == (0xE0 + dest_reg):
            dispatchers.append(ea)
            ea += 5
        else:
            ea += 1

    if not dispatchers:
        return []

    # Cluster by proximity (MAX_CLUSTER_GAP = 0x1000)
    MAX_CLUSTER_GAP = 0x1000
    MIN_CLUSTER_SIZE = 5
    clusters = [[dispatchers[0]]]
    for d in dispatchers[1:]:
        if d - clusters[-1][-1] < MAX_CLUSTER_GAP:
            clusters[-1].append(d)
        else:
            clusters.append([d])

    # Filter to CFF-size clusters and return ranges with padding
    ranges = []
    for c in clusters:
        if len(c) >= MIN_CLUSTER_SIZE:
            # Extend range by 0x100 on each side
            start = c[0] - 0x100
            end = c[-1] + 0x100
            if start < seg_start:
                start = seg_start
            if end > seg_end:
                end = seg_end
            ranges.append((start, end))

    return ranges


def scan_data_in_cff_regions():
    """
    Scan CFF cluster regions for bytes classified as data that could be code.

    Returns list of dicts with ea, valid_insns, cluster_idx.
    """
    ranges = _find_cff_cluster_ranges()
    if not ranges:
        print("  No CFF cluster ranges found")
        return []

    results = []
    for idx, (rng_start, rng_end) in enumerate(ranges):
        ea = rng_start
        while ea < rng_end:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(flags):
                next_h = idc.next_head(ea, rng_end)
                if next_h == idaapi.BADADDR:
                    break
                ea = next_h
                continue

            # Non-code byte found - try to decode
            valid = _count_valid_insns(ea, MIN_VALID_INSNS + 5)
            if valid >= MIN_VALID_INSNS:
                results.append({
                    'ea': ea,
                    'valid_insns': valid,
                    'cluster_idx': idx,
                })
                # Skip past this block to avoid double-counting
                cur = ea
                for _ in range(valid):
                    insn = ida_ua.insn_t()
                    size = ida_ua.decode_insn(insn, cur)
                    if size == 0:
                        break
                    cur += size
                ea = cur
                continue

            # Not valid - advance byte by byte
            ea += 1

    return results


def fix_data_in_cff_regions(sites=None, dry_run=False):
    """
    Phase B: Convert data blocks in CFF regions to code.

    Args:
        sites: List from scan_data_in_cff_regions(), or None to scan.
        dry_run: Preview only.

    Returns: list of converted sites.
    """
    if sites is None:
        sites = scan_data_in_cff_regions()

    ranges = _find_cff_cluster_ranges()

    print(f"\n[Phase B] Data-to-code conversion in CFF regions")
    print(f"  CFF cluster ranges: {len(ranges)}")
    for i, (s, e) in enumerate(ranges):
        print(f"    Cluster {i}: 0x{s:08X} - 0x{e:08X} ({e - s:#x} bytes)")
    print(f"  Data blocks found: {len(sites)}")

    if not sites:
        return sites

    # Print first 20
    shown = min(len(sites), 20)
    print(f"\n  First {shown} sites:")
    print(f"  {'Address':>12} {'Cluster':>7} {'Insns':>5}")
    print(f"  {'-'*12} {'-'*7} {'-'*5}")
    for s in sites[:shown]:
        print(f"  0x{s['ea']:08X} {s['cluster_idx']:>7} {s['valid_insns']:>5}")
    if len(sites) > shown:
        print(f"  ... and {len(sites) - shown} more")

    if dry_run:
        return sites

    # Convert each site
    converted = 0
    for s in sites:
        ea = s['ea']
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            converted += 1
            continue

        code_end = _make_code_range(ea, max_size=0x200)
        if code_end > ea:
            converted += 1

    print(f"  Converted: {converted}/{len(sites)} data blocks")
    ida_auto.auto_wait()

    # Fix function boundaries for all CFF clusters
    fixed_funcs = 0
    for rng_start, rng_end in ranges:
        # Find functions that overlap this range
        func = ida_funcs.get_func(rng_start)
        if func:
            ida_auto.plan_range(func.start_ea, max(func.end_ea, rng_end))
            fixed_funcs += 1
    if fixed_funcs:
        ida_auto.auto_wait()
    print(f"  Functions reanalyzed: {fixed_funcs}")

    return sites


# ============================================================================
# Phase C: Junk Code Detection and Removal
# ============================================================================

def _get_reg_from_opcode(insn):
    """Extract register index from instruction operand 0."""
    op = insn.ops[0]
    if op.type == idc.o_reg:
        return op.reg
    return -1


def _get_all_function_eas():
    """Get start addresses of all functions in .text."""
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return []
    func_eas = []
    ea = seg_start
    while ea < seg_end:
        func = ida_funcs.get_func(ea)
        if func and func.start_ea == ea:
            func_eas.append(ea)
        ea = idc.next_func(ea)
        if ea == idaapi.BADADDR:
            break
    return func_eas


def scan_junk_patterns():
    """
    Scan all functions in .text for junk instruction patterns:
      1. push reg; pop reg (same register)
      2. mov reg, reg (same source and dest)
      3. add reg, imm; sub reg, imm (self-canceling, same imm)
      4. xor reg, imm; xor reg, imm (self-canceling, same imm)

    Returns list of dicts with ea, pattern, size, description.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return []

    results = []
    reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

    # Walk through all code in .text
    ea = seg_start
    while ea < seg_end:
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            next_h = idc.next_head(ea, seg_end)
            if next_h == idaapi.BADADDR:
                break
            ea = next_h
            continue

        insn1 = ida_ua.insn_t()
        size1 = ida_ua.decode_insn(insn1, ea)
        if size1 == 0:
            ea += 1
            continue

        mnem1 = insn1.get_canon_mnem()
        ea2 = ea + size1

        # --- Pattern 1: push reg; pop reg (same register) ---
        # push reg = 50+reg (1 byte), pop reg = 58+reg (1 byte)
        if mnem1 == 'push' and insn1.ops[0].type == idc.o_reg:
            reg1 = insn1.ops[0].reg
            insn2 = ida_ua.insn_t()
            size2 = ida_ua.decode_insn(insn2, ea2)
            if size2 > 0:
                mnem2 = insn2.get_canon_mnem()
                if mnem2 == 'pop' and insn2.ops[0].type == idc.o_reg:
                    reg2 = insn2.ops[0].reg
                    if reg1 == reg2:
                        total_size = size1 + size2
                        # Verify no xrefs to middle
                        if not _has_xrefs_to(ea2):
                            rname = reg_names[reg1] if reg1 < len(reg_names) else f"r{reg1}"
                            results.append({
                                'ea': ea,
                                'pattern': 'push_pop',
                                'size': total_size,
                                'desc': f"push {rname}; pop {rname}",
                            })
                            ea = ea2 + size2
                            continue

        # --- Pattern 2: mov reg, reg (same source and dest) ---
        if mnem1 == 'mov' and size1 == 2:
            op0 = insn1.ops[0]
            op1 = insn1.ops[1]
            if op0.type == idc.o_reg and op1.type == idc.o_reg:
                if op0.reg == op1.reg:
                    rname = reg_names[op0.reg] if op0.reg < len(reg_names) else f"r{op0.reg}"
                    results.append({
                        'ea': ea,
                        'pattern': 'mov_self',
                        'size': size1,
                        'desc': f"mov {rname}, {rname}",
                    })
                    ea = ea2
                    continue

        # --- Pattern 3: add reg, imm; sub reg, imm (same reg, same imm) ---
        if mnem1 == 'add' and insn1.ops[0].type == idc.o_reg and \
           insn1.ops[1].type in (idc.o_imm, ):
            reg1 = insn1.ops[0].reg
            imm1 = insn1.ops[1].value & 0xFFFFFFFF
            insn2 = ida_ua.insn_t()
            size2 = ida_ua.decode_insn(insn2, ea2)
            if size2 > 0:
                mnem2 = insn2.get_canon_mnem()
                if mnem2 == 'sub' and insn2.ops[0].type == idc.o_reg and \
                   insn2.ops[1].type in (idc.o_imm, ):
                    reg2 = insn2.ops[0].reg
                    imm2 = insn2.ops[1].value & 0xFFFFFFFF
                    if reg1 == reg2 and imm1 == imm2:
                        total_size = size1 + size2
                        if not _has_xrefs_to(ea2):
                            rname = reg_names[reg1] if reg1 < len(reg_names) else f"r{reg1}"
                            results.append({
                                'ea': ea,
                                'pattern': 'add_sub',
                                'size': total_size,
                                'desc': f"add {rname}, 0x{imm1:X}; sub {rname}, 0x{imm1:X}",
                            })
                            ea = ea2 + size2
                            continue

        # Also check sub reg, imm; add reg, imm (reverse order)
        if mnem1 == 'sub' and insn1.ops[0].type == idc.o_reg and \
           insn1.ops[1].type in (idc.o_imm, ):
            reg1 = insn1.ops[0].reg
            imm1 = insn1.ops[1].value & 0xFFFFFFFF
            insn2 = ida_ua.insn_t()
            size2 = ida_ua.decode_insn(insn2, ea2)
            if size2 > 0:
                mnem2 = insn2.get_canon_mnem()
                if mnem2 == 'add' and insn2.ops[0].type == idc.o_reg and \
                   insn2.ops[1].type in (idc.o_imm, ):
                    reg2 = insn2.ops[0].reg
                    imm2 = insn2.ops[1].value & 0xFFFFFFFF
                    if reg1 == reg2 and imm1 == imm2:
                        total_size = size1 + size2
                        if not _has_xrefs_to(ea2):
                            rname = reg_names[reg1] if reg1 < len(reg_names) else f"r{reg1}"
                            results.append({
                                'ea': ea,
                                'pattern': 'sub_add',
                                'size': total_size,
                                'desc': f"sub {rname}, 0x{imm1:X}; add {rname}, 0x{imm1:X}",
                            })
                            ea = ea2 + size2
                            continue

        # --- Pattern 4: xor reg, imm; xor reg, imm (same reg, same imm) ---
        if mnem1 == 'xor' and insn1.ops[0].type == idc.o_reg and \
           insn1.ops[1].type in (idc.o_imm, ):
            reg1 = insn1.ops[0].reg
            imm1 = insn1.ops[1].value & 0xFFFFFFFF
            insn2 = ida_ua.insn_t()
            size2 = ida_ua.decode_insn(insn2, ea2)
            if size2 > 0:
                mnem2 = insn2.get_canon_mnem()
                if mnem2 == 'xor' and insn2.ops[0].type == idc.o_reg and \
                   insn2.ops[1].type in (idc.o_imm, ):
                    reg2 = insn2.ops[0].reg
                    imm2 = insn2.ops[1].value & 0xFFFFFFFF
                    if reg1 == reg2 and imm1 == imm2:
                        total_size = size1 + size2
                        if not _has_xrefs_to(ea2):
                            rname = reg_names[reg1] if reg1 < len(reg_names) else f"r{reg1}"
                            results.append({
                                'ea': ea,
                                'pattern': 'xor_xor',
                                'size': total_size,
                                'desc': f"xor {rname}, 0x{imm1:X}; xor {rname}, 0x{imm1:X}",
                            })
                            ea = ea2 + size2
                            continue

        # --- Pattern 5: inc reg; dec reg  /  dec reg; inc reg ---
        if mnem1 in ('inc', 'dec') and insn1.ops[0].type == idc.o_reg:
            reg1 = insn1.ops[0].reg
            insn2 = ida_ua.insn_t()
            size2 = ida_ua.decode_insn(insn2, ea2)
            if size2 > 0:
                mnem2 = insn2.get_canon_mnem()
                if mnem2 in ('inc', 'dec') and mnem2 != mnem1:
                    if insn2.ops[0].type == idc.o_reg and insn2.ops[0].reg == reg1:
                        total_size = size1 + size2
                        if not _has_xrefs_to(ea2):
                            rname = reg_names[reg1] if reg1 < len(reg_names) else f"r{reg1}"
                            results.append({
                                'ea': ea,
                                'pattern': f'{mnem1}_{mnem2}',
                                'size': total_size,
                                'desc': f"{mnem1} {rname}; {mnem2} {rname}",
                            })
                            ea = ea2 + size2
                            continue

        ea = ea2

    return results


def fix_junk_patterns(sites=None, dry_run=False):
    """
    Phase C: NOP out junk instruction patterns.

    Args:
        sites: List from scan_junk_patterns(), or None to scan.
        dry_run: Preview only.

    Returns: list of junk sites found.
    """
    if sites is None:
        sites = scan_junk_patterns()

    print(f"\n[Phase C] Junk code detection and removal")
    print(f"  Found: {len(sites)} junk patterns")

    if not sites:
        return sites

    # Summarize by pattern type
    from collections import Counter
    pattern_counts = Counter(s['pattern'] for s in sites)
    for pat, cnt in sorted(pattern_counts.items()):
        print(f"    {pat}: {cnt}")

    # Print first 20 examples
    shown = min(len(sites), 20)
    print(f"\n  First {shown} examples:")
    print(f"  {'Address':>12} {'Pattern':>10} {'Size':>4} Description")
    print(f"  {'-'*12} {'-'*10} {'-'*4} {'-'*40}")
    for s in sites[:shown]:
        print(f"  0x{s['ea']:08X} {s['pattern']:>10} {s['size']:>4} {s['desc']}")
    if len(sites) > shown:
        print(f"  ... and {len(sites) - shown} more")

    if dry_run:
        return sites

    # NOP out each junk pattern
    nopped_bytes = 0
    nopped_count = 0
    for s in sites:
        n = _nop_range(s['ea'], s['ea'] + s['size'])
        if n > 0:
            nopped_bytes += n
            nopped_count += 1
            # Re-create as NOP instructions
            _recreate_as_code(s['ea'], s['ea'] + s['size'])

    print(f"  NOPed: {nopped_count} patterns ({nopped_bytes} bytes)")
    ida_auto.auto_wait()

    return sites


# ============================================================================
# Phase D: Dead Code After Unconditional Jumps
# ============================================================================

def scan_dead_code():
    """
    Find code after unconditional jmp / ret that has no incoming xrefs.

    Returns list of dicts with ea (start of dead code), end_ea, size, after_insn.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return []

    results = []

    ea = seg_start
    while ea < seg_end:
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            next_h = idc.next_head(ea, seg_end)
            if next_h == idaapi.BADADDR:
                break
            ea = next_h
            continue

        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size == 0:
            ea += 1
            continue

        mnem = insn.get_canon_mnem()

        # Check for unconditional jump or return
        is_uncond_jmp = False
        if mnem == 'jmp':
            # Only unconditional jmp (not conditional jcc)
            is_uncond_jmp = True
        elif mnem in ('ret', 'retn'):
            is_uncond_jmp = True

        if not is_uncond_jmp:
            ea += size
            continue

        next_ea = ea + size

        # Check if next address is code
        if next_ea >= seg_end:
            break

        next_flags = ida_bytes.get_full_flags(next_ea)
        if not ida_bytes.is_code(next_flags):
            ea += size
            continue

        # Check if next address has NO incoming xrefs
        if _has_xrefs_to(next_ea):
            ea += size
            continue

        # Scan forward to find where xrefs resume (= end of dead code)
        dead_start = next_ea
        dead_end = next_ea
        scan_ea = next_ea
        max_dead = min(next_ea + MAX_JUNK_SCAN, seg_end)

        while scan_ea < max_dead:
            scan_flags = ida_bytes.get_full_flags(scan_ea)
            if not ida_bytes.is_code(scan_flags):
                break

            if scan_ea > dead_start and _has_xrefs_to(scan_ea):
                break

            # Advance to next instruction
            scan_insn = ida_ua.insn_t()
            scan_size = ida_ua.decode_insn(scan_insn, scan_ea)
            if scan_size == 0:
                break

            dead_end = scan_ea + scan_size
            scan_ea += scan_size

        dead_size = dead_end - dead_start
        if dead_size > 0 and dead_size <= MAX_JUNK_SCAN:
            results.append({
                'ea': dead_start,
                'end_ea': dead_end,
                'size': dead_size,
                'after_insn': mnem,
                'after_ea': ea,
            })

        ea = dead_end if dead_end > ea + size else ea + size

    return results


def fix_dead_code(sites=None, dry_run=False):
    """
    Phase D: NOP out dead code after unconditional jumps/returns.

    Args:
        sites: List from scan_dead_code(), or None to scan.
        dry_run: Preview only.

    Returns: list of dead code sites found.
    """
    if sites is None:
        sites = scan_dead_code()

    print(f"\n[Phase D] Dead code after unconditional jumps")
    print(f"  Found: {len(sites)} dead code blocks")

    if not sites:
        return sites

    # Summarize
    total_bytes = sum(s['size'] for s in sites)
    after_jmp = sum(1 for s in sites if s['after_insn'] == 'jmp')
    after_ret = sum(1 for s in sites if s['after_insn'] in ('ret', 'retn'))
    print(f"    After jmp: {after_jmp}")
    print(f"    After ret/retn: {after_ret}")
    print(f"    Total dead bytes: {total_bytes}")

    # Print first 20
    shown = min(len(sites), 20)
    print(f"\n  First {shown} sites:")
    print(f"  {'DeadStart':>12} {'DeadEnd':>12} {'Size':>5} {'After':>5}")
    print(f"  {'-'*12} {'-'*12} {'-'*5} {'-'*5}")
    for s in sites[:shown]:
        print(f"  0x{s['ea']:08X} 0x{s['end_ea']:08X} {s['size']:>5} {s['after_insn']:>5}")
    if len(sites) > shown:
        print(f"  ... and {len(sites) - shown} more")

    if dry_run:
        return sites

    # NOP out dead code
    nopped_bytes = 0
    nopped_count = 0
    for s in sites:
        n = _nop_range(s['ea'], s['end_ea'])
        if n > 0:
            nopped_bytes += n
            nopped_count += 1
            _recreate_as_code(s['ea'], s['end_ea'])

    print(f"  NOPed: {nopped_count} dead blocks ({nopped_bytes} bytes)")
    ida_auto.auto_wait()

    return sites


# ============================================================================
# Switch Table Fix
# ============================================================================

def diagnose_switch(switch_ea, output_path=None):
    """
    Diagnose a switch jump and dump the jump table contents.
    Also attempts to detect ncases from the preceding cmp instruction.

    Usage in IDA:
        diagnose_switch(0x0280484C)
    """
    if output_path is None:
        output_path = DEBUG_FILE

    report = {
        'target': f"0x{switch_ea:08X}",
        'timestamp': datetime.datetime.now().isoformat(),
        'type': 'switch_diagnosis',
    }

    # Decode the switch jmp instruction
    insn = ida_ua.insn_t()
    insn_size = ida_ua.decode_insn(insn, switch_ea)
    raw_bytes = [ida_bytes.get_byte(switch_ea + i) for i in range(max(insn_size, 8))]
    report['instruction'] = {
        'disasm': idc.generate_disasm_line(switch_ea, 0),
        'bytes': ' '.join(f'{b:02X}' for b in raw_bytes),
        'size': insn_size,
    }

    # Extract jump table base address from the instruction encoding
    # FF 24 85 xx xx xx xx = jmp [eax*4 + disp32]
    # FF 24 8D xx xx xx xx = jmp [ecx*4 + disp32]
    # General: FF 24 [SIB] [disp32]
    jtable_base = 0
    index_reg = ''
    reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
    b0 = ida_bytes.get_byte(switch_ea)
    b1 = ida_bytes.get_byte(switch_ea + 1)
    if b0 == 0xFF and b1 == 0x24:
        sib = ida_bytes.get_byte(switch_ea + 2)
        scale = (sib >> 6) & 3
        idx = (sib >> 3) & 7
        base = sib & 7
        if base == 5 and scale == 2:  # disp32 only, scale=4
            jtable_base = struct.unpack('<I', bytes([
                ida_bytes.get_byte(switch_ea + 3),
                ida_bytes.get_byte(switch_ea + 4),
                ida_bytes.get_byte(switch_ea + 5),
                ida_bytes.get_byte(switch_ea + 6),
            ]))[0]
            index_reg = reg_names[idx]

    report['jtable'] = {
        'base_addr': f"0x{jtable_base:08X}" if jtable_base else None,
        'index_reg': index_reg,
    }

    # Find ncases from preceding cmp instruction
    ncases = 0
    cmp_ea = 0
    default_ea = 0
    p = switch_ea
    for _ in range(20):
        p = idc.prev_head(p, 0)
        if p == idaapi.BADADDR:
            break
        p_insn = ida_ua.insn_t()
        p_size = ida_ua.decode_insn(p_insn, p)
        if p_size == 0:
            continue
        mnem = p_insn.get_canon_mnem()
        if mnem == 'cmp' and p_insn.ops[0].type == idc.o_reg and \
           p_insn.ops[1].type == idc.o_imm:
            if reg_names[p_insn.ops[0].reg] == index_reg:
                ncases = (p_insn.ops[1].value & 0xFFFFFFFF) + 1
                cmp_ea = p
                break

    # Find default case (ja/jb after cmp)
    if cmp_ea:
        next_h = idc.next_head(cmp_ea, switch_ea)
        if next_h != idaapi.BADADDR:
            j_insn = ida_ua.insn_t()
            j_size = ida_ua.decode_insn(j_insn, next_h)
            if j_size > 0:
                j_mnem = j_insn.get_canon_mnem()
                if j_mnem in ('ja', 'jb', 'jae', 'jbe', 'jg', 'jl'):
                    if j_insn.ops[0].type in (idc.o_near, idc.o_far):
                        default_ea = j_insn.ops[0].addr

    report['switch_params'] = {
        'ncases': ncases,
        'cmp_ea': f"0x{cmp_ea:08X}" if cmp_ea else None,
        'default_ea': f"0x{default_ea:08X}" if default_ea else None,
    }

    # Dump jump table entries
    func = ida_funcs.get_func(switch_ea)
    func_start = func.start_ea if func else 0
    func_end = func.end_ea if func else 0

    jtable_entries = []
    if jtable_base and ncases > 0:
        for i in range(ncases):
            entry_ea = jtable_base + i * 4
            target = struct.unpack('<I', bytes([
                ida_bytes.get_byte(entry_ea),
                ida_bytes.get_byte(entry_ea + 1),
                ida_bytes.get_byte(entry_ea + 2),
                ida_bytes.get_byte(entry_ea + 3),
            ]))[0]
            in_func = func_start <= target < func_end if func else False
            target_flags = ida_bytes.get_full_flags(target)
            is_code = ida_bytes.is_code(target_flags)
            disasm = idc.generate_disasm_line(target, 0) if is_code else '(not code)'
            jtable_entries.append({
                'index': i,
                'table_ea': f"0x{entry_ea:08X}",
                'target': f"0x{target:08X}",
                'in_function': in_func,
                'is_code': is_code,
                'disasm': disasm,
            })

    report['jtable_entries'] = jtable_entries

    # Existing switch info
    si = _get_switch_info(switch_ea)
    has_si = si is not None
    if has_si:
        report['existing_switch_info'] = {
            'ncases': si.get_jtable_size(),
            'startea': f"0x{si.startea:08X}",
            'elbase': f"0x{si.elbase:08X}",
            'defjump': f"0x{si.defjump:08X}",
            'jumps': f"0x{si.jumps:08X}",
        }
    else:
        report['existing_switch_info'] = None

    # Validation summary
    valid_entries = sum(1 for e in jtable_entries if e['in_function'] and e['is_code'])
    report['validation'] = {
        'total_entries': len(jtable_entries),
        'valid_entries': valid_entries,
        'all_valid': valid_entries == len(jtable_entries),
        'can_fix': valid_entries == len(jtable_entries) and ncases > 0,
    }

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[*] Switch diagnosis written to: {output_path}")
    print(f"    Jump table: 0x{jtable_base:08X}, {ncases} cases, "
          f"{valid_entries}/{ncases} valid targets")
    return report


def fix_switch(switch_ea):
    """
    Fix an incomplete switch by setting proper switch_info_t.

    Usage in IDA:
        fix_switch(0x0280484C)
    """
    reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

    # Parse the jmp instruction to get jump table base and index reg
    b0 = ida_bytes.get_byte(switch_ea)
    b1 = ida_bytes.get_byte(switch_ea + 1)
    if b0 != 0xFF or b1 != 0x24:
        print(f"[!] 0x{switch_ea:08X} is not a jmp [reg*4+disp32] instruction")
        return False

    sib = ida_bytes.get_byte(switch_ea + 2)
    scale = (sib >> 6) & 3
    idx = (sib >> 3) & 7
    base = sib & 7
    if base != 5 or scale != 2:
        print(f"[!] Unexpected SIB encoding at 0x{switch_ea:08X}")
        return False

    jtable_base = struct.unpack('<I', bytes([
        ida_bytes.get_byte(switch_ea + 3),
        ida_bytes.get_byte(switch_ea + 4),
        ida_bytes.get_byte(switch_ea + 5),
        ida_bytes.get_byte(switch_ea + 6),
    ]))[0]
    index_reg = reg_names[idx]

    # Find ncases from preceding cmp
    ncases = 0
    cmp_ea = 0
    default_ea = 0
    p = switch_ea
    for _ in range(20):
        p = idc.prev_head(p, 0)
        if p == idaapi.BADADDR:
            break
        p_insn = ida_ua.insn_t()
        p_size = ida_ua.decode_insn(p_insn, p)
        if p_size == 0:
            continue
        mnem = p_insn.get_canon_mnem()
        if mnem == 'cmp' and p_insn.ops[0].type == idc.o_reg and \
           p_insn.ops[1].type == idc.o_imm:
            if reg_names[p_insn.ops[0].reg] == index_reg:
                ncases = (p_insn.ops[1].value & 0xFFFFFFFF) + 1
                cmp_ea = p
                break

    if ncases == 0:
        print(f"[!] Could not determine ncases from cmp instruction")
        return False

    # Find default case
    if cmp_ea:
        next_h = idc.next_head(cmp_ea, switch_ea)
        if next_h != idaapi.BADADDR:
            j_insn = ida_ua.insn_t()
            j_size = ida_ua.decode_insn(j_insn, next_h)
            if j_size > 0:
                j_mnem = j_insn.get_canon_mnem()
                if j_mnem in ('ja', 'jb', 'jae', 'jbe', 'jg', 'jl'):
                    if j_insn.ops[0].type in (idc.o_near, idc.o_far):
                        default_ea = j_insn.ops[0].addr

    # Validate jump table entries
    func = ida_funcs.get_func(switch_ea)
    if not func:
        print(f"[!] No function at 0x{switch_ea:08X}")
        return False

    for i in range(ncases):
        target = struct.unpack('<I', bytes([
            ida_bytes.get_byte(jtable_base + i * 4),
            ida_bytes.get_byte(jtable_base + i * 4 + 1),
            ida_bytes.get_byte(jtable_base + i * 4 + 2),
            ida_bytes.get_byte(jtable_base + i * 4 + 3),
        ]))[0]
        if not (func.start_ea <= target < func.start_ea + 0x10000):
            print(f"[!] Entry {i}: target 0x{target:08X} outside function range")
            return False

    # Set up switch_info_t
    si = idaapi.switch_info_t()
    si.set_jtable_size(ncases)
    si.jumps = jtable_base
    si.startea = cmp_ea if cmp_ea else switch_ea
    si.set_jtable_element_size(4)
    si.set_shift(0)
    si.set_elbase(0)
    if default_ea:
        si.defjump = default_ea
    si.flags = idaapi.SWI_DEFAULT | idaapi.SWI_J32

    idaapi.set_switch_info(switch_ea, si)

    # Create xrefs from switch to each case target
    for i in range(ncases):
        target = struct.unpack('<I', bytes([
            ida_bytes.get_byte(jtable_base + i * 4),
            ida_bytes.get_byte(jtable_base + i * 4 + 1),
            ida_bytes.get_byte(jtable_base + i * 4 + 2),
            ida_bytes.get_byte(jtable_base + i * 4 + 3),
        ]))[0]
        idc.add_cref(switch_ea, target, idc.fl_JN)

    # Reanalyze function
    ida_auto.plan_range(func.start_ea, func.end_ea)
    ida_auto.auto_wait()

    print(f"[*] Fixed switch at 0x{switch_ea:08X}: {ncases} cases, "
          f"table @ 0x{jtable_base:08X}")
    if default_ea:
        print(f"    Default: 0x{default_ea:08X}")
    return True


# ============================================================================
# Diagnostics (output to debug_diagnostics.json)
# ============================================================================

def diagnose(ea, context_before=15, context_after=10, output_path=None):
    """
    Diagnose a problematic address — writes detailed info to debug file.

    Usage in IDA:
        diagnose(0x0280484C)
    """
    if output_path is None:
        output_path = DEBUG_FILE

    reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
    report = {
        'target': f"0x{ea:08X}",
        'timestamp': datetime.datetime.now().isoformat(),
    }

    # Basic info at target
    flags = ida_bytes.get_full_flags(ea)
    is_code = ida_bytes.is_code(flags)
    insn = ida_ua.insn_t()
    insn_size = ida_ua.decode_insn(insn, ea)
    raw_bytes = [ida_bytes.get_byte(ea + i) for i in range(max(insn_size, 16))]

    report['target_info'] = {
        'disasm': idc.generate_disasm_line(ea, 0),
        'mnemonic': insn.get_canon_mnem() if insn_size else '(undecoded)',
        'insn_size': insn_size,
        'is_code': is_code,
        'bytes_hex': ' '.join(f'{b:02X}' for b in raw_bytes),
        'op0_type': insn.ops[0].type if insn_size else -1,
        'op0_reg': reg_names[insn.ops[0].reg] if (insn_size and insn.ops[0].type == idc.o_reg and insn.ops[0].reg < 8) else '',
        'op1_type': insn.ops[1].type if insn_size else -1,
    }

    # Function info
    func = ida_funcs.get_func(ea)
    if func:
        report['function'] = {
            'start': f"0x{func.start_ea:08X}",
            'end': f"0x{func.end_ea:08X}",
            'size': func.end_ea - func.start_ea,
            'name': idc.get_func_name(func.start_ea),
        }
    else:
        report['function'] = None

    # Context: instructions before
    context = []
    prev_addrs = []
    p = ea
    for _ in range(context_before):
        p = idc.prev_head(p, 0)
        if p == idaapi.BADADDR:
            break
        prev_addrs.append(p)
    prev_addrs.reverse()

    # Instructions before + target + after
    all_addrs = prev_addrs + [ea]
    a = ea
    for _ in range(context_after):
        a_next = idc.next_head(a, ea + 0x200)
        if a_next == idaapi.BADADDR:
            break
        a = a_next
        all_addrs.append(a)

    for a in all_addrs:
        marker = ">>>" if a == ea else ""
        disasm = idc.generate_disasm_line(a, 0)
        a_insn = ida_ua.insn_t()
        a_size = ida_ua.decode_insn(a_insn, a)
        a_bytes = [ida_bytes.get_byte(a + i) for i in range(max(a_size, 1))]
        a_flags = ida_bytes.get_full_flags(a)
        context.append({
            'addr': f"0x{a:08X}",
            'disasm': disasm,
            'bytes': ' '.join(f'{b:02X}' for b in a_bytes),
            'is_code': ida_bytes.is_code(a_flags),
            'marker': marker,
        })
    report['context'] = context

    # Xrefs to target
    code_refs_to = []
    for ref in idautils.CodeRefsTo(ea, 0):
        code_refs_to.append({
            'from': f"0x{ref:08X}",
            'disasm': idc.generate_disasm_line(ref, 0),
        })
    for ref in idautils.CodeRefsTo(ea, 1):
        if not any(r['from'] == f"0x{ref:08X}" for r in code_refs_to):
            code_refs_to.append({
                'from': f"0x{ref:08X}",
                'disasm': idc.generate_disasm_line(ref, 0),
                'flow': True,
            })
    data_refs_to = []
    for ref in idautils.DataRefsTo(ea):
        data_refs_to.append({'from': f"0x{ref:08X}"})

    report['xrefs_to'] = {
        'code_refs': code_refs_to,
        'data_refs': data_refs_to,
    }

    # Xrefs from target
    code_refs_from = []
    for ref in idautils.CodeRefsFrom(ea, 0):
        code_refs_from.append({
            'to': f"0x{ref:08X}",
            'disasm': idc.generate_disasm_line(ref, 0),
        })
    for ref in idautils.CodeRefsFrom(ea, 1):
        if not any(r['to'] == f"0x{ref:08X}" for r in code_refs_from):
            code_refs_from.append({
                'to': f"0x{ref:08X}",
                'disasm': idc.generate_disasm_line(ref, 0),
                'flow': True,
            })
    report['xrefs_from'] = code_refs_from

    # CFF dispatcher check (scan ea-10..ea+5 for the 5-byte pattern)
    cff_check = []
    for off in range(-10, 6):
        c = ea + off
        b0 = ida_bytes.get_byte(c)
        if b0 == 0x8B:
            b1 = ida_bytes.get_byte(c + 1)
            b2 = ida_bytes.get_byte(c + 2)
            b3 = ida_bytes.get_byte(c + 3)
            b4 = ida_bytes.get_byte(c + 4)
            mod = (b1 >> 6) & 3
            rm = b1 & 7
            scale = (b2 >> 6) & 3
            dest = (b1 >> 3) & 7
            base = b2 & 7
            is_cff = (mod == 0 and rm == 4 and scale == 2
                      and base != 5 and b3 == 0xFF and b4 == (0xE0 + dest))
            cff_check.append({
                'addr': f"0x{c:08X}",
                'bytes': f"{b0:02X} {b1:02X} {b2:02X} {b3:02X} {b4:02X}",
                'is_cff_dispatcher': is_cff,
                'dest_reg': reg_names[dest] if is_cff else '',
            })
    report['cff_check'] = cff_check

    # Switch info check
    si = _get_switch_info(ea)
    has_switch = si is not None
    if has_switch:
        report['switch_info'] = {
            'jumps': si.get_jtable_size(),
            'startea': f"0x{si.startea:08X}",
            'elbase': f"0x{si.elbase:08X}",
        }
    else:
        report['switch_info'] = None

    # Write to file
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[*] Diagnostics written to: {output_path}")
    return report


# ============================================================================
# JSON Export
# ============================================================================

def _export_results(results, dry_run, phases, output_path=None):
    """Export all results to a JSON file for external review."""
    if output_path is None:
        output_path = OUTPUT_FILE

    export = {
        'timestamp': datetime.datetime.now().isoformat(),
        'dry_run': dry_run,
        'phases_requested': phases,
        'summary': {},
        'phases': {},
    }

    total = 0
    for phase_key, sites in results.items():
        total += len(sites)
        export['summary'][f'phase_{phase_key}'] = len(sites)

        # Convert sites to serializable format (addresses as hex strings)
        phase_data = []
        for s in sites:
            entry = {}
            for k, v in s.items():
                if isinstance(v, int) and k in ('ea', 'next_ea', 'end_ea', 'after_ea',
                                                  'func_start', 'jmp_addr'):
                    entry[k] = f"0x{v:08X}"
                else:
                    entry[k] = v
            phase_data.append(entry)
        export['phases'][phase_key] = phase_data

    export['summary']['total'] = total

    with open(output_path, 'w') as f:
        json.dump(export, f, indent=2)

    print(f"\n[*] Results exported to: {output_path}")
    return output_path


# ============================================================================
# Main Entry Point
# ============================================================================

def fix_code_obfuscation(dry_run=False, phases="ABD"):
    """
    Main function. Runs selected deobfuscation phases.

    Args:
        dry_run: If True, only scan and report without making changes.
        phases: String of phase letters to run, e.g. "A" for jmp-reg only,
                "ABCD" for all phases including Phase C.

    Note: Phase C (junk pair removal) is excluded from default phases because
    it NOP-fills instruction pairs that cancel out in value (add/sub, xor/xor,
    inc/dec) but these instructions still modify EFLAGS. If a subsequent jcc,
    setcc, or cmov depends on those flags, NOP removal changes semantics.
    Use phases="ABCD" to explicitly opt in.
    """
    print("=" * 70)
    print("Lumma Stealer Comprehensive Code Deobfuscator")
    print("=" * 70)
    print(f"  Phases: {phases}")
    print(f"  Dry run: {dry_run}")

    results = {}
    total_fixes = 0

    # --- Phase A ---
    if 'A' in phases.upper():
        sites_a = fix_jmp_reg_code_recovery(dry_run=dry_run)
        results['A'] = sites_a
        total_fixes += len(sites_a)

    # --- Phase B ---
    if 'B' in phases.upper():
        sites_b = fix_data_in_cff_regions(dry_run=dry_run)
        results['B'] = sites_b
        total_fixes += len(sites_b)

    # --- Phase C ---
    if 'C' in phases.upper():
        sites_c = fix_junk_patterns(dry_run=dry_run)
        results['C'] = sites_c
        total_fixes += len(sites_c)

    # --- Phase D ---
    if 'D' in phases.upper():
        sites_d = fix_dead_code(dry_run=dry_run)
        results['D'] = sites_d
        total_fixes += len(sites_d)

    # --- Final reanalysis ---
    if not dry_run and total_fixes > 0:
        print(f"\n[Final] Reanalyzing affected functions...")
        seg_start, seg_end = _get_text_seg()
        if seg_start is not None:
            # Collect all affected function starts
            affected_funcs = set()
            for phase_key, sites in results.items():
                for s in sites:
                    func_start = s.get('func_start', 0)
                    if func_start:
                        affected_funcs.add(func_start)
                    else:
                        # Try to find function from ea
                        site_ea = s.get('ea', s.get('next_ea', 0))
                        if site_ea:
                            func = ida_funcs.get_func(site_ea)
                            if func:
                                affected_funcs.add(func.start_ea)

            for func_start in affected_funcs:
                func = ida_funcs.get_func(func_start)
                if func:
                    ida_auto.plan_range(func.start_ea, func.end_ea)

            ida_auto.auto_wait()
            print(f"  Reanalyzed {len(affected_funcs)} functions")

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    if 'A' in results:
        print(f"  Phase A - jmp/call reg recovery:   {len(results['A'])} sites")
    if 'B' in results:
        print(f"  Phase B - CFF data-to-code:        {len(results['B'])} blocks")
    if 'C' in results:
        print(f"  Phase C - Junk patterns removed:    {len(results['C'])} patterns")
    if 'D' in results:
        print(f"  Phase D - Dead code removed:        {len(results['D'])} blocks")
    print(f"  {'':>36} --------")
    print(f"  Total sites processed:              {total_fixes}")
    print(f"{'=' * 70}")

    if dry_run:
        print(f"\n[*] Dry run complete. No changes made.")
    else:
        print(f"\n[*] Done. Try decompiling affected functions (F5) to verify.")

    print(f"[*] Use revert_all_patches() to undo all byte changes.")

    # Export results to JSON
    _export_results(results, dry_run, phases)

    return results


# ============================================================================
# Revert all patches
# ============================================================================

def revert_all_patches():
    """
    Revert ALL byte patches in .text back to original bytes.

    WARNING: This undoes changes from ALL scripts (lumma_fix_code_obfuscation,
    lumma_fix_cff_v2, fix_zeroed_switches, AND this script). Only use this to
    return to a completely unpatched state. To selectively undo, restore the
    IDB from backup instead.
    """
    seg_start, seg_end = _get_text_seg()
    if seg_start is None:
        return

    count = 0
    ea = seg_start
    while ea < seg_end:
        orig = ida_bytes.get_original_byte(ea)
        curr = ida_bytes.get_byte(ea)
        if orig != curr:
            ida_bytes.revert_byte(ea)
            count += 1
        ea += 1

    if count:
        print(f"[*] Reverted {count} patched bytes to original values")
        ida_auto.plan_range(seg_start, seg_end)
        ida_auto.auto_wait()
        print(f"[*] Reanalysis complete")
    else:
        print("[*] No patches to revert")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    print("")
    print("Lumma Stealer Comprehensive Code Deobfuscator")
    print("")
    print("Functions:")
    print("  fix_code_obfuscation()                 - Run all phases (RECOMMENDED)")
    print("  fix_code_obfuscation(dry_run=True)     - Preview all phases")
    print("  fix_code_obfuscation(phases='A')       - Phase A only")
    print("  fix_code_obfuscation(phases='CD')      - Phases C+D only")
    print("")
    print("Scan-only:")
    print("  scan_jmp_reg()                         - Phase A: jmp/call reg sites")
    print("  scan_data_in_cff_regions()             - Phase B: data in CFF regions")
    print("  scan_junk_patterns()                   - Phase C: junk instruction pairs")
    print("  scan_dead_code()                       - Phase D: unreachable code blocks")
    print("")
    print("Undo:")
    print("  revert_all_patches()                   - Revert all byte patches")
    print("")

    try:
        if idaapi.get_imagebase():
            fix_code_obfuscation()
    except:
        print("[!] Run this script in IDA Pro")
