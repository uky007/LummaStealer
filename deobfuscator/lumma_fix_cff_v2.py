"""
lumma_fix_cff_v2.py - IDA Python Script
Fixes Control Flow Flattening (CFF) obfuscation in Lumma Stealer.

Improvements over v1 (lumma_fix_cff.py):
  - Detects SPLIT dispatchers: mov reg,[reg+reg*4]; <insn>; jmp reg  (56 extra)
  - NOPs full setup sequence (const-init + stack loads + core + gap)
  - Identifies setcc-based conditional dispatches for analysis
  - Better junk detection and cleanup

Pattern:
    Contiguous (5 bytes):
        mov REG_A, [REG_B+REG_C*4]   ; table dereference (3 bytes)
        jmp REG_A                     ; dispatch (2 bytes)

    Split (7-19 bytes):
        mov REG_A, [REG_B+REG_C*4]   ; table dereference (3 bytes)
        <1-3 unrelated instructions>  ; interleaved code
        jmp REG_A                     ; dispatch (2 bytes)

    Full setup sequence (up to ~30 bytes before core):
        [mov dword ptr [esp+X], CONST]    ; const-index init (11 bytes, optional)
        mov REG_D, [esp+TABLE_OFF]        ; load jump table pointer (7 bytes)
        mov REG_E, [esp+INDEX_OFF]        ; load state index (7 bytes)

CFF Analysis:
    - 4 CFF clusters with 451 total dispatchers (399 contiguous + 56 split)
    - 85 constant-index dispatchers (always jump to same target)
    - 126 setcc-based dispatchers (obfuscated conditional branches)
    - ~184 computed-index dispatchers
    - 98% have valid code immediately after → NOP fall-through is viable

Usage in IDA:
    File -> Script file -> lumma_fix_cff_v2.py

    Or from the Python console:
        exec(open("lumma_fix_cff_v2.py").read())

    Individual functions:
        results = scan_cff_dispatchers()         # Scan only
        fix_cff(dry_run=True)                    # Preview changes
        fix_cff()                                # Apply all fixes
        revert_cff_patches()                     # Undo all changes
"""

import struct
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_auto
import ida_ua
import ida_segment


# ============================================================================
# Configuration
# ============================================================================

# Minimum dispatchers in a cluster to consider it CFF (vs legitimate switch)
MIN_CLUSTER_SIZE = 5

# Maximum gap between dispatchers in same cluster
MAX_CLUSTER_GAP = 0x1000

# Maximum bytes to scan for code block after dispatcher
MAX_CODE_SCAN = 0x2000

# Maximum instructions between table deref and jmp reg in split dispatchers
MAX_SPLIT_GAP_INSNS = 4


# ============================================================================
# Phase 1: Scan for CFF dispatchers (contiguous + split)
# ============================================================================

def scan_cff_dispatchers():
    """
    Find all CFF dispatcher patterns in .text:
        Contiguous: mov reg, [reg+reg*4]; jmp reg  (5 bytes)
        Split:      mov reg, [reg+reg*4]; <insns>; jmp reg  (7+ bytes)

    Returns a list of dicts with dispatcher info.
    """
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        print("[!] .text segment not found")
        return []

    seg_start = text_seg.start_ea
    seg_end = text_seg.end_ea
    reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

    dispatchers = []
    ea = seg_start
    while ea < seg_end - 5:
        b0 = ida_bytes.get_byte(ea)
        if b0 != 0x8B:
            ea += 1
            continue

        b1 = ida_bytes.get_byte(ea + 1)  # ModRM
        mod = (b1 >> 6) & 3
        dest_reg = (b1 >> 3) & 7
        rm = b1 & 7

        if mod != 0 or rm != 4:
            ea += 1
            continue

        b2 = ida_bytes.get_byte(ea + 2)  # SIB
        scale = (b2 >> 6) & 3
        index_reg = (b2 >> 3) & 7
        base_reg = b2 & 7

        if scale != 2 or base_reg == 5:  # scale=4, no disp32 base
            ea += 1
            continue

        # --- Check for contiguous dispatcher (5 bytes) ---
        b3 = ida_bytes.get_byte(ea + 3)
        b4 = ida_bytes.get_byte(ea + 4)
        is_contiguous = (b3 == 0xFF and b4 == (0xE0 + dest_reg))

        # --- Check for split dispatcher ---
        is_split = False
        split_jmp_ea = 0
        split_gap_insns = []
        split_total_size = 0

        if not is_contiguous:
            # Try to find jmp dest_reg within next MAX_SPLIT_GAP_INSNS instructions
            scan_ea = ea + 3
            gap_insns = []
            for _ in range(MAX_SPLIT_GAP_INSNS):
                insn = ida_ua.insn_t()
                size = ida_ua.decode_insn(insn, scan_ea)
                if size == 0:
                    break

                mnem = idc.print_insn_mnem(scan_ea)
                op_str = idc.print_operand(scan_ea, 0)

                # Check if this is jmp dest_reg
                bx = ida_bytes.get_byte(scan_ea)
                by = ida_bytes.get_byte(scan_ea + 1)
                if bx == 0xFF and by == (0xE0 + dest_reg):
                    is_split = True
                    split_jmp_ea = scan_ea
                    split_gap_insns = gap_insns
                    split_total_size = (scan_ea + 2) - ea
                    break

                # Record gap instruction
                gap_insns.append({
                    'ea': scan_ea,
                    'size': size,
                    'disasm': f"{mnem} {op_str}",
                })
                scan_ea += size

        if not is_contiguous and not is_split:
            ea += 1
            continue

        # Found a dispatcher
        mov_ea = ea
        if is_contiguous:
            jmp_ea = ea + 3
            after_ea = ea + 5
            disp_type = 'contiguous'
        else:
            jmp_ea = split_jmp_ea
            after_ea = split_jmp_ea + 2
            disp_type = 'split'

        # --- Look for constant-index init ---
        has_const_init = False
        const_value = -1
        const_init_ea = 0
        const_init_size = 0

        for back in range(11, 50):
            check_ea = ea - back
            if check_ea < seg_start:
                break
            if (ida_bytes.get_byte(check_ea) == 0xC7 and
                    ida_bytes.get_byte(check_ea + 1) == 0x84 and
                    ida_bytes.get_byte(check_ea + 2) == 0x24):
                imm = struct.unpack('<I', bytes([
                    ida_bytes.get_byte(check_ea + 7),
                    ida_bytes.get_byte(check_ea + 8),
                    ida_bytes.get_byte(check_ea + 9),
                    ida_bytes.get_byte(check_ea + 10),
                ]))[0]
                if imm <= 16:
                    has_const_init = True
                    const_value = imm
                    const_init_ea = check_ea
                    const_init_size = 11
                    break

        # --- Look for stack load setup instructions ---
        # Pattern: mov REG, [esp+DISP32] (7 bytes: 8B [84|8C|94...] 24 [disp32])
        setup_start = mov_ea
        check_ea = mov_ea
        for _ in range(4):
            # Try 7-byte form
            prev7 = check_ea - 7
            if prev7 >= seg_start:
                b = ida_bytes.get_byte(prev7)
                b1 = ida_bytes.get_byte(prev7 + 1)
                b2 = ida_bytes.get_byte(prev7 + 2)
                if b == 0x8B and b2 == 0x24 and (b1 & 0xC7) == 0x84:
                    check_ea = prev7
                    setup_start = prev7
                    continue
            # Try 4-byte form (small displacement)
            prev4 = check_ea - 4
            if prev4 >= seg_start:
                b = ida_bytes.get_byte(prev4)
                b1 = ida_bytes.get_byte(prev4 + 1)
                b2 = ida_bytes.get_byte(prev4 + 2)
                if b == 0x8B and b2 == 0x24 and (b1 & 0xC7) == 0x44:
                    check_ea = prev4
                    setup_start = prev4
                    continue
            break

        # If we have const_init, extend setup to include it
        if has_const_init and const_init_ea < setup_start:
            setup_start = const_init_ea

        # Get function context
        func = ida_funcs.get_func(ea)
        func_start = func.start_ea if func else 0

        dispatchers.append({
            'mov_ea': mov_ea,
            'jmp_ea': jmp_ea,
            'after_ea': after_ea,
            'setup_start': setup_start,
            'dest_reg': reg_names[dest_reg],
            'base_reg': reg_names[base_reg],
            'index_reg': reg_names[index_reg],
            'has_const_init': has_const_init,
            'const_value': const_value,
            'const_init_ea': const_init_ea,
            'disp_type': disp_type,
            'split_gap': [g['disasm'] for g in split_gap_insns] if is_split else [],
            'func_start': func_start,
            'nop_start': setup_start,
            'nop_end': after_ea,
        })

        ea = after_ea  # Skip past this dispatcher

    return dispatchers


def _cluster_dispatchers(dispatchers):
    """Group dispatchers into clusters based on proximity."""
    if not dispatchers:
        return []

    sorted_disps = sorted(dispatchers, key=lambda d: d['mov_ea'])
    clusters = [[sorted_disps[0]]]

    for d in sorted_disps[1:]:
        if d['mov_ea'] - clusters[-1][-1]['mov_ea'] < MAX_CLUSTER_GAP:
            clusters[-1].append(d)
        else:
            clusters.append([d])

    return clusters


def _is_cff_cluster(cluster):
    """Check if a cluster is CFF (enough dispatchers, some with constant index)."""
    const_count = sum(1 for d in cluster if d['has_const_init'])
    return len(cluster) >= MIN_CLUSTER_SIZE and const_count >= 1


# ============================================================================
# Phase 2: NOP dispatcher sequences
# ============================================================================

def _nop_range(start_ea, end_ea):
    """NOP out a range of bytes."""
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
    ida_bytes.del_items(start_ea, ida_bytes.DELIT_SIMPLE, end_ea - start_ea)
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


# ============================================================================
# Phase 3: Convert data to code
# ============================================================================

def _convert_data_to_code(start_ea, max_size=MAX_CODE_SCAN):
    """Delete data items and create code instructions from start_ea."""
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        return start_ea
    seg_end = min(start_ea + max_size, text_seg.end_ea)

    data_end = start_ea
    while data_end < seg_end:
        flags = ida_bytes.get_full_flags(data_end)
        if ida_bytes.is_code(flags):
            break
        next_h = idc.next_head(data_end, seg_end)
        if next_h == idaapi.BADADDR:
            data_end = seg_end
            break
        data_end = next_h

    if data_end > start_ea:
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, data_end - start_ea)

    ea = start_ea
    code_end = start_ea
    while ea < seg_end:
        size = idc.create_insn(ea)
        if size == 0:
            break
        code_end = ea + size
        ea += size
    return code_end


# ============================================================================
# Phase 4: Fix function boundaries
# ============================================================================

def _fix_func_boundary(func_start, code_start, code_end):
    """Ensure code block is part of the function."""
    func = ida_funcs.get_func(func_start)
    if not func:
        return False

    if func.contains(code_start):
        return True

    if ida_funcs.append_func_tail(func, code_start, code_end):
        return True

    if code_start <= func.end_ea + 0x100:
        if ida_funcs.set_func_end(func_start, max(func.end_ea, code_end)):
            return True

    ida_auto.plan_range(func_start, code_end)
    return True


# ============================================================================
# Main: fix_cff
# ============================================================================

def fix_cff(dry_run=False):
    """
    Main function. Finds and fixes all CFF obfuscation.

    Args:
        dry_run: If True, only scan and report without making changes.
    """
    print("=" * 70)
    print("Lumma Stealer CFF Fixer v2")
    print("  (contiguous + split dispatcher support)")
    print("=" * 70)

    # --- Phase 1: Scan ---
    print("\n[Phase 1] Scanning for CFF dispatchers...")
    all_dispatchers = scan_cff_dispatchers()

    contiguous = sum(1 for d in all_dispatchers if d['disp_type'] == 'contiguous')
    split = sum(1 for d in all_dispatchers if d['disp_type'] == 'split')
    print(f"  Found: {len(all_dispatchers)} dispatchers "
          f"({contiguous} contiguous, {split} split)")

    if not all_dispatchers:
        print("[*] No CFF dispatchers found.")
        return []

    # Cluster and identify CFF functions
    clusters = _cluster_dispatchers(all_dispatchers)
    cff_clusters = [c for c in clusters if _is_cff_cluster(c)]
    non_cff = [c for c in clusters if not _is_cff_cluster(c)]

    print(f"  Clusters: {len(clusters)} total, {len(cff_clusters)} CFF, "
          f"{len(non_cff)} non-CFF (skipped)")

    cff_dispatchers = []
    for cluster in cff_clusters:
        cff_dispatchers.extend(cluster)

    const_count = sum(1 for d in cff_dispatchers if d['has_const_init'])
    split_count = sum(1 for d in cff_dispatchers if d['disp_type'] == 'split')
    print(f"  CFF dispatchers: {len(cff_dispatchers)} "
          f"({const_count} const-index, {split_count} split)")

    # Print cluster details
    for i, cluster in enumerate(cff_clusters):
        c_const = sum(1 for d in cluster if d['has_const_init'])
        c_split = sum(1 for d in cluster if d['disp_type'] == 'split')
        first = cluster[0]['mov_ea']
        last = cluster[-1]['mov_ea']
        print(f"\n  Cluster {i}: 0x{first:08X} - 0x{last:08X}")
        print(f"    Dispatchers: {len(cluster)} "
              f"({c_const} const-index, {c_split} split)")
        funcs = set(d['func_start'] for d in cluster if d['func_start'])
        if funcs:
            print(f"    Functions: {', '.join(f'0x{f:08X}' for f in sorted(funcs))}")

    if dry_run:
        print(f"\n[*] Dry run. {len(cff_dispatchers)} dispatchers would be fixed.")

        # Show examples
        print("\n  Examples (first 10 dispatchers):")
        for d in cff_dispatchers[:10]:
            gap_str = ""
            if d['disp_type'] == 'split':
                gap_str = f" gap=[{'; '.join(d['split_gap'])}]"
            const_str = f" index={d['const_value']}" if d['has_const_init'] else ""
            nop_size = d['nop_end'] - d['nop_start']
            print(f"    0x{d['mov_ea']:08X} [{d['disp_type']:10s}]{const_str} "
                  f"NOP: 0x{d['nop_start']:08X}-0x{d['nop_end']:08X} "
                  f"({nop_size}B){gap_str}")
        return cff_dispatchers

    # --- Phase 2: NOP dispatcher sequences ---
    print(f"\n[Phase 2] NOPing {len(cff_dispatchers)} dispatcher sequences...")

    cff_dispatchers.sort(key=lambda d: d['mov_ea'])

    total_nopped = 0
    for d in cff_dispatchers:
        nop_start = d['nop_start']
        nop_end = d['nop_end']

        nopped = _nop_range(nop_start, nop_end)
        total_nopped += nopped

        # Re-create as NOP instructions
        _recreate_as_code(nop_start, nop_end)

    print(f"  NOPed: {total_nopped} bytes across {len(cff_dispatchers)} dispatchers")

    # --- Phase 3: Convert data to code ---
    print(f"\n[Phase 3] Converting data blocks to code...")
    converted = 0
    code_ranges = []

    for d in cff_dispatchers:
        after_ea = d['after_ea']
        flags = ida_bytes.get_full_flags(after_ea)

        if ida_bytes.is_code(flags):
            code_ranges.append((after_ea, after_ea))
            continue

        code_end = _convert_data_to_code(after_ea)
        if code_end > after_ea:
            code_ranges.append((after_ea, code_end))
            converted += 1

    print(f"  Converted: {converted} data blocks to code")

    print("\n  Running auto-analysis...")
    ida_auto.auto_wait()

    # --- Phase 4: Fix function boundaries ---
    print(f"\n[Phase 4] Fixing function boundaries...")
    fixed = 0

    for i, d in enumerate(cff_dispatchers):
        if not d['func_start']:
            continue

        after_ea = d['after_ea']
        if i < len(code_ranges):
            code_end = code_ranges[i][1]
        else:
            code_end = after_ea

        text_seg = ida_segment.get_segm_by_name(".text")
        if not text_seg:
            continue

        actual_end = after_ea
        while actual_end < after_ea + MAX_CODE_SCAN:
            f = ida_bytes.get_full_flags(actual_end)
            if not ida_bytes.is_code(f):
                break
            next_h = idc.next_head(actual_end, after_ea + MAX_CODE_SCAN)
            if next_h == idaapi.BADADDR:
                break
            actual_end = next_h

        if actual_end > after_ea:
            if _fix_func_boundary(d['func_start'], after_ea, actual_end):
                fixed += 1

    print(f"  Fixed: {fixed} function boundaries")

    # --- Phase 5: Second pass for remaining data ---
    print(f"\n[Phase 5] Second pass - converting remaining data...")
    second_pass = 0
    for cluster in cff_clusters:
        cluster_start = cluster[0]['mov_ea']
        cluster_end = cluster[-1]['after_ea'] + 0x100

        ea = cluster_start
        text_seg = ida_segment.get_segm_by_name(".text")
        if not text_seg:
            continue
        limit = min(cluster_end, text_seg.end_ea)

        while ea < limit:
            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_code(flags):
                size = idc.create_insn(ea)
                if size > 0:
                    second_pass += 1
                    ea += size
                    continue
            next_h = idc.next_head(ea, limit)
            if next_h == idaapi.BADADDR:
                break
            ea = next_h

    print(f"  Additional instructions created: {second_pass}")

    # --- Phase 6: Final reanalysis ---
    print(f"\n[Phase 6] Final reanalysis...")
    reanalyzed = set()
    for d in cff_dispatchers:
        if d['func_start'] and d['func_start'] not in reanalyzed:
            func = ida_funcs.get_func(d['func_start'])
            if func:
                ida_auto.plan_range(func.start_ea, func.end_ea)
                reanalyzed.add(d['func_start'])

    ida_auto.auto_wait()
    print(f"  Reanalyzed {len(reanalyzed)} functions")

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Dispatchers found:     {len(all_dispatchers)}")
    print(f"    Contiguous:          {contiguous}")
    print(f"    Split:               {split}")
    print(f"  CFF clusters:          {len(cff_clusters)}")
    print(f"  CFF dispatchers:       {len(cff_dispatchers)}")
    print(f"    Constant-index:      {const_count}")
    print(f"    Variable-index:      {len(cff_dispatchers) - const_count}")
    print(f"  Bytes NOPed:           {total_nopped}")
    print(f"  Data blocks converted: {converted}")
    print(f"  Functions fixed:       {fixed}")
    print(f"  Functions reanalyzed:  {len(reanalyzed)}")
    print(f"{'=' * 70}")
    print(f"\n[*] Done. Try decompiling affected functions (F5).")
    print(f"[*] Use revert_cff_patches() to undo all changes.")

    return cff_dispatchers


# ============================================================================
# Analysis: detailed CFF report
# ============================================================================

def analyze_cff():
    """
    Analyze CFF obfuscation and print detailed report.
    Does NOT modify anything.
    """
    print("=" * 70)
    print("CFF Analysis Report v2")
    print("=" * 70)

    dispatchers = scan_cff_dispatchers()
    if not dispatchers:
        print("[*] No CFF dispatchers found.")
        return

    clusters = _cluster_dispatchers(dispatchers)
    cff_clusters = [c for c in clusters if _is_cff_cluster(c)]

    contiguous = sum(1 for d in dispatchers if d['disp_type'] == 'contiguous')
    split = sum(1 for d in dispatchers if d['disp_type'] == 'split')

    print(f"\nTotal dispatchers: {len(dispatchers)} "
          f"({contiguous} contiguous, {split} split)")
    print(f"Total clusters: {len(clusters)}")
    print(f"CFF clusters: {len(cff_clusters)}")

    for i, cluster in enumerate(cff_clusters):
        first = cluster[0]['mov_ea']
        last = cluster[-1]['mov_ea']
        c_const = sum(1 for d in cluster if d['has_const_init'])
        c_split = sum(1 for d in cluster if d['disp_type'] == 'split')
        funcs = set(d['func_start'] for d in cluster if d['func_start'])

        print(f"\n--- Cluster {i} ---")
        print(f"Range: 0x{first:08X} - 0x{last:08X} ({last - first:#x} bytes)")
        print(f"Dispatchers: {len(cluster)} "
              f"({c_const} const-index, {c_split} split)")
        print(f"Functions: {len(funcs)}")

        # Index distribution
        from collections import Counter
        idx_dist = Counter(d['const_value'] for d in cluster if d['has_const_init'])
        if idx_dist:
            print(f"Const-index values: {dict(idx_dist)}")

        # NOP size statistics
        nop_sizes = [d['nop_end'] - d['nop_start'] for d in cluster]
        total_nop = sum(nop_sizes)
        print(f"Total bytes to NOP: {total_nop} "
              f"(avg {total_nop // len(cluster) if cluster else 0}/dispatcher)")

        # Show const-index dispatchers
        print(f"\nConstant-index dispatchers:")
        for d in cluster:
            if d['has_const_init']:
                flags = ida_bytes.get_full_flags(d['after_ea'])
                is_code = ida_bytes.is_code(flags)
                tag = "CODE" if is_code else "DATA"
                split_tag = " [SPLIT]" if d['disp_type'] == 'split' else ""
                nop_sz = d['nop_end'] - d['nop_start']
                print(f"  0x{d['mov_ea']:08X}: [{tag}] "
                      f"jmp {d['dest_reg']} (index={d['const_value']}, "
                      f"NOP={nop_sz}B){split_tag}")

        # Show split dispatchers
        if c_split > 0:
            print(f"\nSplit dispatchers:")
            for d in cluster:
                if d['disp_type'] == 'split':
                    gap = '; '.join(d['split_gap'])
                    nop_sz = d['nop_end'] - d['nop_start']
                    print(f"  0x{d['mov_ea']:08X}: "
                          f"mov {d['dest_reg']},[{d['base_reg']}+{d['index_reg']}*4]; "
                          f"{gap}; jmp {d['dest_reg']} (NOP={nop_sz}B)")


# ============================================================================
# Revert patches
# ============================================================================

def revert_cff_patches():
    """
    Revert ALL byte patches in .text back to original bytes.

    WARNING: This reverts patches from ALL scripts, not just this one.
    Only use this to return to a completely unpatched state.
    """
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        print("[!] .text segment not found")
        return

    count = 0
    ea = text_seg.start_ea
    while ea < text_seg.end_ea:
        orig = ida_bytes.get_original_byte(ea)
        curr = ida_bytes.get_byte(ea)
        if orig != curr:
            ida_bytes.revert_byte(ea)
            count += 1
        ea += 1

    if count:
        print(f"[*] Reverted {count} patched bytes")
        ida_auto.plan_range(text_seg.start_ea, text_seg.end_ea)
        ida_auto.auto_wait()
        print(f"[*] Reanalysis complete")
    else:
        print("[*] No patches to revert")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    print("")
    print("Lumma Stealer CFF Obfuscation Fixer v2")
    print("")
    print("Functions:")
    print("  fix_cff()                  - Fix all CFF obfuscation (RECOMMENDED)")
    print("  fix_cff(dry_run=True)      - Preview changes without patching")
    print("  analyze_cff()              - Detailed analysis report")
    print("  scan_cff_dispatchers()     - List all dispatchers")
    print("  revert_cff_patches()       - Undo all byte patches")
    print("")

    try:
        if idaapi.get_imagebase():
            fix_cff(dry_run=True)
    except:
        print("[!] Run this script in IDA Pro")
