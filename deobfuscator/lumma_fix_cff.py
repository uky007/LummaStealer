"""
lumma_fix_cff.py - IDA Python Script
Fixes Control Flow Flattening (CFF) obfuscation in Lumma Stealer.

Problem:
    The malware uses register-indirect jump dispatchers to implement CFF.
    Pattern:
        mov [esp+X], CONST            ; set state index (constant)
        mov REG_A, [esp+TABLE_OFF]    ; load jump table pointer from stack
        mov REG_B, [esp+X]            ; load state index
        mov REG_A, [REG_A+REG_B*4]   ; dereference table[index]
        jmp REG_A                     ; dispatch (always same target)

    This breaks IDA's code flow analysis and prevents decompilation.
    ~381 dispatchers across 4 CFF-obfuscated functions.

Fix strategy:
    1. Find all CFF dispatcher patterns (mov reg,[reg+reg*4]; jmp reg)
    2. Group into clusters to identify CFF-obfuscated functions
    3. NOP out dispatcher sequences (5 bytes each) for fall-through
    4. Also NOP junk bytes between dispatchers
    5. Convert remaining data blocks to code
    6. Fix function boundaries
    7. Force reanalysis for Hex-Rays decompiler

Usage in IDA:
    File -> Script file -> lumma_fix_cff.py

    Or from the Python console:
        exec(open("lumma_fix_cff.py").read())

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


# ============================================================================
# Phase 1: Scan for CFF dispatchers
# ============================================================================

def scan_cff_dispatchers():
    """
    Find all CFF dispatcher patterns in .text:
        mov reg, [reg+reg*4]; jmp reg

    Encoding: 8B [ModRM=00,reg,100] [SIB=10,idx,base] FF [E0+reg]
    (3 bytes + 2 bytes = 5 bytes)

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

        # Check jmp dest_reg immediately after (2 bytes)
        b3 = ida_bytes.get_byte(ea + 3)
        b4 = ida_bytes.get_byte(ea + 4)
        if b3 != 0xFF or b4 != (0xE0 + dest_reg):
            ea += 1
            continue

        # Found: mov dest_reg, [base_reg + index_reg*4]; jmp dest_reg
        jmp_ea = ea + 3
        after_ea = ea + 5

        # Check for constant-index init: look back up to 30 bytes for
        # mov dword ptr [esp+X], CONST (C7 84 24 xx xx xx xx yy yy yy yy)
        has_const_init = False
        const_value = -1
        const_init_ea = 0
        const_init_size = 0
        index_stack_offset = 0

        for back in range(11, 45):
            check_ea = ea - back
            if check_ea < seg_start:
                break
            if ida_bytes.get_byte(check_ea) == 0xC7 and \
               ida_bytes.get_byte(check_ea + 1) == 0x84 and \
               ida_bytes.get_byte(check_ea + 2) == 0x24:
                disp = struct.unpack('<I', bytes([
                    ida_bytes.get_byte(check_ea + 3),
                    ida_bytes.get_byte(check_ea + 4),
                    ida_bytes.get_byte(check_ea + 5),
                    ida_bytes.get_byte(check_ea + 6),
                ]))[0]
                imm = struct.unpack('<I', bytes([
                    ida_bytes.get_byte(check_ea + 7),
                    ida_bytes.get_byte(check_ea + 8),
                    ida_bytes.get_byte(check_ea + 9),
                    ida_bytes.get_byte(check_ea + 10),
                ]))[0]
                if imm <= 16:  # Small constant = CFF index
                    has_const_init = True
                    const_value = imm
                    const_init_ea = check_ea
                    const_init_size = 11
                    index_stack_offset = disp
                    break

        # Get function context
        func = ida_funcs.get_func(ea)
        func_start = func.start_ea if func else 0

        dispatchers.append({
            'mov_ea': ea,           # mov reg, [reg+reg*4]
            'jmp_ea': jmp_ea,       # jmp reg
            'after_ea': after_ea,   # first byte after jmp reg
            'dest_reg': reg_names[dest_reg],
            'base_reg': reg_names[base_reg],
            'index_reg': reg_names[index_reg],
            'has_const_init': has_const_init,
            'const_value': const_value,
            'const_init_ea': const_init_ea,
            'const_init_size': const_init_size,
            'func_start': func_start,
        })

        ea += 5  # Skip past this dispatcher

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
    """Check if a cluster is CFF (has constant-index dispatchers)."""
    const_count = sum(1 for d in cluster if d['has_const_init'])
    return len(cluster) >= MIN_CLUSTER_SIZE and const_count >= 1


# ============================================================================
# Phase 2: Identify dispatcher sequences to NOP
# ============================================================================

def _find_dispatcher_sequence(d):
    """
    For a dispatcher, find the full sequence to NOP.

    Returns (start_ea, end_ea) of bytes to NOP.
    At minimum: the 5-byte mov+jmp pair.
    If constant-index init found: also include the setup instructions
    between the init and the table dereference.
    """
    # Always NOP the 5-byte core: mov reg,[reg+reg*4]; jmp reg
    core_start = d['mov_ea']
    core_end = d['after_ea']

    if d['has_const_init']:
        # NOP from the constant init to the jmp reg (inclusive)
        return (d['const_init_ea'], core_end)
    else:
        # For non-const dispatchers within a CFF cluster,
        # try to find the start of the setup sequence.
        # Look for the first mov reg, [esp+X] that loads the table/index
        # by walking backwards from the core.
        seq_start = core_start

        # Walk backwards checking for stack loads that are part of this dispatcher
        # Pattern: mov REG, [esp+DISP] (7 bytes: 8B x4 24 xx xx xx xx)
        # or (4 bytes: 8B x4 24 xx for small disp)
        check_ea = core_start
        for _ in range(4):  # At most 4 instructions back
            # Try 7-byte form: 8B [84|8C|94|...] 24 [disp32]
            prev7 = check_ea - 7
            if prev7 >= 0:
                b = ida_bytes.get_byte(prev7)
                b1 = ida_bytes.get_byte(prev7 + 1)
                b2 = ida_bytes.get_byte(prev7 + 2)
                if b == 0x8B and b2 == 0x24 and (b1 & 0xC7) == 0x84:
                    check_ea = prev7
                    seq_start = prev7
                    continue
            # Try 4-byte form: 8B [44|4C|54|...] 24 [disp8]
            prev4 = check_ea - 4
            if prev4 >= 0:
                b = ida_bytes.get_byte(prev4)
                b1 = ida_bytes.get_byte(prev4 + 1)
                b2 = ida_bytes.get_byte(prev4 + 2)
                if b == 0x8B and b2 == 0x24 and (b1 & 0xC7) == 0x44:
                    check_ea = prev4
                    seq_start = prev4
                    continue
            break

        return (seq_start, core_end)


def _find_junk_after(after_ea, next_dispatcher_ea, seg_end):
    """
    Check if there are junk bytes between after_ea and the next dispatcher
    or valid code block. Returns the end of junk (= start of next valid region).
    """
    # If next dispatcher is right after, no junk
    if next_dispatcher_ea and next_dispatcher_ea <= after_ea:
        return after_ea

    limit = min(
        next_dispatcher_ea if next_dispatcher_ea else after_ea + 64,
        seg_end,
        after_ea + 64
    )

    # Try to decode instructions at after_ea
    insn = ida_ua.insn_t()
    test_ea = after_ea
    valid_streak = 0
    INVALID_MNEMS = {'ljmp', 'into', 'out', 'in', 'hlt', 'popfd', 'insd',
                     'insb', 'outsb', 'outsd', 'lds', 'les', 'bound',
                     'arpl', 'daa', 'das', 'aaa', 'aas', 'aam', 'aad'}

    while test_ea < limit:
        size = ida_ua.decode_insn(insn, test_ea)
        if size == 0:
            # Can't decode - skip byte
            test_ea += 1
            valid_streak = 0
            continue

        mnem = insn.get_canon_mnem()
        if mnem in INVALID_MNEMS:
            test_ea += size
            valid_streak = 0
            continue

        valid_streak += 1
        if valid_streak >= 3:
            # Found valid code - junk ends at (test_ea - 2*avg_insn_size)?
            # Actually, junk ends where the valid streak started
            # Walk back to find start of valid streak
            junk_end = test_ea
            check = test_ea
            for _ in range(valid_streak - 1):
                # Walk back (approximate)
                for back in range(1, 16):
                    prev = check - back
                    test_insn = ida_ua.insn_t()
                    s = ida_ua.decode_insn(test_insn, prev)
                    if s > 0 and prev + s == check:
                        junk_end = prev
                        check = prev
                        break
            return junk_end

        test_ea += size

    return after_ea  # No clear junk boundary found


# ============================================================================
# Phase 3: Apply NOP patches
# ============================================================================

def _nop_range(start_ea, end_ea):
    """NOP out a range of bytes."""
    count = 0
    for ea in range(start_ea, end_ea):
        if ida_bytes.get_byte(ea) != 0x90:
            ida_bytes.patch_byte(ea, 0x90)
            count += 1
    return count


# ============================================================================
# Phase 4: Convert data to code
# ============================================================================

def _convert_data_to_code(start_ea, max_size=MAX_CODE_SCAN):
    """
    Delete data items and create code instructions from start_ea.
    Returns the end address of the created code block.
    """
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        return start_ea
    seg_end = min(start_ea + max_size, text_seg.end_ea)

    # Find extent of non-code
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

    # Delete data items
    if data_end > start_ea:
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, data_end - start_ea)

    # Create instructions
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
# Phase 5: Fix function boundaries
# ============================================================================

def _fix_func_boundary(func_start, code_start, code_end):
    """Ensure code block is part of the function."""
    func = ida_funcs.get_func(func_start)
    if not func:
        return False

    # Check if already within function
    if func.contains(code_start):
        return True

    # Try append_func_tail
    if ida_funcs.append_func_tail(func, code_start, code_end):
        return True

    # Try extending function end
    if code_start <= func.end_ea + 0x100:
        if ida_funcs.set_func_end(func_start, max(func.end_ea, code_end)):
            return True

    # Force reanalysis
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
    print("Lumma Stealer CFF (Control Flow Flattening) Fixer")
    print("=" * 70)

    # --- Phase 1: Scan ---
    print("\n[Phase 1] Scanning for CFF dispatchers...")
    all_dispatchers = scan_cff_dispatchers()
    print(f"  Found: {len(all_dispatchers)} dispatchers total")

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
    print(f"  CFF dispatchers: {len(cff_dispatchers)} "
          f"({const_count} with constant index)")

    # Print cluster details
    for i, cluster in enumerate(cff_clusters):
        c_const = sum(1 for d in cluster if d['has_const_init'])
        first = cluster[0]['mov_ea']
        last = cluster[-1]['mov_ea']
        print(f"\n  Cluster {i}: 0x{first:08X} - 0x{last:08X}")
        print(f"    Dispatchers: {len(cluster)} ({c_const} const-index)")
        funcs = set(d['func_start'] for d in cluster if d['func_start'])
        if funcs:
            print(f"    Functions: {', '.join(f'0x{f:08X}' for f in sorted(funcs))}")

    if dry_run:
        print(f"\n[*] Dry run. {len(cff_dispatchers)} dispatchers would be fixed.")

        # Show a few examples
        print("\n  Examples (first 10 const-index dispatchers):")
        for d in [d for d in cff_dispatchers if d['has_const_init']][:10]:
            print(f"    0x{d['mov_ea']:08X}: "
                  f"mov {d['dest_reg']},[{d['base_reg']}+{d['index_reg']}*4]; "
                  f"jmp {d['dest_reg']}  "
                  f"(index={d['const_value']})")
        return cff_dispatchers

    # --- Phase 2: NOP dispatcher sequences ---
    print(f"\n[Phase 2] NOPing {len(cff_dispatchers)} dispatcher sequences...")

    # Sort by address for sequential processing
    cff_dispatchers.sort(key=lambda d: d['mov_ea'])

    total_nopped = 0
    nop_ranges = []

    for i, d in enumerate(cff_dispatchers):
        seq_start, seq_end = _find_dispatcher_sequence(d)

        # Also check for junk between this dispatcher's end and the next one
        next_disp_ea = cff_dispatchers[i + 1]['mov_ea'] if i + 1 < len(cff_dispatchers) else None

        # For const-init dispatchers, try to extend NOP to cover any nearby
        # non-const dispatcher setups that are between const-init dispatchers
        junk_end = d['after_ea']
        if next_disp_ea and next_disp_ea > d['after_ea']:
            # Check if the bytes between after_ea and next dispatcher are junk
            gap = next_disp_ea - d['after_ea']
            if gap <= 20:
                # Small gap - check if it's junk
                text_seg = ida_segment.get_segm_by_name(".text")
                if text_seg:
                    junk_end = _find_junk_after(
                        d['after_ea'], next_disp_ea, text_seg.end_ea
                    )
                    if junk_end > d['after_ea'] and junk_end <= next_disp_ea:
                        seq_end = junk_end

        nopped = _nop_range(seq_start, seq_end)
        total_nopped += nopped
        nop_ranges.append((seq_start, seq_end))

        # Re-create instructions at the NOP'd location
        ida_bytes.del_items(seq_start, ida_bytes.DELIT_SIMPLE, seq_end - seq_start)
        ea = seq_start
        while ea < seq_end:
            size = idc.create_insn(ea)
            if size == 0:
                ea += 1
            else:
                ea += size

    print(f"  NOPed: {total_nopped} bytes across {len(nop_ranges)} ranges")

    # --- Phase 3: Convert data to code ---
    print(f"\n[Phase 3] Converting data blocks to code...")
    converted = 0
    code_ranges = []

    for d in cff_dispatchers:
        after_ea = d['after_ea']
        flags = ida_bytes.get_full_flags(after_ea)

        # Skip if already code (might have been auto-analyzed after NOPing)
        if ida_bytes.is_code(flags):
            code_ranges.append((after_ea, after_ea))
            continue

        code_end = _convert_data_to_code(after_ea)
        if code_end > after_ea:
            code_ranges.append((after_ea, code_end))
            converted += 1

    print(f"  Converted: {converted} data blocks to code")

    # Auto-analysis pass
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

        # Find actual code extent
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
    # For each CFF cluster, scan the entire range for unconverted data
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
                # Try to make code here
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
# Revert patches
# ============================================================================

def revert_cff_patches():
    """
    Revert all byte patches in .text back to original bytes.
    This undoes all changes made by fix_cff().
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
        # Re-create code after reverting
        ida_auto.plan_range(text_seg.start_ea, text_seg.end_ea)
        ida_auto.auto_wait()
        print(f"[*] Reanalysis complete")
    else:
        print("[*] No patches to revert")


# ============================================================================
# Standalone analysis (print details without patching)
# ============================================================================

def analyze_cff():
    """
    Analyze CFF obfuscation and print detailed report.
    Does NOT modify anything.
    """
    print("=" * 70)
    print("CFF Analysis Report")
    print("=" * 70)

    dispatchers = scan_cff_dispatchers()
    if not dispatchers:
        print("[*] No CFF dispatchers found.")
        return

    clusters = _cluster_dispatchers(dispatchers)
    cff_clusters = [c for c in clusters if _is_cff_cluster(c)]

    print(f"\nTotal dispatchers: {len(dispatchers)}")
    print(f"Total clusters: {len(clusters)}")
    print(f"CFF clusters: {len(cff_clusters)}")

    for i, cluster in enumerate(cff_clusters):
        first = cluster[0]['mov_ea']
        last = cluster[-1]['mov_ea']
        c_const = sum(1 for d in cluster if d['has_const_init'])
        funcs = set(d['func_start'] for d in cluster if d['func_start'])

        print(f"\n--- Cluster {i} ---")
        print(f"Range: 0x{first:08X} - 0x{last:08X} ({last - first:#x} bytes)")
        print(f"Dispatchers: {len(cluster)} ({c_const} const-index)")
        print(f"Functions: {len(funcs)}")

        # Index distribution
        from collections import Counter
        idx_dist = Counter(d['const_value'] for d in cluster if d['has_const_init'])
        if idx_dist:
            print(f"Index values: {dict(idx_dist)}")

        # Show const-index dispatchers
        print(f"\nConstant-index dispatchers:")
        for d in cluster:
            if d['has_const_init']:
                # Check what follows
                flags = ida_bytes.get_full_flags(d['after_ea'])
                is_code = ida_bytes.is_code(flags)
                tag = "CODE" if is_code else "DATA"
                print(f"  0x{d['mov_ea']:08X}: [{tag}] "
                      f"jmp {d['dest_reg']} (index={d['const_value']}, "
                      f"init@0x{d['const_init_ea']:08X})")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    print("")
    print("Lumma Stealer CFF Obfuscation Fixer")
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
            fix_cff()
    except:
        print("[!] Run this script in IDA Pro")
