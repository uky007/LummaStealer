"""
lumma_fix_code_obfuscation.py - IDA Python Script
Fixes indirect jump obfuscation in Lumma Stealer.

Problem:
    The malware uses `jmp [dword_XXXXXXXX]` (FF 25) to break IDA's code flow
    analysis. ~264 indirect jumps in .text have their target address stored in
    .data, causing IDA to treat the valid code after the jump as raw data (dd).
    This prevents both disassembly and decompilation.

Fix strategy:
    1. Find all `jmp [mem]` (FF 25) where the target address is in .data
       and the bytes immediately following are NOT recognized as code
    2. Patch the 6-byte indirect jump (FF 25 xx xx xx xx) to a 5-byte direct
       jump (E9 rel32) + NOP, targeting the next address (fall-through)
    3. Delete the data items after the jump and convert them to code
    4. Extend or fix function boundaries so the new code is included
    5. Force reanalysis for Hex-Rays decompiler

Usage in IDA:
    File -> Script file -> lumma_fix_code_obfuscation.py

    Or from the Python console:
        exec(open("lumma_fix_code_obfuscation.py").read())

    Individual phases can be called separately:
        results = scan_indirect_jumps()          # Phase 1: scan only
        fix_indirect_jumps(dry_run=True)         # Preview changes
        fix_indirect_jumps()                     # Apply all fixes
"""

import struct
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_auto
import ida_xref
import ida_ua
import ida_segment
import ida_idp


# ============================================================================
# Configuration
# ============================================================================

# .data section range for target validation
DATA_SECTION_START = 0x02852000
DATA_SECTION_END   = 0x02856000

# Minimum number of valid instructions to consider a block as code
MIN_VALID_INSNS = 5

# Maximum bytes to scan for code block end
MAX_BLOCK_SIZE = 0x2000


# ============================================================================
# Phase 1: Scan for indirect jumps followed by data
# ============================================================================

def scan_indirect_jumps():
    """
    Find all `jmp [dword_XXXXXXXX]` instructions in .text where:
    - The target memory address is in .data section
    - The bytes immediately after the jump are NOT recognized as code
    Returns a list of dicts with jmp_addr, next_addr, target_mem, func_start.
    """
    results = []

    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        print("[!] .text segment not found")
        return results

    seg_start = text_seg.start_ea
    seg_end = text_seg.end_ea

    ea = seg_start
    while ea < seg_end:
        flags = ida_bytes.get_full_flags(ea)

        # Only look at code items
        if not ida_bytes.is_code(flags):
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Check if this is a jmp instruction
        mnem = idc.print_insn_mnem(ea)
        if mnem != "jmp":
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Decode the instruction
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, ea)
        if insn_len == 0:
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Check for memory-indirect operand (jmp [dword_ptr])
        op = insn.ops[0]
        if op.type != idc.o_mem:
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        target_mem = op.addr
        next_ea = ea + insn_len

        # Validate: target must be in .data section
        if target_mem < DATA_SECTION_START or target_mem >= DATA_SECTION_END:
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Check if the next address has non-code bytes
        next_flags = ida_bytes.get_full_flags(next_ea)
        if ida_bytes.is_code(next_flags):
            # Already recognized as code - may still need function fix
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Validate: try to decode the bytes after as x86 instructions
        valid_count = _count_valid_insns(next_ea, MIN_VALID_INSNS + 5)
        if valid_count < MIN_VALID_INSNS:
            ea = idc.next_head(ea, seg_end)
            if ea == idaapi.BADADDR:
                break
            continue

        # Get the containing function
        func = ida_funcs.get_func(ea)
        func_start = func.start_ea if func else 0

        results.append({
            'jmp_addr': ea,
            'jmp_size': insn_len,
            'next_addr': next_ea,
            'target_mem': target_mem,
            'func_start': func_start,
            'valid_insns': valid_count,
        })

        ea = idc.next_head(ea, seg_end)
        if ea == idaapi.BADADDR:
            break

    return results


def _count_valid_insns(ea, max_count):
    """Try to decode up to max_count instructions at ea, return valid count."""
    count = 0
    cur = ea
    for _ in range(max_count):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, cur)
        if size == 0:
            break
        count += 1
        cur += size
    return count


# ============================================================================
# Phase 2: Patch indirect jumps to direct jumps
# ============================================================================

def _patch_jmp_indirect_to_direct(jmp_addr, jmp_size, target_addr):
    """
    Patch: FF 25 xx xx xx xx  (jmp [dword_ptr], 6 bytes)
    To:    E9 rel32 90        (jmp rel32 + NOP, 6 bytes)

    This makes the control flow explicit for IDA and Hex-Rays.
    """
    if jmp_size < 5:
        return False

    # Calculate relative offset for E9 (jmp rel32)
    # next_ip after E9 instruction = jmp_addr + 5
    rel_offset = target_addr - (jmp_addr + 5)

    # Pack as signed 32-bit little-endian
    offset_bytes = struct.pack('<i', rel_offset)

    # Write: E9 <rel32>
    ida_bytes.patch_byte(jmp_addr, 0xE9)
    for i in range(4):
        ida_bytes.patch_byte(jmp_addr + 1 + i, offset_bytes[i])

    # NOP remaining bytes (jmp_size - 5)
    for i in range(5, jmp_size):
        ida_bytes.patch_byte(jmp_addr + i, 0x90)

    return True


# ============================================================================
# Phase 3: Convert data to code
# ============================================================================

def _make_code_range(start_ea, max_size=MAX_BLOCK_SIZE):
    """
    Delete data items and create code instructions from start_ea.
    Returns the end address of the created code block.
    """
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        return start_ea
    seg_end = text_seg.end_ea

    end_scan = min(start_ea + max_size, seg_end)

    # First, find the extent of non-code (data/undefined) bytes
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

    # Delete all data items in the range
    if data_end > start_ea:
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, data_end - start_ea)

    # Create instructions one by one
    ea = start_ea
    code_end = start_ea
    while ea < end_scan:
        size = idc.create_insn(ea)
        if size == 0:
            # Can't decode - might have hit actual data or alignment
            break
        code_end = ea + size
        ea += size

    return code_end


# ============================================================================
# Phase 4: Fix function boundaries
# ============================================================================

def _fix_function_boundary(func_start, new_code_start, new_code_end):
    """
    Ensure the new code block is part of the function.
    Try multiple strategies:
    1. append_func_tail (add as disjoint chunk)
    2. Extend function end
    3. Plan reanalysis
    """
    func = ida_funcs.get_func(func_start)
    if not func:
        return False

    # Strategy 1: Try append_func_tail
    if ida_funcs.append_func_tail(func, new_code_start, new_code_end):
        return True

    # Strategy 2: If the new code is contiguous with the function,
    # just extend the function end
    if new_code_start <= func.end_ea + 16:
        if ida_funcs.set_func_end(func_start, new_code_end):
            return True

    # Strategy 3: Force reanalysis of the function
    ida_auto.plan_range(func_start, new_code_end)
    return True


# ============================================================================
# Main: fix_indirect_jumps
# ============================================================================

def fix_indirect_jumps(dry_run=False):
    """
    Main function. Finds and fixes all indirect jump obfuscation.

    Args:
        dry_run: If True, only scan and report without making changes.
    """
    print("=" * 70)
    print("Lumma Stealer Code Obfuscation Fixer")
    print("=" * 70)

    # --- Phase 1: Scan ---
    print("\n[Phase 1] Scanning for indirect jumps followed by data...")
    patterns = scan_indirect_jumps()
    print(f"  Found: {len(patterns)} indirect jumps with data following")

    if not patterns:
        print("[*] No patterns found. Nothing to fix.")
        return []

    # Print details
    print(f"\n  {'JmpAddr':>12} {'NextAddr':>12} {'TargetMem':>12} {'FuncStart':>12} {'Insns':>5}")
    print(f"  {'-'*12} {'-'*12} {'-'*12} {'-'*12} {'-'*5}")
    for p in patterns:
        func_str = f"0x{p['func_start']:08X}" if p['func_start'] else "   (none)   "
        print(f"  0x{p['jmp_addr']:08X} 0x{p['next_addr']:08X} 0x{p['target_mem']:08X} {func_str} {p['valid_insns']:5}")

    if dry_run:
        print(f"\n[*] Dry run complete. {len(patterns)} patterns would be fixed.")
        return patterns

    # --- Phase 2: Patch indirect jumps ---
    print(f"\n[Phase 2] Patching {len(patterns)} indirect jumps to direct jumps...")
    patched = 0
    for p in patterns:
        # Patch jmp [mem] -> jmp next_addr
        if _patch_jmp_indirect_to_direct(p['jmp_addr'], p['jmp_size'], p['next_addr']):
            # Re-create the instruction at the patched location
            ida_bytes.del_items(p['jmp_addr'], ida_bytes.DELIT_SIMPLE, p['jmp_size'])
            idc.create_insn(p['jmp_addr'])
            patched += 1

    print(f"  Patched: {patched}/{len(patterns)}")

    # --- Phase 3: Convert data to code ---
    print(f"\n[Phase 3] Converting data blocks to code...")
    converted = 0
    code_ranges = []
    for p in patterns:
        next_ea = p['next_addr']

        # Check if already code now (might have been auto-analyzed after patching)
        flags = ida_bytes.get_full_flags(next_ea)
        if ida_bytes.is_code(flags):
            code_ranges.append((next_ea, next_ea))
            converted += 1
            continue

        code_end = _make_code_range(next_ea)
        if code_end > next_ea:
            code_ranges.append((next_ea, code_end))
            converted += 1

    print(f"  Converted: {converted}/{len(patterns)}")

    # Let auto-analysis propagate
    print("\n  Running auto-analysis...")
    ida_auto.auto_wait()

    # --- Phase 4: Fix function boundaries ---
    print(f"\n[Phase 4] Fixing function boundaries...")
    fixed_funcs = 0
    for i, p in enumerate(patterns):
        if not p['func_start']:
            continue

        next_ea = p['next_addr']
        code_end = code_ranges[i][1] if i < len(code_ranges) else next_ea

        # Find actual code end (might have extended from auto-analysis)
        actual_end = next_ea
        while actual_end < next_ea + MAX_BLOCK_SIZE:
            flags = ida_bytes.get_full_flags(actual_end)
            if not ida_bytes.is_code(flags):
                break
            actual_end = idc.next_head(actual_end, next_ea + MAX_BLOCK_SIZE)
            if actual_end == idaapi.BADADDR:
                break

        if actual_end > next_ea:
            if _fix_function_boundary(p['func_start'], next_ea, actual_end):
                fixed_funcs += 1

    print(f"  Fixed: {fixed_funcs} function boundaries")

    # --- Phase 5: Second pass - handle chained patterns ---
    # Some blocks themselves end with indirect jumps. After Phase 2-4, new
    # code may reveal more patterns. Run another scan.
    print(f"\n[Phase 5] Second pass for chained patterns...")
    patterns2 = scan_indirect_jumps()
    if patterns2:
        print(f"  Found {len(patterns2)} additional patterns (chained)")
        patched2 = 0
        for p in patterns2:
            if _patch_jmp_indirect_to_direct(p['jmp_addr'], p['jmp_size'], p['next_addr']):
                ida_bytes.del_items(p['jmp_addr'], ida_bytes.DELIT_SIMPLE, p['jmp_size'])
                idc.create_insn(p['jmp_addr'])
                patched2 += 1

                code_end = _make_code_range(p['next_addr'])
                if p['func_start']:
                    _fix_function_boundary(p['func_start'], p['next_addr'], code_end)

        print(f"  Patched: {patched2} additional")
    else:
        print(f"  No additional patterns found.")

    # --- Phase 6: Final reanalysis ---
    print(f"\n[Phase 6] Final reanalysis...")
    # Plan reanalysis for all affected functions
    reanalyzed = set()
    for p in patterns + (patterns2 or []):
        if p['func_start'] and p['func_start'] not in reanalyzed:
            func = ida_funcs.get_func(p['func_start'])
            if func:
                ida_auto.plan_range(func.start_ea, func.end_ea)
                reanalyzed.add(p['func_start'])

    ida_auto.auto_wait()
    print(f"  Reanalyzed {len(reanalyzed)} functions")

    # --- Summary ---
    total = len(patterns) + len(patterns2 or [])
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"  Phase 1 - Patterns found:     {len(patterns)}")
    print(f"  Phase 2 - Jumps patched:       {patched}")
    print(f"  Phase 3 - Data->Code:          {converted}")
    print(f"  Phase 4 - Functions fixed:      {fixed_funcs}")
    print(f"  Phase 5 - Chained patterns:     {len(patterns2 or [])}")
    print(f"  Phase 6 - Functions reanalyzed: {len(reanalyzed)}")
    print(f"  ----------------------------------------")
    print(f"  Total fixes applied:            {total}")
    print(f"{'='*70}")
    print(f"\n[*] Done. Try decompiling affected functions (F5) to verify.")
    print(f"[*] Example: Go to 0x02812E36, press F5")

    return patterns


# ============================================================================
# Utility: Revert patches (undo)
# ============================================================================

def revert_patches():
    """
    Revert all byte patches in the IDB back to original bytes.
    Use this if something goes wrong.
    """
    count = 0
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        print("[!] .text segment not found")
        return

    ea = text_seg.start_ea
    while ea < text_seg.end_ea:
        orig = ida_bytes.get_original_byte(ea)
        curr = ida_bytes.get_byte(ea)
        if orig != curr:
            ida_bytes.revert_byte(ea)
            count += 1
        ea += 1

    if count:
        print(f"[*] Reverted {count} patched bytes to original values")
        ida_auto.auto_wait()
    else:
        print("[*] No patches to revert")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    print("")
    print("Lumma Stealer Code Obfuscation Fixer")
    print("")
    print("Functions:")
    print("  fix_indirect_jumps()            - Fix all (RECOMMENDED)")
    print("  fix_indirect_jumps(dry_run=True) - Scan only, no changes")
    print("  scan_indirect_jumps()           - List all patterns")
    print("  revert_patches()                - Undo all byte patches")
    print("")

    try:
        if idaapi.get_imagebase():
            fix_indirect_jumps()
    except:
        print("[!] Run this script in IDA Pro")
