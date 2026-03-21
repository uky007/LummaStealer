"""
fix_zeroed_switches.py - Fix zeroed switch tables for Hex-Rays decompilation

Problem:
    7 switch instructions reference jump tables in .rdata that are all zeros.
    This causes "switch analysis failed" in Hex-Rays, preventing F5 decompilation.

Root Cause:
    CFF obfuscation tool intentionally zeroed these tables.
    VirtualProtect is absent from the binary — tables can never be written at runtime.
    No code references write to the table ranges.

Solution:
    Patch each switch `jmp [table+reg*4]` instruction to `jmp default_case`.
    This routes all cases to the default handler, which is correct for zeroed tables.
    IDA's switch_info is then deleted so Hex-Rays treats it as a normal jump.

Run AFTER:
    1. lumma_fix_code_obfuscation.py
    2. lumma_fix_cff_v2.py
Run BEFORE:
    3. lumma_code_deobfuscator.py

Usage:
    fix_zeroed_switches(dry_run=True)   # Preview changes
    fix_zeroed_switches()               # Apply patches
    revert_zeroed_switches()            # Undo all patches
"""

import struct
import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_auto
import ida_ua

try:
    import ida_nalt
except ImportError:
    ida_nalt = None


# ============================================================================
# Zeroed switch sites (from find_switch_init_results.json)
# ============================================================================

ZEROED_SWITCHES = [
    # (switch_ea, startea, description)
    (0x02801CE1, 0x02801CD9, "sub_2801CC0, jmp [jpt+ecx*4], lowcase=91"),
    (0x02802295, 0x02802289, "sub_28021B0, jmp [jpt+edx*4], lowcase=34"),
    (0x02803BB6, 0x02803BA8, "sub_2803A50, jmp [jpt+ecx*4], lowcase=0"),
    (0x0280484C, 0x02804836, "sub_2804720, jmp [jpt+eax*4], lowcase=0"),
    (0x02814EEC, 0x02814EDC, "sub_2814980, jmp eax type,    lowcase=0"),
    (0x02823120, 0x02823116, "sub_2823110, jmp [jpt+edx*4], lowcase=43, table in .text"),
    (0x0284C3C6, 0x0284C3C1, "sub_284C2F0, jmp [jpt+ebp*4], lowcase=0"),
]


def _get_insn_length(ea):
    """Get instruction length at ea."""
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    return size if size > 0 else 0


def _find_default_case(switch_ea, startea):
    """Find the default case address for a switch.

    Strategy:
    1. Check IDA switch_info_t.defjump
    2. Search backward from switch_ea for ja/jae/jb/jbe → target is default
    """
    # Strategy 1: IDA switch info
    si = idaapi.get_switch_info(switch_ea)
    if si:
        dj = si.defjump
        if dj and dj != idc.BADADDR and dj != 0:
            return dj, 'switch_info'

    # Strategy 2: Conditional jump before switch
    func = ida_funcs.get_func(switch_ea)
    lower = func.start_ea if func else 0
    ea = switch_ea
    for _ in range(20):
        ea = idc.prev_head(ea, lower)
        if ea == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(ea)
        if mnem in ('ja', 'jae', 'jb', 'jbe', 'jg', 'jge'):
            target = idc.get_operand_value(ea, 0)
            if target and target != idc.BADADDR:
                return target, 'cond_jump'

    # Strategy 3: Look for IDA's def_ label
    func_name = idc.get_func_name(switch_ea) or ''
    # IDA typically names the default case def_XXXXXXXX
    def_name = f'def_{switch_ea:X}'
    def_ea = idc.get_name_ea_simple(def_name)
    if def_ea and def_ea != idc.BADADDR:
        return def_ea, 'def_label'

    return None, None


def _is_jmp_reg(ea):
    """Check if instruction is `jmp reg` (FF E0-FF E7)."""
    b0 = ida_bytes.get_byte(ea)
    b1 = ida_bytes.get_byte(ea + 1)
    return b0 == 0xFF and (b1 & 0xF8) == 0xE0


def _is_jmp_table(ea):
    """Check if instruction is `jmp [table + reg*4]` (FF 24 xx ...)."""
    b0 = ida_bytes.get_byte(ea)
    b1 = ida_bytes.get_byte(ea + 1)
    return b0 == 0xFF and b1 == 0x24


def _find_table_load_before_jmp_reg(ea):
    """For `jmp eax` type switches, find the preceding `mov eax, [table+reg*4]`.

    Returns (load_ea, load_len) or (None, 0).
    """
    func = ida_funcs.get_func(ea)
    lower = func.start_ea if func else 0
    scan = ea
    for _ in range(5):
        scan = idc.prev_head(scan, lower)
        if scan == idc.BADADDR:
            break
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, scan)
        if size <= 0:
            continue
        mnem = insn.get_canon_mnem()
        # Look for `mov reg, [table + reg*4]` pattern
        if mnem == 'mov' and insn.ops[0].type == idc.o_reg:
            if insn.ops[1].type in (idc.o_mem, idc.o_displ, idc.o_phrase):
                return scan, size
    return None, 0


def _build_jmp_rel32(from_ea, to_ea):
    """Build a 5-byte near jump (E9 rel32)."""
    rel = to_ea - (from_ea + 5)
    # Pack as signed 32-bit
    return struct.pack('<Bi', 0xE9, rel)


def _patch_bytes(ea, data):
    """Patch bytes at ea."""
    for i, b in enumerate(data):
        ida_bytes.patch_byte(ea + i, b)


def fix_one_switch(switch_ea, startea, desc, dry_run=False):
    """Fix one zeroed switch. Returns True on success."""
    disasm = idc.generate_disasm_line(switch_ea, 0)
    func_name = idc.get_func_name(switch_ea) or '???'
    func = ida_funcs.get_func(switch_ea)

    print(f'  Switch:   0x{switch_ea:08X}  {disasm}')
    print(f'  Function: {func_name}')
    print(f'  Note:     {desc}')

    # Find default case
    default_ea, source = _find_default_case(switch_ea, startea)
    if not default_ea:
        print(f'  [SKIP] Cannot find default case address')
        return False
    print(f'  Default:  0x{default_ea:08X} (source: {source})')

    # Determine patch strategy based on instruction type
    is_reg = _is_jmp_reg(switch_ea)
    is_tbl = _is_jmp_table(switch_ea)
    insn_len = _get_insn_length(switch_ea)

    if is_tbl and insn_len >= 5:
        # Standard case: jmp [table + reg*4] — 7 bytes, plenty of room
        patch_ea = switch_ea
        patch_len = insn_len
        print(f'  Type:     jmp [table+reg*4] ({insn_len} bytes)')

    elif is_reg and insn_len == 2:
        # jmp reg — only 2 bytes, need to include preceding mov
        load_ea, load_len = _find_table_load_before_jmp_reg(switch_ea)
        if load_ea and load_len > 0:
            patch_ea = load_ea
            patch_len = (switch_ea + insn_len) - load_ea
            load_disasm = idc.generate_disasm_line(load_ea, 0)
            print(f'  Type:     jmp reg (2 bytes) + table load at 0x{load_ea:08X}')
            print(f'  Load:     {load_disasm} ({load_len} bytes)')
            print(f'  Patch:    0x{patch_ea:08X} - 0x{patch_ea + patch_len - 1:08X} ({patch_len} bytes)')
        else:
            print(f'  [SKIP] jmp reg without identifiable table load')
            return False

    else:
        print(f'  [SKIP] Unrecognized instruction type (bytes: {insn_len})')
        return False

    if patch_len < 5:
        print(f'  [SKIP] Patch region too small ({patch_len} bytes, need 5)')
        return False

    # Build patch: E9 rel32 + NOPs
    jmp_bytes = _build_jmp_rel32(patch_ea, default_ea)
    nop_count = patch_len - 5
    patch = jmp_bytes + (b'\x90' * nop_count)

    if dry_run:
        print(f'  [DRY RUN] Would patch {patch_len} bytes at 0x{patch_ea:08X}')
        print(f'            -> jmp 0x{default_ea:08X} + {nop_count} NOPs')
        return True

    # Apply patch
    ida_bytes.del_items(patch_ea, 0, patch_len)
    _patch_bytes(patch_ea, patch)

    # Recreate as code
    idc.create_insn(patch_ea)
    for i in range(5, patch_len):
        if ida_bytes.get_byte(patch_ea + i) == 0x90:
            idc.create_insn(patch_ea + i)

    # Delete switch info
    si = idaapi.get_switch_info(switch_ea)
    if si:
        deleted = False
        for del_func in [
            lambda ea: ida_nalt.del_switch_info(ea) if ida_nalt else None,
            lambda ea: idaapi.del_switch_info(ea),
        ]:
            try:
                del_func(switch_ea)
                print(f'  Deleted switch_info at 0x{switch_ea:08X}')
                deleted = True
                break
            except Exception:
                continue
        if not deleted:
            print(f'  [WARN] Could not delete switch_info (manual deletion may be needed)')

    # If we patched starting from load_ea (jmp reg case), also clear at switch_ea
    if patch_ea != switch_ea:
        for del_func in [
            lambda ea: ida_nalt.del_switch_info(ea) if ida_nalt else None,
            lambda ea: idaapi.del_switch_info(ea),
        ]:
            try:
                del_func(switch_ea)
                break
            except Exception:
                continue

    # Reanalyze function
    if func:
        ida_auto.plan_range(func.start_ea, func.end_ea)
        ida_auto.auto_wait()

    new_disasm = idc.generate_disasm_line(patch_ea, 0)
    print(f'  Patched:  {new_disasm}')
    print(f'  [OK]')
    return True


def fix_zeroed_switches(dry_run=False):
    """Fix all 7 zeroed switch tables.

    Args:
        dry_run: If True, preview changes without patching.

    Usage:
        fix_zeroed_switches(dry_run=True)   # Preview
        fix_zeroed_switches()               # Apply
    """
    mode = 'DRY RUN' if dry_run else 'PATCH'
    print('=' * 60)
    print(f'Fix Zeroed Switch Tables ({mode})')
    print('=' * 60)

    fixed = 0
    skipped = 0

    for switch_ea, startea, desc in ZEROED_SWITCHES:
        print()
        ok = fix_one_switch(switch_ea, startea, desc, dry_run=dry_run)
        if ok:
            fixed += 1
        else:
            skipped += 1

    print()
    print('=' * 60)
    print(f'Results: {fixed} fixed, {skipped} skipped')
    print('=' * 60)

    if not dry_run and fixed > 0:
        print()
        print('Verifying decompilation (F5)...')
        _verify_decompilation()


def _verify_decompilation():
    """Try F5 on all affected functions and report results."""
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            print('  [WARN] Hex-Rays not available')
            return
    except ImportError:
        print('  [WARN] ida_hexrays not available')
        return

    seen_funcs = set()
    for switch_ea, _, desc in ZEROED_SWITCHES:
        func = ida_funcs.get_func(switch_ea)
        if not func or func.start_ea in seen_funcs:
            continue
        seen_funcs.add(func.start_ea)
        func_name = idc.get_func_name(func.start_ea) or '???'
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                # Count lines as rough complexity measure
                lines = str(cfunc).count('\n')
                print(f'  [OK]   {func_name} (0x{func.start_ea:08X}): '
                      f'F5 success ({lines} lines)')
            else:
                print(f'  [FAIL] {func_name} (0x{func.start_ea:08X}): '
                      f'decompile returned None')
        except Exception as e:
            msg = str(e)
            # Truncate long error messages
            if len(msg) > 80:
                msg = msg[:80] + '...'
            print(f'  [FAIL] {func_name} (0x{func.start_ea:08X}): {msg}')


def revert_zeroed_switches():
    """Revert all patches applied by fix_zeroed_switches()."""
    print('Reverting zeroed switch patches...')
    total_reverted = 0

    for switch_ea, startea, desc in ZEROED_SWITCHES:
        count = 0
        # Revert a generous range around the switch (covers both jmp reg and jmp table)
        scan_start = startea
        scan_end = switch_ea + 8  # max 7-byte instruction + 1

        for ea in range(scan_start, scan_end):
            orig = ida_bytes.get_original_byte(ea)
            curr = ida_bytes.get_byte(ea)
            if orig != curr:
                ida_bytes.revert_byte(ea)
                count += 1

        if count:
            # Reanalyze
            ida_bytes.del_items(scan_start, 0, scan_end - scan_start)
            ea = scan_start
            while ea < scan_end:
                size = idc.create_insn(ea)
                if size > 0:
                    ea += size
                else:
                    ea += 1
            func = ida_funcs.get_func(switch_ea)
            if func:
                ida_auto.plan_range(func.start_ea, func.end_ea)
                ida_auto.auto_wait()
            print(f'  0x{switch_ea:08X}: reverted {count} bytes')
            total_reverted += count
        else:
            print(f'  0x{switch_ea:08X}: no patches to revert')

    print(f'Total: {total_reverted} bytes reverted')


# ============================================================================
# Main
# ============================================================================

try:
    print()
    print('fix_zeroed_switches.py loaded')
    print()
    print('Usage:')
    print('  fix_zeroed_switches(dry_run=True)   # Preview changes')
    print('  fix_zeroed_switches()               # Apply patches')
    print('  revert_zeroed_switches()            # Undo all patches')
    print()
    fix_zeroed_switches(dry_run=True)
except Exception as e:
    print(f'[!] Auto-run error: {e}')
    import traceback
    traceback.print_exc()
    print()
    print('Functions are still available. Try: fix_zeroed_switches(dry_run=True)')
