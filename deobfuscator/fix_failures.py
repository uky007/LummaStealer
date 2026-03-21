"""
Fix decompilation failures:
1. Convert DATA JUMPOUT targets to code
2. Fix NOP-start functions by adjusting entry point
3. Report results

Output: tmp/fix_failures_output.txt
"""
import idc
import ida_funcs
import ida_bytes
import ida_auto
import ida_ua
import ida_hexrays
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUT_FILE = os.path.join(SCRIPT_DIR, 'fix_failures_output.txt')

lines = []
def log(msg):
    print(msg)
    lines.append(msg)

ida_hexrays.init_hexrays_plugin()

log("=" * 70)
log("Fix Decompilation Failures")
log("=" * 70)

# ============================================================
# Fix 1: Convert DATA JUMPOUT targets to code
# ============================================================

log("\n--- Fix 1: DATA → Code at JUMPOUT targets ---")

DATA_TARGETS = [
    0x028275C7,  # Cluster 0, source: 0x028272B0
    0x028290C7,  # Cluster 1, source: 0x02838970
    0x0283A8C8,  # Cluster 3, source: 0x02839F20
    0x0283C873,  # Cluster 3, source: 0x0283C874
    0x0283D675,  # Cluster 3, source: 0x0283D670
    0x0283D96B,  # Cluster 3, source: 0x0283D966
    0x0283DE13,  # Cluster 3, source: 0x0283DE06
    0x0283F2C3,  # Cluster 3, source: 0x0283F290
    # 0x232EE6CF - invalid address, skip
]

fixed_data = 0
for target in DATA_TARGETS:
    flags = ida_bytes.get_full_flags(target)
    if ida_bytes.is_code(flags):
        log(f"  0x{target:08X}: already code")
        fixed_data += 1
        continue

    # Delete items and try to create code
    ida_bytes.del_items(target, ida_bytes.DELIT_EXPAND, 0x20)
    size = idc.create_insn(target)
    if size > 0:
        # Create more instructions after
        ea = target + size
        for _ in range(20):
            s = idc.create_insn(ea)
            if s <= 0:
                break
            ea += s
        log(f"  0x{target:08X}: FIXED → {idc.generate_disasm_line(target, 0)}")
        fixed_data += 1
    else:
        log(f"  0x{target:08X}: FAILED (byte=0x{ida_bytes.get_byte(target):02X})")

log(f"  Fixed: {fixed_data}/{len(DATA_TARGETS)}")

# ============================================================
# Fix 2: Adjust NOP-start functions
# ============================================================

log("\n--- Fix 2: NOP-start function adjustment ---")

NOP_FUNCS = [
    (0x028276C0, "Cluster 0"),
    (0x02827EB0, "Cluster 0"),
    (0x02828035, "Cluster 0"),
    (0x028284F5, "Cluster 0"),
]

fixed_nop = 0
for fea, cname in NOP_FUNCS:
    func = ida_funcs.get_func(fea)
    if not func:
        log(f"  0x{fea:08X}: no function")
        continue

    # Find first non-NOP instruction
    new_start = fea
    while new_start < func.end_ea:
        if ida_bytes.get_byte(new_start) != 0x90:
            break
        new_start += 1

    if new_start == fea:
        log(f"  0x{fea:08X}: doesn't start with NOP")
        continue

    nop_count = new_start - fea
    old_end = func.end_ea
    first_real = idc.generate_disasm_line(new_start, 0)
    log(f"  0x{fea:08X}: {nop_count} leading NOPs, first real: 0x{new_start:08X} {first_real}")

    # Delete old function and create new one starting at first real instruction
    ida_funcs.del_func(fea)
    ok = ida_funcs.add_func(new_start, old_end)
    if not ok:
        ok = ida_funcs.add_func(new_start)

    new_func = ida_funcs.get_func(new_start)
    if new_func:
        # Test F5
        try:
            cfunc = ida_hexrays.decompile(new_start)
            if cfunc:
                pseudo = str(cfunc)
                lc = pseudo.count('\n')
                has_jo = 'JUMPOUT' in pseudo
                log(f"    → FIXED: 0x{new_start:08X} {lc} lines ({'JUMPOUT' if has_jo else 'clean'})")
                fixed_nop += 1
            else:
                log(f"    → Function created but F5 still None")
        except Exception as e:
            log(f"    → Function created but F5 error: {e}")
    else:
        log(f"    → Failed to create function at 0x{new_start:08X}")
        # Restore original
        ida_funcs.add_func(fea, old_end)

log(f"  Fixed: {fixed_nop}/{len(NOP_FUNCS)}")

# ============================================================
# Reanalyze affected areas
# ============================================================

log("\n--- Reanalyzing ---")
for target in DATA_TARGETS:
    if target < 0x2900000:  # skip invalid addresses
        func = ida_funcs.get_func(target)
        if func:
            ida_auto.plan_range(func.start_ea, func.end_ea)
ida_auto.auto_wait()

# ============================================================
# Re-test JUMPOUT functions after fixes
# ============================================================

log("\n--- Re-test JUMPOUT source functions ---")

JUMPOUT_SOURCES = [
    0x028272B0, 0x028276BB, 0x028278A6, 0x02827AF3, 0x02827EAB,
    0x02828030, 0x02838970, 0x02839F20, 0x0283BE32, 0x0283BE95,
    0x0283C0B5, 0x0283C80E, 0x0283C874, 0x0283C8C8, 0x0283CA39,
    0x0283D670, 0x0283D966, 0x0283D9EC, 0x0283DE06, 0x0283E0DE,
    0x0283F290, 0x028405E0,
]

improved = 0
still_jumpout = 0
now_none = 0

for fea in JUMPOUT_SOURCES:
    func = ida_funcs.get_func(fea)
    if not func:
        # Function might have been moved (NOP adjustment)
        log(f"  0x{fea:08X}: no function (may have been adjusted)")
        continue

    actual_ea = func.start_ea
    try:
        cfunc = ida_hexrays.decompile(actual_ea)
        if cfunc:
            pseudo = str(cfunc)
            lc = pseudo.count('\n')
            has_jo = 'JUMPOUT' in pseudo
            if not has_jo:
                log(f"  0x{actual_ea:08X}: IMPROVED → {lc} lines (clean)")
                improved += 1
            else:
                still_jumpout += 1
        else:
            log(f"  0x{actual_ea:08X}: now None")
            now_none += 1
    except Exception as e:
        log(f"  0x{actual_ea:08X}: error: {e}")
        now_none += 1

log(f"\n  JUMPOUT resolved: {improved}")
log(f"  Still JUMPOUT: {still_jumpout}")
log(f"  Became None: {now_none}")

# ============================================================
# Final summary
# ============================================================

log(f"\n--- Final Count ---")

RANGES = [
    (0x028272B0, 0x02828921), (0x0282A3C0, 0x0282DF72),
    (0x02835C40, 0x02836F5D), (0x02839F20, 0x02840A6E),
]

total = 0
f5_ok = 0
f5_clean = 0
f5_none = 0
total_lines = 0

for rng_start, rng_end in RANGES:
    scan = rng_start
    seen = set()
    while scan < rng_end:
        f = ida_funcs.get_func(scan)
        if f and f.start_ea not in seen and f.start_ea >= rng_start:
            seen.add(f.start_ea)
            total += 1
            try:
                cfunc = ida_hexrays.decompile(f.start_ea)
                if cfunc:
                    pseudo = str(cfunc)
                    lc = pseudo.count('\n')
                    f5_ok += 1
                    total_lines += lc
                    if 'JUMPOUT' not in pseudo:
                        f5_clean += 1
                else:
                    f5_none += 1
            except:
                f5_none += 1
            scan = f.end_ea
        else:
            scan += 1

log(f"  Total functions: {total}")
log(f"  F5 success: {f5_ok} ({100*f5_ok//total}%)")
log(f"  Clean: {f5_clean} ({100*f5_clean//total}%)")
log(f"  None/error: {f5_none}")
log(f"  Total lines: {total_lines}")

log(f"\n{'=' * 70}")

with open(OUT_FILE, 'w') as f:
    f.write('\n'.join(lines) + '\n')
log(f"Output: {OUT_FILE}")
