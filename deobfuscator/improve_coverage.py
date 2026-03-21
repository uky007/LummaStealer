"""
Improve decompilation coverage for CFF clusters.
Strategy: create functions for orphan code blocks, then test F5 on each.

For Cluster 2: diagnose the JUMPOUT blocker at 0x02836109.
For Clusters 0/3: create individual functions for uncovered code blocks.

Output: tmp/improve_coverage_output.txt
"""
import idc
import ida_funcs
import ida_auto
import ida_bytes
import ida_ua
import ida_hexrays
import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUT_FILE = os.path.join(SCRIPT_DIR, 'improve_coverage_output.txt')

lines = []
def log(msg):
    print(msg)
    lines.append(msg)

ida_hexrays.init_hexrays_plugin()

log("=" * 70)
log("Improve CFF Decompilation Coverage")
log("=" * 70)

# ============================================================
# Step 1: Create functions for orphan code blocks
# ============================================================

def create_functions_for_orphans(start, end, name):
    """Find code blocks without a function and create functions for them."""
    log(f"\n--- {name}: 0x{start:08X}-0x{end:08X} ---")

    created = 0
    ea = start
    while ea < end:
        flags = ida_bytes.get_full_flags(ea)

        # Skip if already in a function
        func = ida_funcs.get_func(ea)
        if func:
            ea = func.end_ea
            continue

        # Skip if not code
        if not ida_bytes.is_code(flags):
            ea += 1
            continue

        # Found orphan code - try to create a function here
        ok = ida_funcs.add_func(ea)
        if ok:
            new_func = ida_funcs.get_func(ea)
            if new_func:
                created += 1
                ea = new_func.end_ea
                continue

        ea = idc.next_head(ea, end)
        if ea == idc.BADADDR:
            break

    log(f"  Created {created} new functions")
    return created


# Process Cluster 0 and 3 (orphan code)
create_functions_for_orphans(0x028275CF, 0x02828921, "Cluster 0 orphans")
create_functions_for_orphans(0x0283A8D2, 0x02840A6E, "Cluster 3 orphans")

ida_auto.auto_wait()

# ============================================================
# Step 2: Diagnose Cluster 2 JUMPOUT at 0x02836109
# ============================================================

log(f"\n--- Cluster 2 JUMPOUT Diagnosis ---")
target = 0x02836109
log(f"  JUMPOUT target: 0x{target:08X}")
log(f"  Instruction: {idc.generate_disasm_line(target, 0)}")

flags = ida_bytes.get_full_flags(target)
log(f"  Is code: {ida_bytes.is_code(flags)}")

func = ida_funcs.get_func(target)
if func:
    log(f"  In function: 0x{func.start_ea:08X}-0x{func.end_ea:08X}")

# Context around the JUMPOUT target
log(f"  Context:")
ea = target
for _ in range(3):
    ea = idc.prev_head(ea, 0)
    if ea == idc.BADADDR:
        break
ea_start = ea
for _ in range(10):
    if ea == idc.BADADDR or ea > target + 0x30:
        break
    marker = ">>>" if ea == target else "   "
    disasm = idc.generate_disasm_line(ea, 0)
    b = ida_bytes.get_byte(ea)
    log(f"  {marker} 0x{ea:08X} [{b:02X}] {disasm}")
    ea = idc.next_head(ea, target + 0x100)

# ============================================================
# Step 3: Count functions and test F5 on all functions in clusters
# ============================================================

log(f"\n--- F5 Results for All Functions in CFF Ranges ---")

RANGES = [
    (0x028272B0, 0x02828921, "Cluster 0"),
    (0x0282A3C0, 0x0282DF72, "Cluster 1"),
    (0x02835C40, 0x02836F5D, "Cluster 2"),
    (0x02839F20, 0x02840A6E, "Cluster 3"),
]

total_funcs = 0
total_decompiled = 0
total_lines = 0
total_clean = 0

for rng_start, rng_end, name in RANGES:
    log(f"\n  {name}:")
    funcs_in_range = []
    scan = rng_start
    seen = set()
    while scan < rng_end:
        f = ida_funcs.get_func(scan)
        if f and f.start_ea not in seen and f.start_ea >= rng_start:
            seen.add(f.start_ea)
            funcs_in_range.append(f.start_ea)
            scan = f.end_ea
        else:
            scan += 1

    for fea in funcs_in_range:
        func = ida_funcs.get_func(fea)
        if not func:
            continue
        total_funcs += 1
        fsize = func.end_ea - func.start_ea
        try:
            cfunc = ida_hexrays.decompile(fea)
            if cfunc:
                pseudo = str(cfunc)
                lc = pseudo.count('\n')
                has_jo = 'JUMPOUT' in pseudo
                total_decompiled += 1
                total_lines += lc
                if not has_jo:
                    total_clean += 1
                tag = "JUMPOUT" if has_jo else "clean"
                if lc >= 10 or has_jo:
                    log(f"    0x{fea:08X} (0x{fsize:X}): {lc} lines ({tag})")
            else:
                log(f"    0x{fea:08X} (0x{fsize:X}): decompile=None")
        except Exception as e:
            log(f"    0x{fea:08X} (0x{fsize:X}): {type(e).__name__}")

log(f"\n--- Summary ---")
log(f"  Total functions in CFF ranges: {total_funcs}")
log(f"  Successfully decompiled: {total_decompiled}")
log(f"  Clean (no JUMPOUT): {total_clean}")
log(f"  Total pseudocode lines: {total_lines}")

log(f"\n{'=' * 70}")

with open(OUT_FILE, 'w') as f:
    f.write('\n'.join(lines) + '\n')
log(f"Output: {OUT_FILE}")
