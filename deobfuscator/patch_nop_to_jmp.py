"""
Replace NOP'd CFF dispatcher regions with jmp-to-next.

Current state: dispatcher regions are NOP sleds (from lumma_fix_cff_v2.py)
Problem: IDA loses flow edges through NOP sleds → JUMPOUT, broken functions
Fix: Replace first 5 bytes of each NOP region with E9 rel32 (jmp after_ea)

Before: 90 90 90 90 90 90 90 90 ... 90 [next code block]
After:  E9 xx xx xx xx 90 90 90 ... 90 [next code block]
                                        ^-- jmp target

Output: tmp/patch_nop_to_jmp_output.txt
"""
import struct
import idc
import ida_bytes
import ida_funcs
import ida_auto
import ida_ua
import ida_segment
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUT_FILE = os.path.join(SCRIPT_DIR, 'patch_nop_to_jmp_output.txt')

lines = []
def log(msg):
    print(msg)
    lines.append(msg)

# ============================================================
# Step 1: Find all NOP regions that were CFF dispatchers
# ============================================================

def find_nop_regions_in_cff():
    """Find NOP sled regions within CFF cluster ranges."""
    CFF_RANGES = [
        (0x028272B9, 0x02828921),
        (0x0282A3C0, 0x0282DF72),
        (0x02835C40, 0x02836F5D),
        (0x02839F29, 0x02840A6E),
    ]

    regions = []
    for cff_start, cff_end in CFF_RANGES:
        ea = cff_start
        while ea < cff_end:
            # Find start of NOP sled (>= 5 consecutive NOPs)
            if ida_bytes.get_byte(ea) == 0x90:
                nop_start = ea
                while ea < cff_end and ida_bytes.get_byte(ea) == 0x90:
                    ea += 1
                nop_len = ea - nop_start
                if nop_len >= 5:
                    regions.append((nop_start, ea, nop_len))
            else:
                ea += 1

    return regions


# ============================================================
# Step 2: Patch NOP regions to jmp-to-next
# ============================================================

log("=" * 70)
log("Patch NOP'd CFF Dispatchers → jmp-to-next")
log("=" * 70)

regions = find_nop_regions_in_cff()
log(f"\nFound {len(regions)} NOP regions (>= 5 bytes) in CFF ranges")

patched = 0
total_bytes = 0

for nop_start, nop_end, nop_len in regions:
    target = nop_end  # jmp to the code right after the NOP sled

    # Calculate E9 rel32
    rel32 = target - (nop_start + 5)
    jmp_bytes = struct.pack('<Bi', 0xE9, rel32)

    # Patch first 5 bytes with jmp
    for i, b in enumerate(jmp_bytes):
        ida_bytes.patch_byte(nop_start + i, b)

    # Delete old items and recreate instruction at the jmp
    ida_bytes.del_items(nop_start, ida_bytes.DELIT_SIMPLE, 5)
    idc.create_insn(nop_start)

    # Recreate NOP instructions for remaining bytes
    for i in range(5, nop_len):
        idc.create_insn(nop_start + i)

    patched += 1
    total_bytes += nop_len

log(f"Patched: {patched} NOP regions → jmp-to-next")
log(f"Total bytes covered: {total_bytes}")

# ============================================================
# Step 3: Rebuild functions
# ============================================================

log(f"\n--- Rebuilding Functions ---")

FUNC_ENTRIES = [
    (0x028272B9, 0x02828921, "Cluster 0"),
    (0x0282A3C0, 0x0282DF72, "Cluster 1"),
    (0x02835C40, 0x02836F5D, "Cluster 2"),
    (0x02839F29, 0x02840A6E, "Cluster 3"),
]

for entry, target_end, name in FUNC_ENTRIES:
    log(f"\n  {name}:")

    # Delete only functions whose START is within the CFF range
    # IMPORTANT: get_func returns the function CONTAINING the address,
    # which may START before our range. Only delete if start_ea is within range.
    deleted = 0
    func_starts_to_delete = []
    scan = entry
    while scan < target_end:
        f = ida_funcs.get_func(scan)
        if f:
            if f.start_ea >= entry and f.start_ea < target_end:
                if f.start_ea not in func_starts_to_delete:
                    func_starts_to_delete.append(f.start_ea)
            scan = max(scan + 1, f.end_ea)
        else:
            scan += 1

    for fs in func_starts_to_delete:
        ida_funcs.del_func(fs)
        deleted += 1
    if deleted:
        log(f"    Deleted {deleted} functions (only those starting within range)")

    # Reanalyze only the CFF range (not surrounding code)
    ida_auto.plan_range(entry, target_end)
    ida_auto.auto_wait()

    # Delete any auto-created fragment functions within range
    scan = entry + 1
    while scan < target_end:
        f = ida_funcs.get_func(scan)
        if f and f.start_ea > entry and f.start_ea < target_end:
            ida_funcs.del_func(f.start_ea)
            scan = f.end_ea
        else:
            scan += 1

    # Create function
    ok = ida_funcs.add_func(entry, target_end)
    func = ida_funcs.get_func(entry)
    if func:
        log(f"    Function: 0x{func.start_ea:08X} - 0x{func.end_ea:08X} "
            f"(size=0x{func.end_ea - func.start_ea:X})")
    else:
        # Try auto-end
        ida_funcs.add_func(entry)
        func = ida_funcs.get_func(entry)
        if func:
            log(f"    Function (auto): 0x{func.start_ea:08X} - 0x{func.end_ea:08X} "
                f"(size=0x{func.end_ea - func.start_ea:X})")
        else:
            log(f"    [FAIL] Cannot create function")

# Final reanalysis
ida_auto.auto_wait()

# ============================================================
# Step 4: Test F5
# ============================================================

log(f"\n--- F5 Decompilation Test ---")

try:
    import ida_hexrays
    has_hexrays = ida_hexrays.init_hexrays_plugin()
except:
    has_hexrays = False

if not has_hexrays:
    log("[!] Hex-Rays not available")
else:
    for entry, target_end, name in FUNC_ENTRIES:
        func = ida_funcs.get_func(entry)
        if not func:
            log(f"  {name}: NO FUNCTION")
            continue

        try:
            cfunc = ida_hexrays.decompile(entry)
            if cfunc:
                pseudocode = str(cfunc)
                line_count = pseudocode.count('\n')
                has_jumpout = 'JUMPOUT' in pseudocode
                log(f"  {name}: SUCCESS - {line_count} lines"
                    f"{' (has JUMPOUT)' if has_jumpout else ' (clean)'}")
            else:
                log(f"  {name}: decompile() returned None")
        except Exception as e:
            log(f"  {name}: {type(e).__name__}: {e}")

log(f"\n{'=' * 70}")

with open(OUT_FILE, 'w') as f:
    f.write('\n'.join(lines) + '\n')
log(f"Output: {OUT_FILE}")
