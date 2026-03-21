"""
Fix functions that fall through without terminator.
Extend function end to include the fall-through code up to the next
jmp/ret/retn terminator.

Output: tmp/fix_fallthrough_output.txt
"""
import idc
import ida_funcs
import ida_bytes
import ida_auto
import ida_ua
import ida_hexrays
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUT_FILE = os.path.join(SCRIPT_DIR, 'fix_fallthrough_output.txt')

lines = []
def log(msg):
    print(msg)
    lines.append(msg)

ida_hexrays.init_hexrays_plugin()

log("=" * 70)
log("Fix Fall-Through Functions")
log("=" * 70)

TARGET_FUNCS = [
    0x028272B0,  # Cluster 0, falls through at 0x028275C7
    0x02839F20,  # Cluster 3, falls through at 0x0283A8C8
]

for fea in TARGET_FUNCS:
    func = ida_funcs.get_func(fea)
    if not func:
        log(f"\n  0x{fea:08X}: no function")
        continue

    log(f"\n--- 0x{fea:08X} ---")
    log(f"  Current: 0x{func.start_ea:08X} - 0x{func.end_ea:08X} (0x{func.end_ea-func.start_ea:X})")

    # Find the next terminator after function end
    new_end = func.end_ea
    ea = func.end_ea
    max_scan = func.end_ea + 0x1000  # scan up to 4KB

    while ea < max_scan:
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            # Try to create instruction
            size = idc.create_insn(ea)
            if size <= 0:
                log(f"  Hit non-decodable byte at 0x{ea:08X}")
                break
            ea += size
            continue

        mnem = idc.print_insn_mnem(ea)
        insn_size = idc.get_item_size(ea)

        if mnem in ('retn', 'ret'):
            new_end = ea + insn_size
            log(f"  Found terminator: 0x{ea:08X} {mnem}")
            break
        elif mnem == 'jmp':
            new_end = ea + insn_size
            log(f"  Found terminator: 0x{ea:08X} {idc.generate_disasm_line(ea, 0)}")
            break
        elif mnem == 'int3':
            new_end = ea
            log(f"  Found int3 at 0x{ea:08X}")
            break

        ea = idc.next_head(ea, max_scan)
        if ea == idc.BADADDR:
            break

    if new_end <= func.end_ea:
        log(f"  No terminator found, cannot extend")
        continue

    extend_size = new_end - func.end_ea
    log(f"  Extending by 0x{extend_size:X} bytes to 0x{new_end:08X}")

    # Delete any blocking functions in the extension area
    scan = func.end_ea
    while scan < new_end:
        f2 = ida_funcs.get_func(scan)
        if f2 and f2.start_ea >= func.end_ea and f2.start_ea < new_end:
            log(f"  Deleting blocking function: 0x{f2.start_ea:08X}")
            ida_funcs.del_func(f2.start_ea)
            scan = f2.end_ea
        else:
            scan += 1

    # Try to extend
    ok = ida_funcs.set_func_end(func.start_ea, new_end)
    if ok:
        func = ida_funcs.get_func(fea)
        log(f"  Extended: 0x{func.start_ea:08X} - 0x{func.end_ea:08X}")
    else:
        # Try append_func_tail
        ok2 = ida_funcs.append_func_tail(func, func.end_ea, new_end)
        if ok2:
            log(f"  Added as tail chunk: 0x{func.end_ea:08X} - 0x{new_end:08X}")
        else:
            log(f"  [FAIL] Cannot extend or add tail chunk")
            continue

    # Reanalyze
    ida_auto.plan_range(func.start_ea, new_end)
    ida_auto.auto_wait()

    # Test F5
    func = ida_funcs.get_func(fea)
    if func:
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                pseudo = str(cfunc)
                lc = pseudo.count('\n')
                has_jo = 'JUMPOUT' in pseudo
                log(f"  F5: {lc} lines ({'JUMPOUT' if has_jo else 'CLEAN!'})")
            else:
                log(f"  F5: None")
        except Exception as e:
            log(f"  F5 error: {e}")

# Final count
log(f"\n--- Final Count ---")
RANGES = [
    (0x028272B0, 0x02828921), (0x0282A3C0, 0x0282DF72),
    (0x02835C40, 0x02836F5D), (0x02839F20, 0x02840A6E),
]
total = f5_ok = f5_clean = total_lines = 0
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
                    f5_ok += 1
                    total_lines += pseudo.count('\n')
                    if 'JUMPOUT' not in pseudo:
                        f5_clean += 1
            except:
                pass
            scan = f.end_ea
        else:
            scan += 1

log(f"  Total: {total}, F5 OK: {f5_ok}, Clean: {f5_clean}, Lines: {total_lines}")

log(f"\n{'=' * 70}")

with open(OUT_FILE, 'w') as f:
    f.write('\n'.join(lines) + '\n')
log(f"Output: {OUT_FILE}")
