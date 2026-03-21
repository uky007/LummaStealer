"""
Restore original control flow for resolved CFF dispatchers.
Replace NOP/jmp-to-next with proper jcc/jmp instructions using
the resolved jump table targets.

For unconditional: jmp target (5 bytes)
For conditional:   jcc target1 (6 bytes) + jmp target0 (5 bytes)

Input: cff_cluster3_resolved.json
Output: tmp/restore_control_flow_output.txt
"""
import struct
import json
import idc
import ida_bytes
import ida_funcs
import ida_auto
import ida_ua
import ida_hexrays
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
OUT_FILE = os.path.join(SCRIPT_DIR, 'restore_control_flow_output.txt')
RESOLVED_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), 'cff_cluster3_resolved.json')

lines = []
def log(msg):
    print(msg)
    lines.append(msg)

with open(RESOLVED_FILE) as f:
    data = json.load(f)

resolved = data['resolved']
log("=" * 70)
log(f"Restore Control Flow - Cluster 3")
log(f"Resolved dispatchers: {len(resolved)}")
log("=" * 70)

# setcc byte → jcc opcode mapping (0F 8x)
SETCC_TO_JCC = {
    0x90: 0x80,  # seto  → jo
    0x91: 0x81,  # setno → jno
    0x92: 0x82,  # setb  → jb
    0x93: 0x83,  # setae → jae
    0x94: 0x84,  # sete  → je
    0x95: 0x85,  # setne → jne
    0x96: 0x86,  # setbe → jbe
    0x97: 0x87,  # seta  → ja
    0x98: 0x88,  # sets  → js
    0x99: 0x89,  # setns → jns
    0x9A: 0x8A,  # setp  → jp
    0x9B: 0x8B,  # setnp → jnp
    0x9C: 0x8C,  # setl  → jl
    0x9D: 0x8D,  # setge → jge
    0x9E: 0x8E,  # setle → jle
    0x9F: 0x8F,  # setg  → jg
}


def find_nop_region(ea):
    """Find the NOP/E9-jmp region around a dispatcher address."""
    # Search backward for the start of the NOP/E9 region
    start = ea
    while start > ea - 0x40:
        b = ida_bytes.get_byte(start - 1)
        if b == 0x90 or b == 0xE9:
            start -= 1
        else:
            break

    # Search forward for the end
    end = ea
    while end < ea + 0x40:
        b = ida_bytes.get_byte(end)
        if b == 0x90:
            end += 1
        elif b == 0xE9 and end == start:
            # E9 jmp at start - skip the 5-byte jmp
            end += 5
        else:
            break

    return start, end


def find_setcc_before(ea):
    """Find the setcc instruction before ea. Returns (setcc_ea, setcc_byte) or None."""
    # Use original bytes to find setcc
    scan = ea
    for _ in range(30):
        scan = idc.prev_head(scan, ea - 0x100)
        if scan == idc.BADADDR:
            break
        b0 = ida_bytes.get_original_byte(scan)
        b1 = ida_bytes.get_original_byte(scan + 1)
        if b0 == 0x0F and 0x90 <= b1 <= 0x9F:
            return scan, b1
    return None, None


def patch_unconditional(disp_ea, target):
    """Replace dispatcher with jmp target."""
    nop_start, nop_end = find_nop_region(disp_ea)
    nop_size = nop_end - nop_start

    if nop_size < 5:
        return False, f"NOP region too small ({nop_size}B)"

    # Write E9 rel32 (jmp target)
    rel32 = target - (nop_start + 5)
    jmp_bytes = struct.pack('<Bi', 0xE9, rel32)

    for i, b in enumerate(jmp_bytes):
        ida_bytes.patch_byte(nop_start + i, b)

    # NOP remaining bytes
    for i in range(5, nop_size):
        ida_bytes.patch_byte(nop_start + i, 0x90)

    # Recreate instructions
    ida_bytes.del_items(nop_start, ida_bytes.DELIT_SIMPLE, nop_size)
    ea = nop_start
    while ea < nop_end:
        size = idc.create_insn(ea)
        if size <= 0:
            ea += 1
        else:
            ea += size

    return True, f"jmp 0x{target:08X} at 0x{nop_start:08X}"


def patch_conditional(disp_ea, target0, target1):
    """Replace dispatcher with jcc target1 + jmp target0."""
    nop_start, nop_end = find_nop_region(disp_ea)
    nop_size = nop_end - nop_start

    if nop_size < 11:
        # Not enough space for jcc (6) + jmp (5) = 11 bytes
        # Fall back to unconditional jmp to target0 (more likely path)
        return patch_unconditional(disp_ea, target0)

    # Find the setcc type to determine jcc opcode
    setcc_ea, setcc_byte = find_setcc_before(disp_ea)

    if setcc_byte is None:
        # Can't determine condition, use unconditional jmp
        return patch_unconditional(disp_ea, target0)

    jcc_byte = SETCC_TO_JCC.get(setcc_byte)
    if jcc_byte is None:
        return patch_unconditional(disp_ea, target0)

    # Write 0F 8x rel32 (jcc target1) - 6 bytes
    jcc_rel32 = target1 - (nop_start + 6)
    ida_bytes.patch_byte(nop_start, 0x0F)
    ida_bytes.patch_byte(nop_start + 1, jcc_byte)
    for i, b in enumerate(struct.pack('<i', jcc_rel32)):
        ida_bytes.patch_byte(nop_start + 2 + i, b)

    # Write E9 rel32 (jmp target0) - 5 bytes
    jmp_rel32 = target0 - (nop_start + 6 + 5)
    ida_bytes.patch_byte(nop_start + 6, 0xE9)
    for i, b in enumerate(struct.pack('<i', jmp_rel32)):
        ida_bytes.patch_byte(nop_start + 7 + i, b)

    # NOP remaining bytes
    for i in range(11, nop_size):
        ida_bytes.patch_byte(nop_start + i, 0x90)

    # Recreate instructions
    ida_bytes.del_items(nop_start, ida_bytes.DELIT_SIMPLE, nop_size)
    ea = nop_start
    while ea < nop_end:
        size = idc.create_insn(ea)
        if size <= 0:
            ea += 1
        else:
            ea += size

    setcc_names = {0x94:'je',0x95:'jne',0x9C:'jl',0x9D:'jge',0x9E:'jle',0x9F:'jg',
                   0x92:'jb',0x93:'jae',0x96:'jbe',0x97:'ja'}
    jcc_name = setcc_names.get(setcc_byte, f'j_{setcc_byte:02X}')
    return True, f"{jcc_name} 0x{target1:08X} / jmp 0x{target0:08X} at 0x{nop_start:08X}"


# Apply patches
patched_uncond = 0
patched_cond = 0
failed = 0

for r in resolved:
    disp_ea = r['disp']

    if r['type'] == 'unconditional':
        ok, msg = patch_unconditional(disp_ea, r['target'])
        if ok:
            patched_uncond += 1
        else:
            log(f"  [FAIL] 0x{disp_ea:08X}: {msg}")
            failed += 1

    elif r['type'] == 'conditional':
        ok, msg = patch_conditional(disp_ea, r['target0'], r['target1'])
        if ok:
            patched_cond += 1
        else:
            log(f"  [FAIL] 0x{disp_ea:08X}: {msg}")
            failed += 1

log(f"\nPatched: {patched_uncond} unconditional + {patched_cond} conditional = {patched_uncond + patched_cond}")
log(f"Failed: {failed}")

# Reanalyze
log(f"\nReanalyzing...")
ida_auto.plan_range(0x02839F20, 0x02840A6E)
ida_auto.auto_wait()

# Test F5
log(f"\n--- F5 Test (Cluster 3 main functions) ---")
ida_hexrays.init_hexrays_plugin()

TEST_FUNCS = [0x02839F20, 0x0283D3C3, 0x0283CB50, 0x0283CD10, 0x0283F560]

for fea in TEST_FUNCS:
    func = ida_funcs.get_func(fea)
    if not func:
        log(f"  0x{fea:08X}: no function")
        continue
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            pseudo = str(cfunc)
            lc = pseudo.count('\n')
            has_jo = 'JUMPOUT' in pseudo
            has_if = 'if' in pseudo
            log(f"  0x{func.start_ea:08X}: {lc} lines ({'JUMPOUT' if has_jo else 'clean'}) "
                f"{'has if/else!' if has_if else 'no branches'}")
        else:
            log(f"  0x{func.start_ea:08X}: None")
    except Exception as e:
        log(f"  0x{func.start_ea:08X}: {e}")

# Final count
log(f"\n--- Final Cluster 3 Count ---")
total = f5_ok = f5_clean = total_lines = 0
scan = 0x02839F20
seen = set()
while scan < 0x02840A6E:
    f = ida_funcs.get_func(scan)
    if f and f.start_ea not in seen and f.start_ea >= 0x02839F20:
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
