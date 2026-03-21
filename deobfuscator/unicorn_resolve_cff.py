"""
Resolve CFF dispatcher jump targets using Unicorn CPU emulation.

Emulates the ORIGINAL (unpatched) binary to determine where each
CFF dispatcher jumps to. This resolves the jump table contents
that are computed at runtime on the stack.

Strategy:
  1. Map original PE sections into Unicorn memory
  2. For each CFF function, emulate from entry
  3. At each dispatcher (mov reg,[reg+reg*4]; jmp reg), capture the
     computed destination register value
  4. For conditional dispatchers, emulate both paths (index=0 and index=1)
  5. Output: dispatcher_ea → (target0, target1) map

Usage:
    python3 unicorn_resolve_cff.py
"""

import struct
import json
import os
from collections import defaultdict
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_PATH = os.path.join(SCRIPT_DIR, "sample",
    "de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874_payload.exe")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "cff_resolved_targets.json")

if not os.path.exists(PAYLOAD_PATH):
    print(f"[!] Payload not found: {PAYLOAD_PATH}")
    print(f"[!] Download the sample from MalwareBazaar (SHA256: de67d471...) and")
    print(f"[!] extract the payload PE, then set PAYLOAD_PATH to its location.")
    raise SystemExit(1)

IMAGE_BASE = 0x02800000
TEXT_VA     = 0x02801000
TEXT_OFFSET = 0x400
TEXT_SIZE   = 0x4E200
RDATA_VA    = 0x02850000
RDATA_OFFSET= 0x4E600
RDATA_SIZE  = 0x2000
DATA_VA     = 0x02852000
DATA_OFFSET = 0x50600
DATA_SIZE   = 0x3E00
RELOC_VA    = 0x0285F000
RELOC_OFFSET= 0x54400
RELOC_SIZE  = 0x3400

STACK_BASE  = 0x00100000
STACK_SIZE  = 0x00100000  # 1MB stack
STACK_TOP   = STACK_BASE + STACK_SIZE - 0x1000

# Dummy area for uninitialized reads
DUMMY_BASE  = 0x01000000
DUMMY_SIZE  = 0x00100000

MAX_INSTRUCTIONS = 50000  # max instructions per path
MAX_PATHS = 500           # max paths to explore

# CFF function entries and their cluster ranges
CFF_FUNCTIONS = [
    (0x028272B9, 0x02828921, "Cluster 0"),
    # Start with Cluster 0 only for testing
]

# ============================================================================
# Load PE
# ============================================================================

with open(PAYLOAD_PATH, "rb") as f:
    pe_data = f.read()

text_bytes = pe_data[TEXT_OFFSET:TEXT_OFFSET + TEXT_SIZE]
rdata_bytes = pe_data[RDATA_OFFSET:RDATA_OFFSET + RDATA_SIZE]
data_bytes = pe_data[DATA_OFFSET:DATA_OFFSET + DATA_SIZE]

# Capstone for instruction decoding
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True

# ============================================================================
# Dispatcher detection
# ============================================================================

def is_dispatcher_at(data, offset):
    """Check if bytes at offset are: mov reg,[reg+reg*4]; jmp reg (5 bytes)"""
    if offset + 5 > len(data):
        return False, None
    if data[offset] != 0x8B:
        return False, None
    modrm = data[offset + 1]
    if (modrm >> 6) & 3 != 0 or modrm & 7 != 4:
        return False, None
    sib = data[offset + 2]
    if (sib >> 6) & 3 != 2 or sib & 7 == 5:
        return False, None
    dest = (modrm >> 3) & 7
    if data[offset + 3] != 0xFF or data[offset + 4] != (0xE0 + dest):
        return False, None
    return True, dest


# Find all dispatcher addresses in original binary
dispatcher_addrs = set()
for i in range(len(text_bytes) - 5):
    found, _ = is_dispatcher_at(text_bytes, i)
    if found:
        dispatcher_addrs.add(TEXT_VA + i)

print(f"Found {len(dispatcher_addrs)} dispatchers in original binary")

# ============================================================================
# Unicorn emulation
# ============================================================================

def create_emulator():
    """Create and initialize a Unicorn emulator with PE sections mapped."""
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map PE sections
    # Align to page boundaries
    pe_base = IMAGE_BASE
    pe_size = 0x60000  # covers all sections
    uc.mem_map(pe_base, pe_size, UC_PROT_ALL)

    # Write section contents
    uc.mem_write(TEXT_VA, text_bytes)
    uc.mem_write(RDATA_VA, rdata_bytes)
    uc.mem_write(DATA_VA, data_bytes)

    # Map and initialize stack
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.reg_write(UC_X86_REG_ESP, STACK_TOP)
    uc.reg_write(UC_X86_REG_EBP, STACK_TOP + 0x100)

    # Map dummy area for unmapped reads
    uc.mem_map(DUMMY_BASE, DUMMY_SIZE, UC_PROT_ALL)

    return uc


def emulate_function(func_entry, cluster_end, name):
    """
    Emulate a CFF function to resolve dispatcher targets.
    Uses DFS to explore all paths.
    Returns: dict of dispatcher_ea -> set of resolved targets
    """
    print(f"\n{'='*60}")
    print(f"Emulating {name}: 0x{func_entry:08X}")
    print(f"{'='*60}")

    resolved = defaultdict(set)  # dispatcher_ea -> set of targets
    visited_dispatchers = set()  # (dispatcher_ea, path_context) to avoid infinite loops

    # Queue: (start_ea, initial_state)
    # initial_state = dict of register values to set before starting
    paths_queue = [(func_entry, {})]
    paths_explored = 0

    while paths_queue and paths_explored < MAX_PATHS:
        start_ea, init_state = paths_queue.pop(0)
        paths_explored += 1

        try:
            uc = create_emulator()

            # Apply initial state
            for reg, val in init_state.items():
                uc.reg_write(reg, val)

            # Track execution
            insn_count = [0]
            current_dispatchers = []
            hit_dispatcher = [False]
            dispatcher_target = [0]

            def hook_code(uc, address, size, user_data):
                insn_count[0] += 1
                if insn_count[0] > MAX_INSTRUCTIONS:
                    uc.emu_stop()
                    return

                # Check if we're at a dispatcher
                if address in dispatcher_addrs:
                    # Read the bytes to get dest register
                    try:
                        code = uc.mem_read(address, 5)
                    except:
                        uc.emu_stop()
                        return

                    modrm = code[1]
                    dest_reg_idx = (modrm >> 3) & 7

                    # Map index to Unicorn register constant
                    reg_map = {
                        0: UC_X86_REG_EAX, 1: UC_X86_REG_ECX,
                        2: UC_X86_REG_EDX, 3: UC_X86_REG_EBX,
                        4: UC_X86_REG_ESP, 5: UC_X86_REG_EBP,
                        6: UC_X86_REG_ESI, 7: UC_X86_REG_EDI,
                    }

                    # Let the mov execute, then check the register before jmp
                    # We'll capture it on the jmp instruction instead
                    current_dispatchers.append((address, reg_map[dest_reg_idx]))

                # Check if this is the jmp reg part of a dispatcher
                if current_dispatchers:
                    disp_ea, dest_reg = current_dispatchers[-1]
                    # The jmp is at disp_ea + 3
                    if address == disp_ea + 3:
                        target = uc.reg_read(dest_reg)
                        resolved[disp_ea].add(target)
                        dispatcher_target[0] = target
                        hit_dispatcher[0] = True

                        # Check if this is a conditional dispatcher
                        # Look back for setcc pattern
                        # For now, just continue to the target

                        # Stop current emulation, will restart from target
                        uc.emu_stop()
                        return

                # Skip API calls (call [IAT])
                try:
                    code = bytes(uc.mem_read(address, 6))
                except:
                    uc.emu_stop()
                    return

                if size == 6 and code[0] == 0xFF and code[1] == 0x15:
                    # call [IAT] - skip it
                    # Set eax=1 (success), adjust esp
                    uc.reg_write(UC_X86_REG_EAX, 1)
                    esp = uc.reg_read(UC_X86_REG_ESP)
                    # Don't adjust ESP here, let the call do its thing
                    # Actually, skip by jumping past
                    uc.reg_write(UC_X86_REG_EIP, address + size)
                    return

                if size == 2 and code[0] == 0xFF:
                    op = code[1]
                    # call reg (FF D0-D7) or jmp reg (FF E0-E7)
                    if 0xD0 <= op <= 0xD7:
                        # call reg - check if target is outside .text
                        reg_idx = op - 0xD0
                        reg_const = [UC_X86_REG_EAX, UC_X86_REG_ECX,
                                     UC_X86_REG_EDX, UC_X86_REG_EBX,
                                     UC_X86_REG_ESP, UC_X86_REG_EBP,
                                     UC_X86_REG_ESI, UC_X86_REG_EDI][reg_idx]
                        target = uc.reg_read(reg_const)
                        if target < TEXT_VA or target >= TEXT_VA + TEXT_SIZE:
                            # Skip external call
                            uc.reg_write(UC_X86_REG_EAX, 1)
                            uc.reg_write(UC_X86_REG_EIP, address + size)
                            return

            def hook_mem_invalid(uc, access, address, size, value, user_data):
                # Map unmapped memory on demand
                page = address & ~0xFFF
                try:
                    uc.mem_map(page, 0x1000, UC_PROT_ALL)
                except:
                    pass
                return True

            uc.hook_add(UC_HOOK_CODE, hook_code)
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                       UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)

            # Run emulation
            try:
                uc.emu_start(start_ea, cluster_end, timeout=10000000, count=MAX_INSTRUCTIONS)
            except UcError as e:
                pass  # Expected - we stop at dispatchers

            # If we hit a dispatcher, queue continuation from the target
            if hit_dispatcher[0] and dispatcher_target[0]:
                target = dispatcher_target[0]
                if TEXT_VA <= target < TEXT_VA + TEXT_SIZE:
                    disp_ea = current_dispatchers[-1][0]
                    ctx = (disp_ea, target)
                    if ctx not in visited_dispatchers:
                        visited_dispatchers.add(ctx)
                        paths_queue.append((target, {}))

        except Exception as e:
            print(f"  Path from 0x{start_ea:08X} failed: {e}")

    print(f"  Paths explored: {paths_explored}")
    print(f"  Dispatchers resolved: {len(resolved)}")

    return resolved


# ============================================================================
# Main
# ============================================================================

print("=" * 60)
print("CFF Dispatcher Resolution via Unicorn Emulation")
print("=" * 60)
print(f"Payload: {PAYLOAD_PATH}")
print(f"Dispatchers in binary: {len(dispatcher_addrs)}")

all_resolved = {}

for func_entry, cluster_end, name in CFF_FUNCTIONS:
    resolved = emulate_function(func_entry, cluster_end, name)

    for disp_ea, targets in sorted(resolved.items()):
        targets_list = sorted(targets)
        all_resolved[f"0x{disp_ea:08X}"] = [f"0x{t:08X}" for t in targets_list]

        if len(targets_list) == 1:
            print(f"  0x{disp_ea:08X} → 0x{targets_list[0]:08X}")
        else:
            print(f"  0x{disp_ea:08X} → {', '.join(f'0x{t:08X}' for t in targets_list)}")

# Save results
with open(OUTPUT_FILE, 'w') as f:
    json.dump(all_resolved, f, indent=2)

print(f"\nResults saved to: {OUTPUT_FILE}")
print(f"Total dispatchers resolved: {len(all_resolved)}")
