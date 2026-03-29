#!/usr/bin/env python3
"""
lumma_decrypt.py - Standalone Lumma Stealer string decryptor using Unicorn emulation

Detects MBA-obfuscated decrypt functions and recovers encrypted strings/data
without IDA Pro or manual algorithm classification.

Approach:
  1. Load PE and extract .text/.data sections (pefile)
  2. Scan for decrypt function prologues (byte pattern matching)
  3. Verify candidates via Unicorn emulation (buffer modification test)
  4. Find call sites via E8 rel32 scanning
  5. Extract encrypted stack bytes from callers (raw byte pattern matching)
  6. Emulate decrypt function with extracted bytes to get plaintext
  7. Classify and output results

Dependencies:
    pip install pefile capstone unicorn

Usage:
    python3 lumma_decrypt.py <pe_file> [-o output.json] [-v] [--validate known.json]
"""

import argparse
import json
import os
import struct
import sys
import uuid
from collections import Counter, defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
from unicorn.x86_const import *

# ============================================================================
# Section 1: PE Loading
# ============================================================================

class PEContext:
    """Holds loaded PE sections and metadata."""

    def __init__(self, path):
        self.path = path
        pe = pefile.PE(path)
        self.image_base = pe.OPTIONAL_HEADER.ImageBase

        # Find .text section
        for sec in pe.sections:
            name = sec.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if name == '.text':
                self.text_va = self.image_base + sec.VirtualAddress
                self.text_raw_offset = sec.PointerToRawData
                self.text_size = sec.SizeOfRawData
                self.text_vsize = sec.Misc_VirtualSize
                break
        else:
            raise ValueError("No .text section found")

        # Find .data section
        self.data_va = 0
        self.data_bytes = b''
        for sec in pe.sections:
            name = sec.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if name == '.data':
                self.data_va = self.image_base + sec.VirtualAddress
                self.data_raw_offset = sec.PointerToRawData
                self.data_size = sec.SizeOfRawData
                break

        # Read raw file
        with open(path, 'rb') as f:
            self.raw = f.read()

        self.text_bytes = self.raw[self.text_raw_offset:
                                   self.text_raw_offset + self.text_size]
        if self.data_va:
            self.data_bytes = self.raw[self.data_raw_offset:
                                       self.data_raw_offset + self.data_size]

        pe.close()

    def va_to_offset(self, va):
        """Convert virtual address to file offset."""
        return va - self.text_va + self.text_raw_offset

    def offset_to_va(self, offset):
        """Convert file offset to virtual address (within .text)."""
        return offset - self.text_raw_offset + self.text_va

    def read_bytes_at_va(self, va, size):
        """Read bytes at a virtual address."""
        if self.text_va <= va < self.text_va + self.text_size:
            off = va - self.text_va
            return self.text_bytes[off:off + size]
        if self.data_va and self.data_va <= va < self.data_va + self.data_size:
            off = va - self.data_va
            return self.data_bytes[off:off + size]
        return None


# ============================================================================
# Section 2: Disassembly Utilities
# ============================================================================

class Disassembler:
    """Capstone-based x86-32 disassembler with index lookup."""

    def __init__(self, text_bytes, text_va):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        self.insns = list(md.disasm(text_bytes, text_va))
        self.addr_to_idx = {insn.address: i for i, insn in enumerate(self.insns)}
        self.text_va = text_va
        self.text_end = text_va + len(text_bytes)

    def get_insn_at(self, addr):
        idx = self.addr_to_idx.get(addr)
        return self.insns[idx] if idx is not None else None

    def insns_in_range(self, start, end):
        si = self.addr_to_idx.get(start)
        if si is None:
            return []
        result = []
        for i in range(si, len(self.insns)):
            if self.insns[i].address >= end:
                break
            result.append(self.insns[i])
        return result


# ============================================================================
# Section 3: Decrypt Function Detection (Prologue Scan)
# ============================================================================

# Prologue byte patterns observed in Lumma Stealer decrypt functions
PROLOGUE_PATTERNS = [
    b'\x83\xec\x14',           # sub esp, 0x14
    b'\x83\xec\x18',           # sub esp, 0x18
    b'\x83\xec\x10',           # sub esp, 0x10
    b'\x56\x83\xec\x14',       # push esi; sub esp, 0x14
    b'\x57\x83\xec\x14',       # push edi; sub esp, 0x14
    b'\x53\x83\xec\x14',       # push ebx; sub esp, 0x14
    b'\x56\x83\xec\x18',       # push esi; sub esp, 0x18
    b'\x57\x83\xec\x18',       # push edi; sub esp, 0x18
    b'\x56\x83\xec\x10',       # push esi; sub esp, 0x10
    b'\x55\x89\xe5\x56',       # push ebp; mov ebp,esp; push esi
]


def scan_prologue_candidates(pe):
    """Scan .text for decrypt function prologues. Returns set of VAs."""
    candidates = set()
    for pat in PROLOGUE_PATTERNS:
        pos = 0
        while True:
            pos = pe.text_bytes.find(pat, pos)
            if pos == -1:
                break
            va = pe.text_va + pos
            candidates.add(va)
            pos += 1
    return sorted(candidates)


# ============================================================================
# Section 4: Unicorn Emulation Engine
# ============================================================================

STACK_BASE = 0x10000000
STACK_SIZE = 0x10000
BUF_BASE   = 0x20000000
BUF_SIZE   = 0x10000
RET_BASE   = 0xDEAD0000
RET_ADDR   = 0xDEADBEEF


def _create_emu(pe):
    """Create a fresh Unicorn emulator with PE sections mapped."""
    emu = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map .text + .data region
    mem_size = max(0x80000, pe.text_size + pe.data_size + 0x10000)
    # Round up to page boundary
    mem_size = (mem_size + 0xFFF) & ~0xFFF
    emu.mem_map(pe.image_base, mem_size)
    emu.mem_write(pe.text_va, pe.text_bytes)
    if pe.data_va and pe.data_bytes:
        emu.mem_write(pe.data_va, pe.data_bytes)

    # Stack
    emu.mem_map(STACK_BASE, STACK_SIZE)

    # Buffer for input/output
    emu.mem_map(BUF_BASE, BUF_SIZE)

    # Return address area
    emu.mem_map(RET_BASE, 0x10000)
    emu.mem_write(RET_ADDR, b'\xcc')  # INT3

    return emu


def emulate_decrypt(pe, func_addr, input_bytes, timeout_us=500000, max_insns=10000):
    """
    Emulate a decrypt function with cdecl calling convention.
    [esp+0] = return address, [esp+4] = buffer pointer
    EAX also set to buffer pointer (some functions use fastcall).
    Returns modified buffer or None on failure.
    """
    try:
        emu = _create_emu(pe)
        size = len(input_bytes)
        emu.mem_write(BUF_BASE, bytes(input_bytes))

        esp = STACK_BASE + STACK_SIZE - 0x200
        emu.reg_write(UC_X86_REG_ESP, esp)
        emu.reg_write(UC_X86_REG_EBP, esp + 0x100)
        emu.mem_write(esp, struct.pack('<I', RET_ADDR))
        emu.mem_write(esp + 4, struct.pack('<I', BUF_BASE))
        emu.reg_write(UC_X86_REG_EAX, BUF_BASE)

        emu.emu_start(func_addr, RET_ADDR, timeout=timeout_us, count=max_insns)

        output = bytes(emu.mem_read(BUF_BASE, size))
        return output
    except UcError:
        return None
    except Exception:
        return None


def verify_decrypt_function(pe, func_addr, verbose=False):
    """
    Multi-probe verification: confirm func_addr is a decrypt function.
    Returns dict with metadata or None if not a decrypt function.
    """
    # Detect buffer size: try increasing sizes, find how many bytes change
    buf_size = None
    for test_size in [8, 16, 32, 64, 128, 256]:
        test_input = bytes([0x00] * test_size)
        output = emulate_decrypt(pe, func_addr, test_input)
        if output is None:
            return None
        changed = sum(1 for a, b in zip(test_input, output) if a != b)
        if changed == 0:
            return None  # Doesn't modify buffer at all
        if changed < test_size:
            # Found the boundary
            buf_size = changed
            break
        buf_size = test_size  # All bytes changed, try larger

    if buf_size is None or buf_size == 0:
        return None

    # Second probe: different input to confirm consistency
    test_a = bytes([0x00] * buf_size)
    test_b = bytes([0x41] * buf_size)
    out_a = emulate_decrypt(pe, func_addr, test_a)
    out_b = emulate_decrypt(pe, func_addr, test_b)
    if out_a is None or out_b is None:
        return None

    # Both must modify exactly buf_size bytes
    changed_a = sum(1 for i in range(buf_size) if test_a[i] != out_a[i])
    changed_b = sum(1 for i in range(buf_size) if test_b[i] != out_b[i])
    if changed_a == 0 or changed_b == 0:
        return None

    # Check linearity: for XOR-based, out_a[i] ^ out_b[i] should equal 0x41
    is_linear = all((out_a[i] ^ out_b[i]) == 0x41 for i in range(buf_size))

    return {
        'address': func_addr,
        'buf_size': buf_size,
        'is_linear': is_linear,
        'key_stream': out_a[:buf_size].hex(),
    }


def detect_decrypt_functions(pe, verbose=False):
    """Full pipeline: prologue scan → emulation verification."""
    candidates = scan_prologue_candidates(pe)
    if verbose:
        print(f"[*] Prologue candidates: {len(candidates)}")

    verified = []
    for i, va in enumerate(candidates):
        result = verify_decrypt_function(pe, va, verbose)
        if result is not None:
            verified.append(result)
        if verbose and (i + 1) % 100 == 0:
            print(f"  Tested {i+1}/{len(candidates)}, verified: {len(verified)}")

    if verbose:
        print(f"[*] Verified decrypt functions: {len(verified)}")
    return verified


# ============================================================================
# Section 5: Cross-Reference Scanner
# ============================================================================

def find_call_sites(pe, func_addrs):
    """
    Scan .text for E8 rel32 (CALL) instructions targeting decrypt functions.
    Returns {func_addr: [call_site_addr, ...]}
    """
    func_set = set(func_addrs)
    xrefs = defaultdict(list)
    text = pe.text_bytes
    text_va = pe.text_va

    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel32 = struct.unpack_from('<i', text, i + 1)[0]
            call_addr = text_va + i
            target = call_addr + 5 + rel32
            if target in func_set:
                xrefs[target].append(call_addr)

    return dict(xrefs)


# ============================================================================
# Section 6: Stack String Extractor
# ============================================================================

def extract_encrypted_bytes(pe, call_addr, expected_size, decrypt_func_addrs,
                            max_scan=768):
    """
    Extract encrypted bytes from stack construction before a CALL.

    Scans raw bytes backward from call_addr looking for:
    - C7 44 24 NN VV VV VV VV     : mov dword [esp+disp8], imm32
    - C7 84 24 NN NN NN NN VV ... : mov dword [esp+disp32], imm32
    - C6 44 24 NN VV              : mov byte [esp+disp8], imm8
    - C6 84 24 NN NN NN NN VV    : mov byte [esp+disp32], imm8
    - 66 C7 44 24 NN VV VV        : mov word [esp+disp8], imm16
    - 66 C7 84 24 NN NN NN NN VV VV : mov word [esp+disp32], imm16

    Also scans for register-relative patterns:
    - C6 4R NN VV                 : mov byte [reg+disp8], imm8  (R=0-7)
    - C7 4R NN VV VV VV VV       : mov dword [reg+disp8], imm32

    Returns extracted bytes or None.
    """
    text = pe.text_bytes
    base = pe.text_va
    call_off = call_addr - base

    # Collect (offset_in_buf, size, value) tuples
    entries_esp = {}    # esp-relative
    entries_reg = {}    # register-relative (eax, ecx, etc.)

    # Scan backward
    scan_start = max(0, call_off - max_scan)

    # Also detect buffer base from LEA
    buf_base_offset = None

    i = scan_start
    while i < call_off:
        b = text[i]

        # --- ESP-relative patterns ---

        # C7 04 24 VV VV VV VV  (mov dword [esp], imm32) -- no displacement
        if b == 0xC7 and i + 1 < call_off and text[i+1] == 0x04 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 6 < call_off:
            val = struct.unpack_from('<I', text, i+3)[0]
            for byte_idx in range(4):
                entries_esp[byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 7
            continue

        # C6 04 24 VV  (mov byte [esp], imm8) -- no displacement
        if b == 0xC6 and i + 1 < call_off and text[i+1] == 0x04 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 3 < call_off:
            val = text[i+3]
            entries_esp[0] = val
            i += 4
            continue

        # 66 C7 04 24 VV VV  (mov word [esp], imm16) -- no displacement
        if b == 0x66 and i + 1 < call_off and text[i+1] == 0xC7 and \
           i + 2 < call_off and text[i+2] == 0x04 and \
           i + 3 < call_off and text[i+3] == 0x24 and i + 5 < call_off:
            val = struct.unpack_from('<H', text, i+4)[0]
            for byte_idx in range(2):
                entries_esp[byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 6
            continue

        # C7 44 24 NN VV VV VV VV  (mov dword [esp+disp8], imm32)
        if b == 0xC7 and i + 1 < call_off and text[i+1] == 0x44 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 7 < call_off:
            disp = text[i+3]
            val = struct.unpack_from('<I', text, i+4)[0]
            for byte_idx in range(4):
                entries_esp[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 8
            continue

        # C7 84 24 NN NN NN NN VV VV VV VV  (mov dword [esp+disp32], imm32)
        if b == 0xC7 and i + 1 < call_off and text[i+1] == 0x84 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 10 < call_off:
            disp = struct.unpack_from('<I', text, i+3)[0]
            val = struct.unpack_from('<I', text, i+7)[0]
            for byte_idx in range(4):
                entries_esp[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 11
            continue

        # C6 44 24 NN VV  (mov byte [esp+disp8], imm8)
        if b == 0xC6 and i + 1 < call_off and text[i+1] == 0x44 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 4 < call_off:
            disp = text[i+3]
            val = text[i+4]
            entries_esp[disp] = val
            i += 5
            continue

        # C6 84 24 NN NN NN NN VV  (mov byte [esp+disp32], imm8)
        if b == 0xC6 and i + 1 < call_off and text[i+1] == 0x84 and \
           i + 2 < call_off and text[i+2] == 0x24 and i + 7 < call_off:
            disp = struct.unpack_from('<I', text, i+3)[0]
            val = text[i+7]
            entries_esp[disp] = val
            i += 8
            continue

        # 66 C7 44 24 NN VV VV  (mov word [esp+disp8], imm16)
        if b == 0x66 and i + 1 < call_off and text[i+1] == 0xC7 and \
           i + 2 < call_off and text[i+2] == 0x44 and \
           i + 3 < call_off and text[i+3] == 0x24 and i + 6 < call_off:
            disp = text[i+4]
            val = struct.unpack_from('<H', text, i+5)[0]
            for byte_idx in range(2):
                entries_esp[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 7
            continue

        # 66 C7 84 24 NN NN NN NN VV VV  (mov word [esp+disp32], imm16)
        if b == 0x66 and i + 1 < call_off and text[i+1] == 0xC7 and \
           i + 2 < call_off and text[i+2] == 0x84 and \
           i + 3 < call_off and text[i+3] == 0x24 and i + 9 < call_off:
            disp = struct.unpack_from('<I', text, i+4)[0]
            val = struct.unpack_from('<H', text, i+8)[0]
            for byte_idx in range(2):
                entries_esp[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 10
            continue

        # --- Register-relative patterns ---

        # C6 00-07 VV  (mov byte [reg], imm8) -- no displacement, reg=[eax]-[edi]
        if b == 0xC6 and i + 1 < call_off and text[i+1] <= 0x07 and \
           text[i+1] != 0x04 and text[i+1] != 0x05 and i + 2 < call_off:
            val = text[i+2]
            entries_reg[0] = val
            i += 3
            continue

        # C7 00-07 VV VV VV VV  (mov dword [reg], imm32) -- no displacement
        if b == 0xC7 and i + 1 < call_off and text[i+1] <= 0x07 and \
           text[i+1] != 0x04 and text[i+1] != 0x05 and i + 5 < call_off:
            val = struct.unpack_from('<I', text, i+2)[0]
            for byte_idx in range(4):
                entries_reg[byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 6
            continue

        # C6 4R NN VV  (mov byte [reg+disp8], imm8) where R = 0x40-0x47
        if b == 0xC6 and i + 1 < call_off and 0x40 <= text[i+1] <= 0x47 and \
           text[i+1] != 0x44 and i + 3 < call_off:  # 0x44 = esp, handled above
            disp = text[i+2]
            val = text[i+3]
            entries_reg[disp] = val
            i += 4
            continue

        # C7 4R NN VV VV VV VV  (mov dword [reg+disp8], imm32)
        if b == 0xC7 and i + 1 < call_off and 0x40 <= text[i+1] <= 0x47 and \
           text[i+1] != 0x44 and i + 6 < call_off:
            disp = text[i+2]
            val = struct.unpack_from('<I', text, i+3)[0]
            for byte_idx in range(4):
                entries_reg[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 7
            continue

        # C6 8R NN NN NN NN VV  (mov byte [reg+disp32], imm8) where 0x80-0x87
        if b == 0xC6 and i + 1 < call_off and 0x80 <= text[i+1] <= 0x87 and \
           text[i+1] != 0x84 and text[i+1] != 0x85 and i + 6 < call_off:
            disp = struct.unpack_from('<I', text, i+2)[0]
            val = text[i+6]
            entries_reg[disp] = val
            i += 7
            continue

        # C7 8R NN NN NN NN VV VV VV VV  (mov dword [reg+disp32], imm32)
        if b == 0xC7 and i + 1 < call_off and 0x80 <= text[i+1] <= 0x87 and \
           text[i+1] != 0x84 and text[i+1] != 0x85 and i + 9 < call_off:
            disp = struct.unpack_from('<I', text, i+2)[0]
            val = struct.unpack_from('<I', text, i+6)[0]
            for byte_idx in range(4):
                entries_reg[disp + byte_idx] = (val >> (byte_idx * 8)) & 0xFF
            i += 10
            continue

        # --- Stop conditions ---

        # E8 xx xx xx xx (CALL) - check if calling another decrypt func
        if b == 0xE8 and i + 4 < call_off and i != call_off:
            rel32 = struct.unpack_from('<i', text, i + 1)[0]
            target = base + i + 5 + rel32
            if target in decrypt_func_addrs:
                # Reset: this is a call to another decrypt function
                entries_esp.clear()
                entries_reg.clear()
            i += 5
            continue

        # C3 (RET) - function boundary
        if b == 0xC3:
            entries_esp.clear()
            entries_reg.clear()

        i += 1

    # Select best collection
    entries = entries_esp if len(entries_esp) >= len(entries_reg) else entries_reg

    if not entries:
        return None

    # Find the best contiguous region of expected_size bytes.
    # Strategy: try each populated offset as a potential base,
    # pick the one with the highest fill ratio.
    sorted_offsets = sorted(entries.keys())
    best_buf = None
    best_filled = 0

    # Candidate bases: every populated offset, plus the minimum offset
    candidate_bases = set(sorted_offsets)
    # Also try offsets where a cluster of entries starts (gap > 4 from previous)
    for i in range(1, len(sorted_offsets)):
        if sorted_offsets[i] - sorted_offsets[i-1] > 4:
            candidate_bases.add(sorted_offsets[i])

    for base in candidate_bases:
        buf = bytearray(expected_size)
        filled = 0
        for offset, val in entries.items():
            idx = offset - base
            if 0 <= idx < expected_size:
                buf[idx] = val
                filled += 1
        if filled > best_filled:
            best_filled = filled
            best_buf = bytes(buf)

    if best_filled < expected_size * 0.5:
        return None

    return best_buf


# ============================================================================
# Section 7: Result Classification
# ============================================================================

def classify_result(data):
    """Classify decrypted bytes into type categories."""
    size = len(data)

    # Strip trailing zeros
    stripped = data.rstrip(b'\x00')
    if not stripped:
        return {'type': 'binary', 'value': data.hex(), 'display': f'(zero, {size}B)'}

    # GUID detection (16 bytes)
    if size == 16:
        guid = format_guid(data)
        if guid:
            return {'type': 'guid', 'value': guid, 'display': guid}

    # DWORD (4 bytes)
    if size == 4:
        val = struct.unpack('<I', data)[0]
        return {'type': 'dword', 'value': f'0x{val:08X}', 'display': f'0x{val:08X}'}

    # Small binary (1-3 bytes)
    if size <= 3:
        return {'type': 'binary', 'value': data.hex(), 'display': data.hex()}

    # Try UTF-8 first (before UTF-16LE, since ASCII is valid UTF-8
    # and would be misinterpreted as CJK in UTF-16LE)
    decoded = try_decode_utf8(stripped)
    if decoded:
        return {'type': 'utf8', 'value': decoded, 'display': decoded}

    # Try UTF-16LE
    decoded = try_decode_utf16le(stripped)
    if decoded:
        return {'type': 'utf16le', 'value': decoded, 'display': decoded}

    # Shellcode detection
    if is_shellcode(data):
        return {'type': 'shellcode', 'value': data.hex(), 'display': f'(shellcode, {size}B)'}

    return {'type': 'binary', 'value': data.hex(), 'display': f'(binary, {size}B)'}


def try_decode_utf16le(data):
    """Try decoding as UTF-16LE string."""
    if len(data) < 2 or len(data) % 2 != 0:
        # Pad if odd
        if len(data) % 2 == 1:
            data = data + b'\x00'
    try:
        s = data.decode('utf-16-le').rstrip('\x00')
        if not s:
            return None
        printable = sum(1 for c in s if c.isprintable() or c in '\t\n\r')
        if printable / len(s) >= 0.7:
            return s
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def try_decode_utf8(data):
    """Try decoding as UTF-8 string."""
    try:
        s = data.rstrip(b'\x00').decode('utf-8')
        if not s:
            return None
        printable = sum(1 for c in s if c.isprintable() or c in '\t\n\r')
        if printable / len(s) >= 0.7:
            return s
    except (UnicodeDecodeError, ValueError):
        pass
    return None


KNOWN_GUIDS = {
    '00021401-0000-0000-c000-000000000046': 'CLSID_ShellLink',
    '000214f9-0000-0000-c000-000000000046': 'IShellLinkA',
    '0000010b-0000-0000-c000-000000000046': 'IPersistFile',
    '4590f811-1d3a-11d0-891f-00aa004b2e24': 'IWbemObjectSink',
    'dc12a687-737f-11cf-884d-00aa004b2e24': 'IClassFactory2',
    '00000000-0000-0000-c000-000000000046': 'IUnknown',
}


def format_guid(data):
    """Format 16 bytes as a GUID string if valid."""
    if len(data) != 16:
        return None
    try:
        # Windows GUID format: DWORD-WORD-WORD-BYTE[2]-BYTE[6]
        d1 = struct.unpack_from('<I', data, 0)[0]
        d2 = struct.unpack_from('<H', data, 4)[0]
        d3 = struct.unpack_from('<H', data, 6)[0]
        d4 = data[8:10].hex()
        d5 = data[10:16].hex()
        guid_str = f'{{{d1:08X}-{d2:04X}-{d3:04X}-{d4.upper()}-{d5.upper()}}}'
        guid_lower = f'{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}'
        name = KNOWN_GUIDS.get(guid_lower, '')
        if name:
            return f'{guid_str} ({name})'
        # Check if it looks like a valid GUID (version/variant bits)
        return guid_str
    except Exception:
        return None


def is_shellcode(data):
    """Basic shellcode detection: x86/x64 instruction patterns."""
    if len(data) < 8:
        return False
    # Common shellcode starts
    starts = [
        b'\x55\x89\xe5',       # push ebp; mov ebp, esp
        b'\xfc\x48',           # cld; dec eax / cld; REX prefix
        b'\x48\x8d',           # lea (x64)
        b'\xe8\x00\x00\x00',   # call $+5 (getpc)
    ]
    for s in starts:
        if data[:len(s)] == s:
            return True
    # High non-printable ratio
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
    return printable / len(data) < 0.1 and len(data) >= 16


# ============================================================================
# Section 8: Main Pipeline
# ============================================================================

def run_pipeline(pe, verbose=False):
    """Execute the full decryption pipeline."""
    results = {
        'summary': {},
        'decrypt_functions': [],
        'entries': [],
    }

    # Step 1: Detect decrypt functions
    print("[*] Step 1: Detecting decrypt functions...")
    funcs = detect_decrypt_functions(pe, verbose)
    print(f"[+] Found {len(funcs)} decrypt functions")
    results['decrypt_functions'] = funcs

    func_addrs = {f['address'] for f in funcs}
    func_buf_sizes = {f['address']: f['buf_size'] for f in funcs}

    # Step 2: Find call sites
    print("[*] Step 2: Scanning for call sites...")
    xrefs = find_call_sites(pe, func_addrs)
    total_calls = sum(len(v) for v in xrefs.values())
    print(f"[+] Found {total_calls} call sites to {len(xrefs)} functions")

    # Step 3: Extract and decrypt
    print("[*] Step 3: Extracting and decrypting...")
    success = 0
    extract_fail = 0
    decrypt_fail = 0

    for func_addr, call_sites in sorted(xrefs.items()):
        buf_size = func_buf_sizes.get(func_addr, 0)
        if buf_size == 0:
            continue

        for call_addr in call_sites:
            # Extract encrypted bytes
            encrypted = extract_encrypted_bytes(
                pe, call_addr, buf_size, func_addrs)

            if encrypted is None:
                extract_fail += 1
                if verbose:
                    print(f"  [!] Extract failed: call 0x{call_addr:08X} -> 0x{func_addr:08X}")
                continue

            # Decrypt via emulation
            decrypted = emulate_decrypt(pe, func_addr, encrypted)
            if decrypted is None:
                decrypt_fail += 1
                continue

            # Classify
            classified = classify_result(decrypted)

            entry = {
                'address': f'0x{call_addr:08X}',
                'func_address': f'0x{func_addr:08X}',
                'size': buf_size,
                'encoding': classified['type'],
                'string': classified.get('value', ''),
                'display': classified.get('display', ''),
                'raw_hex': decrypted.hex(),
            }
            results['entries'].append(entry)
            success += 1

            if verbose and classified['type'] in ('utf8', 'utf16le', 'guid'):
                print(f"  [+] 0x{call_addr:08X}: {classified['display'][:80]}")

    results['summary'] = {
        'decrypt_functions': len(funcs),
        'total_call_sites': total_calls,
        'successful': success,
        'extract_failed': extract_fail,
        'decrypt_failed': decrypt_fail,
    }

    # Type distribution
    type_counts = Counter(e['encoding'] for e in results['entries'])
    results['summary']['type_counts'] = dict(type_counts)

    print(f"\n[+] Results: {success} decrypted, {extract_fail} extract failures, "
          f"{decrypt_fail} decrypt failures")
    for t, c in type_counts.most_common():
        print(f"    {t}: {c}")

    return results


# ============================================================================
# Section 9: Validation
# ============================================================================

def validate_results(results, known_path):
    """Compare results against known good output."""
    with open(known_path) as f:
        known = json.load(f)

    known_addrs = set()
    for e in known['entries']:
        known_addrs.add(e['address'] if isinstance(e['address'], str)
                        else f"0x{e['address']:08X}")

    result_addrs = set(e['address'] for e in results['entries'])

    matched = known_addrs & result_addrs
    missed = known_addrs - result_addrs
    extra = result_addrs - known_addrs

    total_known = len(known['entries'])
    print(f"\n[*] Validation against {known_path}:")
    print(f"    Known entries:  {total_known}")
    print(f"    Our entries:    {len(results['entries'])}")
    print(f"    Matched:        {len(matched)}")
    print(f"    Missed:         {len(missed)}")
    print(f"    Extra:          {len(extra)}")
    if total_known > 0:
        print(f"    Recall:         {len(matched)/total_known:.1%}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Lumma Stealer string decryptor (standalone, no IDA required)')
    parser.add_argument('pe_file', help='Path to Lumma Stealer PE payload')
    parser.add_argument('-o', '--output', default='decrypted_results.json',
                        help='Output JSON file (default: decrypted_results.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--validate', metavar='KNOWN_RESULTS',
                        help='Validate against known results JSON')
    args = parser.parse_args()

    if not os.path.exists(args.pe_file):
        print(f"[!] File not found: {args.pe_file}")
        sys.exit(1)

    print(f"[*] Loading: {args.pe_file}")
    pe = PEContext(args.pe_file)
    print(f"    Image base: 0x{pe.image_base:08X}")
    print(f"    .text: VA=0x{pe.text_va:08X}, size={pe.text_size}")
    if pe.data_va:
        print(f"    .data: VA=0x{pe.data_va:08X}, size={pe.data_size}")

    results = run_pipeline(pe, verbose=args.verbose)

    # Write output
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Results written to: {args.output}")

    # Validate if requested
    if args.validate:
        validate_results(results, args.validate)


if __name__ == '__main__':
    main()
