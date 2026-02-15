"""
Lumma Stealer String Deobfuscator - IDA Python Script
Author: Security Research Assistant
Target: Lumma Stealer (SHA256: de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874)

This script deobfuscates strings in Lumma Stealer malware by:
1. Auto-detecting string decryption functions (Type1-5)
2. Loading known decrypt functions with non-standard patterns (Type6-11)
3. Extracting XOR keys and algorithm parameters
4. Decrypting stack strings using detected MBA (Mixed Boolean-Arithmetic) algorithms
5. Adding comments to IDA database

=== MBA Obfuscation Techniques (11 Types) ===

Type1: XOR + NOT + OR + ADD (most common)
    result = (byte XOR (i XOR xor_key)) + add_value

Type2: Alternative XOR (fallback)
    Similar to Type1 with different MBA structure

Type3: Mask-based SUB (steamcommunity URL)
    result = (tmp & mask2) - ((tmp & mask1) ^ mask1)
    Masks are complementary: mask1 | mask2 = 0xFF

Type4: SHL + AND + SUB (Content-Type headers)
    result = ((tmp << 1) & shl_mask) - (tmp ^ xor_val)

Type5: MBA + Type4 Combined
    MBA result + Type4 transformation

Type6: Modified Key + SUB (powershell commands)
    key = i - ((2*i) & key_mask) + key_const
    result = (byte XOR key) - sub_val
    Example: key_mask=0x34, key_const=26, sub_val=24

Type7: Simple XOR Key + Mask SUB
    key = i ^ xor_key
    result = (mba & mask1) - ((mba & mask2) ^ mask2)
    Example: xor_key=0x1C, mask1=0x6F, mask2=0x90

Type8: Modified Key + ADD (NT API functions)
    key = i - ((2*i) & key_mask) + key_const
    result = (byte XOR key) + add_val
    Example: key_mask=0x5E, key_const=-81, add_val=124
    Decrypts: NtFreeVirtualMemory

Type9: XNOR + Rotating Key + SUB (browser files)
    key = ((~i | 7) & (i | 0xF8)) & 0xFF
    Key sequence: F8 F9 FA FB FC FD FE FF F0 F1 F2 F3...
    result = XNOR(byte, key) - sub_val
    Decrypts: key4.db (UTF-16LE)

Type10: Simple XOR (i + offset)
    key = (i + key_offset) & 0xFF
    result = byte XOR key
    Example: key_offset=0x80

Type11: XOR + SUB with index offset (HTTP Content-Type)
    key = (i + index_offset) ^ xor_key
    result = (byte XOR key) - sub_val
    Example: xor_key=0x91, sub_val=124, index_offset=29 (from buffer layout)
    Decrypts: application/x-www-form-urlencoded

Usage in IDA:
    File -> Script file -> lumma_deobfuscator.py

    Then run:
        deobfuscate_all_with_comments()  # Full analysis + IDA comments
        export_strings("output.txt")     # Export to file

    To add new decrypt functions:
        add_decrypt_function(0xADDRESS, loop_count, algo_type, **params)
"""

import os
import json
import idc
import idaapi
import idautils
import ida_bytes
import ida_name
import ida_funcs
import ida_search
import ida_ua
import struct
import re

# ============================================================================
# Auto-detected Decryption Functions (will be populated at runtime)
# Format: {address: (loop_count, xor_key, add_value, algo_type, mask1, mask2)}
# algo_type: 1-10 for different algorithm types
# ============================================================================

DECRYPT_FUNCTIONS = {}

# ============================================================================
# Known Decrypt Functions (manually identified, merged during auto-detect)
# These are functions with non-standard patterns that can't be auto-detected
#
# Format: {address: (loop_count, xor_key, add_value, algo_type, param1, param2)}
#
# Algorithm Types:
#   Type1: XOR + NOT + OR + ADD         - (loop, xor_key, add_val, 1, 0, 0)
#   Type3: Mask-based SUB               - (loop, xor_key, 0, 3, mask1, mask2)
#   Type4: SHL + AND + SUB              - (loop, xor_key, 0, 4, xor_val, shl_mask)
#   Type5: MBA + Type4                  - (loop, xor_key, 0, 5, xor_val, shl_mask)
#   Type6: Modified key + SUB           - (loop, 0, 0, 6, key_mask, key_const<<8|sub_val)
#   Type7: Simple XOR + mask SUB        - (loop, xor_key, 0, 7, mask1, mask2)
#   Type8: Modified key + ADD           - (loop, 0, 0, 8, key_mask, key_const<<8|add_val)
#   Type9: XNOR + rotating key + SUB    - (loop, 0, sub_val, 9, 0, 0)
#   Type10: Simple XOR (i + offset)     - (loop, 0, 0, 10, key_offset, 0)
#   Type11: XOR + SUB with index offset - (loop, xor_key, sub_val, 11, 0, 0)
# ============================================================================

KNOWN_DECRYPT_FUNCTIONS = {
    # Type6: key = i - ((2*i) & key_mask) + key_const, then SUB
    # sub_281C040: key_mask=0x34, key_const=26, sub_val=24
    0x281C040: (0x32, 0, 0, 6, 0x34, (26 << 8) | 24),

    # Type7: key = i ^ xor_key, MBA, then (mba & mask1) - ((mba & mask2) ^ mask2)
    # sub_2824410: xor_key=0x1C, mask1=0x6F, mask2=0x90
    0x2824410: (0x14, 0x1C, 0, 7, 0x6F, 0x90),
    # sub_2811460: xor_key=0x23, mask1=0x4B, mask2=0xB4
    # Decrypts: "winhttp.dll" (UTF-16LE)
    0x2811460: (0x18, 0x23, 0, 7, 0x4B, 0xB4),
    # sub_2819DE0: xor_key=0xBE, mask1=0x77, mask2=0x88
    0x2819DE0: (0x7C, 0xBE, 0, 7, 0x77, 0x88),

    # Type8: key = i - ((2*i) & key_mask) + key_const, then ADD
    # sub_2824380: key_mask=0x5E, key_const=-81, add_val=124
    0x2824380: (0x14, 0, 0, 8, 0x5E, ((-81 & 0xFF) << 8) | 124),

    # Type9: key = ((~i | 7) & (i | 0xF8)), XNOR, then SUB
    # sub_28293C0: sub_val=36
    0x28293C0: (0x10, 0, 36, 9, 0, 0),

    # Type10: key = i + key_offset, simple XOR
    # sub_282A8A0: key_offset=0x80
    0x282A8A0: (0x10, 0, 0, 10, 0x80, 0),

    # Type1 variants with non-standard xor_key (not auto-detected)
    # sub_282A930: xor_key=0x97, add_val=28 -> decrypts to GUID {0000010B-...} (IPersistFile)
    0x282A930: (0x10, 0x97, 28, 1, 0, 0),

    # Type11: XOR + SUB with index offset
    # sub_282E1F0: xor_key=0x91, sub_val=124
    # Buffer layout causes index_offset (var_14C - var_12F = 29), calculated at extraction time
    # Decrypts: "pplication/x-www-form-urlencoded\r\n" (missing 'a' - malware author bug)
    # Function loops 100 (0x64) bytes, but encrypted data is only 71 (0x47) bytes at call site
    # Using 0x47 to prevent extraction of trailing garbage bytes
    0x282E1F0: (0x47, 0x91, 124, 11, 0, 0),

    # Type4 variant with small xor_key
    # sub_2838580: xor_key=0x51, xor_val=0x7C, shl_mask=0x06
    # Decrypts: "\Local Storage\leveldb" (Chromium browser path)
    0x2838580: (0x2E, 0x51, 0, 4, 0x7C, 0x06),

    # Type1: (byte XOR (i ^ xor_key)) - 12
    # sub_2841A60: xor_key=0xED, add_val=-12
    # Decrypts: SQL query (UTF-16LE)
    0x2841A60: (0x48, 0xED, -12, 1, 0, 0),

    # Type1: (byte XOR (i ^ xor_key)) + 24
    # sub_2843780: xor_key=0xE6, add_val=24
    0x2843780: (0xF, 0xE6, 24, 1, 0, 0),

    # Type12: XNOR with complex key + add
    # sub_28459F0: or_val1=0x6B, or_val2=0x94, add_val=108
    # key = (~i | 0x6B) & (i | 0x94), result = XNOR(key, byte) + 108
    # Decrypts: "This country is not supported!"
    0x28459F0: (0x3E, 0, 0, 12, (0x6B << 8) | 0x94, 108),

    # Type1: (byte XOR (i ^ 7)) - 36
    # sub_2845A80: xor_key=7, add_val=-36
    # Decrypts: "Warning"
    0x2845A80: (0x10, 7, -36, 1, 0, 0),

    # Type1: (byte XOR (i ^ 0xBB)) - 84
    # sub_2831190: xor_key=0xBB, add_val=-84
    # Decrypts: "Microsoft\Office\13.0\Outlook\Profiles\Outlook\9375CFF0..." (UTF-16LE)
    # Previously auto-detected with wrong params, producing garbled separator pattern
    0x2831190: (0xA2, 0xBB, -84, 1, 0, 0),

    # Type1: byte ^ (i ^ 0xA0)  [MBA with final XOR 0x80: (byte^(i^0x20))^0x80]
    # sub_2831220: xor_key=0xA0, add_val=0
    # Decrypts: "Microsoft\Office\14.0\Outlook\Profiles\Outlook\9375CFF0..." (UTF-16LE)
    # Previously auto-detected with wrong params, producing separator pattern (0x31)
    0x2831220: (0xA2, 0xA0, 0, 1, 0, 0),

    # ========================================================================
    # Auto-detected entries with wrong parameters (offline fixer batch)
    # These functions use AND+NEG+LEA MBA obfuscation for key generation:
    #   key = i - ((2*i) & mask) + const
    # which simplifies to key = i ^ const (when mask = (2*const) & 0xFF).
    # The auto-detector fails on these due to:
    #   (a) negative LEA displacement captured as positive (sign bug)
    #   (b) final XOR after ADD not accounted for
    #   (c) no large XOR/LEA constant found (small xor_key < 0xFFFF)
    # ========================================================================

    # --- Type1 entries (21): result = (byte ^ (i ^ xor_key)) + add_val ---
    0x280E150: (0x04, 0x79, 36, 1, 0, 0),
    0x280E290: (0x04, 0xB7, -100, 1, 0, 0),
    0x280E330: (0x04, 0xB2, 72, 1, 0, 0),
    0x28117E0: (0x04, 0x18, 96, 1, 0, 0),   # fixer had LEA overwrite bug (captured MBA LEA not key LEA)
    0x281AB30: (0x04, 0x39, 36, 1, 0, 0),
    0x281AFD0: (0x02, 0xA3, 76, 1, 0, 0),
    0x281B250: (0x02, 0xFD, 52, 1, 0, 0),
    0x281BBA0: (0x0A, 0x22, 8, 1, 0, 0),
    0x28238C0: (0x04, 0xCF, -4, 1, 0, 0),
    0x2823B60: (0x04, 0xA8, -96, 1, 0, 0),
    0x2826220: (0x04, 0x01, 68, 1, 0, 0),
    0x2829010: (0x12, 0x9F, 60, 1, 0, 0),
    0x282A810: (0x10, 0x31, 4, 1, 0, 0),
    0x282AA40: (0x02, 0x7E, 120, 1, 0, 0),
    0x282E310: (0x04, 0xA9, -28, 1, 0, 0),
    0x2831620: (0x12, 0x41, 68, 1, 0, 0),
    0x2841C80: (0x22, 0xCE, -72, 1, 0, 0),
    0x2841D20: (0x0A, 0xE2, 8, 1, 0, 0),
    0x2842290: (0x0C, 0x78, -32, 1, 0, 0),
    0x2845FD0: (0x04, 0xBC, -16, 1, 0, 0),
    0x284CDB0: (0x05, 0x2A, 40, 1, 0, 0),
    0x284CE40: (0x03, 0x83, -52, 1, 0, 0),

    # --- Type3 entries (3): mask-based SUB ---
    # result = (tmp & mask2) - ((tmp & mask1) ^ mask1), where tmp = byte ^ (i ^ xor_key)
    # sub_2841B70: key = i ^ 0x16A76C6F (low=0x6F), mask1=0x84, mask2=0x7B
    0x2841B70: (0x10, 0x6F, 0, 3, 0x84, 0x7B),
    0x2825B30: (0x1C, 0xBD, 0, 3, 0xCC, 0x33),
    0x2845E80: (0x04, 0xD1, 0, 3, 0x7C, 0x83),
    # sub_2826D40: Type3 misclassified as Type1 — AND+NEG+LEA key with mask-based SUB post-processing
    # key = i ^ 0xB3, masks 0x74/0x8B. Decrypts: "\Local Extension Settings\" (UTF-16LE)
    0x2826D40: (0x36, 0xB3, 0, 3, 0x74, 0x8B),
    # sub_2825130: Type3 misclassified as Type1 — AND+NEG+LEA key with mask-based SUB
    # key = i ^ 0x50, masks 0xC0/0x3F. Decrypts: "%ProgramW6432%\" (UTF-16LE)
    0x2825130: (0x20, 0x50, 0, 3, 0xC0, 0x3F),
    # sub_2840CD0: Type3 with direct XOR key (i ^ 0xA2726855, low=0x55), masks 0x6C/0x93
    0x2840CD0: (0x10, 0x55, 0, 3, 0x6C, 0x93),

    # --- Type4 entries (6): SHL+AND+SUB ---
    # result = ((tmp << 1) & shl_mask) - (tmp ^ xor_val), where tmp = byte ^ (i ^ xor_key)
    0x281A3E0: (0x02, 0xC6, 0, 4, 0x68, 0x2E),
    0x281BF90: (0x04, 0x82, 0, 4, 0x78, 0x0E),
    0x2825960: (0x06, 0x48, 0, 4, 0xE0, 0x3E),
    0x2841720: (0x04, 0x18, 0, 4, 0xA0, 0xBE),
    0x284A290: (0x01, 0xD2, 0, 4, 0x38, 0x8E),
    0x284CFD0: (0x09, 0xEE, 0, 4, 0xC8, 0x6E),
    # sub_2838730: Type4 misclassified as Type5 — direct XOR key (i ^ 0x4B95042B, low=0x2B)
    # Decrypts: "%AppData%\Notepad++\session.xml" (UTF-16LE)
    0x2838730: (0x40, 0x2B, 0, 4, 0x94, 0xD6),

    # --- Additional Type1: auto-detect xor_key mismatch ---
    # sub_28266B0: AND mask=0xD323A822 (low=0x22), correct xor_key=0x11, add=0x84
    # Auto-detect extracts wrong xor_key from negative LEA displacement
    # Decrypts: "info_cache"
    0x28266B0: (0x0B, 0x11, 0x84, 1, 0, 0),
    # sub_2823660: literal XOR 0x35985878 (low=0x78), but auto-detect uses 0x8C
    # Correct decryption produces x86-64 shellcode (48 8D 05... = lea rax,[rip+...])
    0x2823660: (0x15, 0x78, 0xE0, 1, 0, 0),
    # sub_028382F0: SHL+XOR+SUB post-processing simplifies to XOR 0x80
    # key = i ^ 0x20, result = tmp ^ 0x80 = byte ^ (i ^ 0xA0). Decrypts: "DiscordPTB" (UTF-16LE)
    0x28382F0: (0x16, 0xA0, 0, 1, 0, 0),
    # sub_2840C50: direct XOR (i ^ 0x336A5E4A, low=0x4A) + ADD 0xA8
    # Auto-detect gets wrong xor_key
    0x2840C50: (0x10, 0x4A, 0xA8, 1, 0, 0),
    # sub_2841C00: key = i ^ 0xE9388CAD (low=0xAD) + ADD 0xF4
    0x2841C00: (0x10, 0xAD, 0xF4, 1, 0, 0),
    # sub_28464E0: key = i ^ 0xFD312124 (low=0x24) + ADD 0x90
    0x28464E0: (0x10, 0x24, 0x90, 1, 0, 0),
    # sub_2846560: key = i ^ 0xD5AD2973 (low=0x73) + ADD 0x8C
    0x2846560: (0x10, 0x73, 0x8C, 1, 0, 0),
    # sub_28499D0: key = i ^ 0x9E2139F7 (low=0xF7), obfuscated ADD 0x9C
    # ADD obfuscation: ((x<<1)&0x36) - (x^0x64) = x + 0x9C. "NtQueryVirtualMemory"
    0x28499D0: (0x15, 0xF7, 0x9C, 1, 0, 0),
    # sub_284CB50: key = i ^ 0xA3A0B4DE (low=0xDE), obfuscated ADD 0xF8
    # ADD obfuscation: ((x<<1)&0xEE) - (x^0x08) = x + 0xF8. x64 syscall stub (16 bytes)
    0x284CB50: (0x10, 0xDE, 0xF8, 1, 0, 0),
    # sub_284CCF0: key = i ^ 0x75957BD5 (low=0xD5) + ADD 0x94. x64 syscall stub (5 bytes)
    0x284CCF0: (0x05, 0xD5, 0x94, 1, 0, 0),
    # sub_2824AA0: Type1 misclassified as Type3 — obfuscated loop increment
    # AND 0xB6/0x49 (complementary) + XOR 0xB6 + SUB falsely triggers Type3 detection
    # Correct: (byte ^ (i ^ 0x79)) + 0x24 → DWORD 0xC0000023 (STATUS_BUFFER_TOO_SMALL)
    0x2824AA0: (0x04, 0x1475EE79, 0x24, 1, 0, 0),

    # --- Type1 misclassified as Type3: obfuscated loop increment ---
    # These functions have AND mask pairs in the loop increment (e.g. (i&1)<<1)
    # that falsely trigger Type3 detection (complementary mask + XOR + SUB pattern).
    # sub_028244A0: (byte ^ (i ^ 0xD5)) + 0x94
    0x28244A0: (0x04, 0xD5, 0x94, 1, 0, 0),
    # sub_02826620: (byte ^ (i ^ 0x1D)) + 0xB4
    0x2826620: (0x08, 0x1D, 0xB4, 1, 0, 0),
    # sub_0282DE80: (byte ^ (i ^ 0xB2)) + 0x48
    0x282DE80: (0x04, 0xB2, 0x48, 1, 0, 0),
    # sub_02849A50: (byte ^ (i ^ 0x79)) + 0x24
    0x2849A50: (0x04, 0x79, 0x24, 1, 0, 0),

    # --- Type1 wrong xor_key: XOR constant low byte = 0xFF (NOT i pattern) ---
    # sub_02841ED0: key = i ^ 0xCB6862FF (low=0xFF), add 0xBC. Decrypts: "displayName" (UTF-16LE)
    0x2841ED0: (0x18, 0xFF, 0xBC, 1, 0, 0),
}

# ============================================================================
# Known decrypted strings (for reference during analysis)
# ============================================================================

KNOWN_STRINGS = {
    0x2816efa: "%TEMP%\\",
    0x2817b9d: "rundll32 \"",
    0x2817d91: "powershell -exec bypass -f \"",
}

# ============================================================================
# Hardcoded results for call sites with runtime-computed encrypted data
# These call sites cannot be resolved by static extraction because the
# encrypted bytes are computed at runtime from other decrypted results.
#
# Format: {call_site_address: decrypted_bytes}
# ============================================================================

HARDCODED_RESULTS = {
    # 0x0283A4A9 -> sub_2840CD0: encrypted data at esp+0xE2 is computed at runtime
    # from IID_IClassFactory2 GUID set at esp+0x2E0 via add+xor byte transformations.
    # Result: IID_IClassFactory2 = {DC12A687-737F-11CF-884D-00AA004B2E24}
    0x0283A4A9: bytes.fromhex("87a612dc7f73cf11884d00aa004b2e24"),
    # 0x0283DC74 -> sub_2841B70: encrypted data at [edi+0..F] is computed at runtime
    # from IID_IWbemObjectSink GUID via (0x7B - byte) ^ (0x90+i) transformation.
    # Chain simplifies to identity: T3((x+0x84)&0xFF) = x for all bytes.
    # Result: IID_IWbemObjectSink = {4590F811-1D3A-11D0-891F-00AA004B2E24}
    0x0283DC74: bytes.fromhex("11f890453a1dd011891f00aa004b2e24"),
    # 0x0283DD9D -> sub_2841C00: encrypted data at [ecx+0..F] is computed at runtime
    # from IID_IClassFactory2 via (byte + 0x0C) ^ (i ^ 0xAD) transformation.
    # Chain cancels: xor_vals = i^0xAD (cancels with Type1 key), 0x0C + 0xF4 = 0x100 = 0.
    # Result: IID_IClassFactory2 = {DC12A687-737F-11CF-884D-00AA004B2E24}
    0x0283DD9D: bytes.fromhex("87a612dc7f73cf11884d00aa004b2e24"),
}


def add_decrypt_function(addr, loop_count, algo_type, **kwargs):
    """
    Helper function to add a known decrypt function.

    Usage:
        add_decrypt_function(0x2824380, 0x14, 8, key_mask=0x5E, key_const=-81, add_val=124)
        add_decrypt_function(0x28293C0, 0x10, 9, sub_val=36)
        add_decrypt_function(0x282A8A0, 0x10, 10, key_offset=0x80)
        add_decrypt_function(0x2824410, 0x14, 7, xor_key=0x1C, mask1=0x6F, mask2=0x90)

    Args:
        addr: Function address
        loop_count: Number of bytes to decrypt
        algo_type: Algorithm type (1-10)
        **kwargs: Algorithm-specific parameters
    """
    xor_key = kwargs.get('xor_key', 0)
    add_value = kwargs.get('add_value', 0)
    mask1 = kwargs.get('mask1', 0)
    mask2 = kwargs.get('mask2', 0)

    if algo_type == 6:
        # Type6: key_mask, (key_const << 8) | sub_val
        key_mask = kwargs.get('key_mask', 0x34)
        key_const = kwargs.get('key_const', 26)
        sub_val = kwargs.get('sub_val', 24)
        mask1 = key_mask
        mask2 = ((key_const & 0xFF) << 8) | (sub_val & 0xFF)
    elif algo_type == 7:
        # Type7: mask1, mask2
        mask1 = kwargs.get('mask1', 0x6F)
        mask2 = kwargs.get('mask2', 0x90)
    elif algo_type == 8:
        # Type8: key_mask, (key_const << 8) | add_val
        key_mask = kwargs.get('key_mask', 0x5E)
        key_const = kwargs.get('key_const', -81) & 0xFF
        add_val = kwargs.get('add_val', 124)
        mask1 = key_mask
        mask2 = (key_const << 8) | (add_val & 0xFF)
    elif algo_type == 9:
        # Type9: sub_val in add_value field
        add_value = kwargs.get('sub_val', 36)
    elif algo_type == 10:
        # Type10: key_offset in mask1
        mask1 = kwargs.get('key_offset', 0x80)
    elif algo_type == 11:
        # Type11: XOR + SUB with index offset
        # xor_key and sub_val stored directly
        xor_key = kwargs.get('xor_key', 0x91)
        add_value = kwargs.get('sub_val', 124)
    elif algo_type == 12:
        # Type12: XNOR with complex key + add
        # mask1 = (or_val1 << 8) | or_val2, mask2 = add_val
        pass  # Parameters already in mask1, mask2

    KNOWN_DECRYPT_FUNCTIONS[addr] = (loop_count, xor_key, add_value, algo_type, mask1, mask2)
    print(f"[+] Added decrypt function at 0x{addr:08X} (Type{algo_type}, loop={loop_count})")


def decrypt_string_type1(encrypted_bytes, xor_key, add_value, length, index_offset=0):
    """
    Decrypt using XOR + NOT + AND + OR + ADD algorithm (most common in Lumma)

    Algorithm:
    for i in range(length):
        key = (i + index_offset) ^ xor_key
        A = byte & (~key)
        B = key & (~byte)
        result = (A | B) + add_value
        decrypted[i] = result & 0xFF

    index_offset: Used when encrypted data starts at non-zero offset in the original buffer
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = ((i + index_offset) ^ xor_key) & 0xFF  # Apply index offset for XOR key

        not_key = (~key) & 0xFF
        not_byte = (~byte) & 0xFF

        A = byte & not_key
        B = key & not_byte

        result = ((A | B) + add_value) & 0xFF
        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type2(encrypted_bytes, xor_key, add_value, length):
    """
    Alternative decryption algorithm (XOR + AND/XOR operations)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i ^ xor_key) & 0xFF

        not_key = (~key) & 0xFF
        not_byte = (~byte) & 0xFF

        A = byte & not_key
        B = key & not_byte
        not_B = (~B) & 0xFF
        C = A & not_B
        D = A ^ B

        result = ((A + D - C) & 0xFF + add_value) & 0xFF
        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type3(encrypted_bytes, xor_key, mask1, mask2, length):
    """
    Type3 algorithm with mask-based subtraction (used for steamcommunity URLs etc.)

    Algorithm:
    for i in range(length):
        key = (i ^ xor_key) & 0xFF
        tmp = byte ^ key
        result = (tmp & mask2) - ((tmp & mask1) ^ mask1)

    Common masks: mask1=0xD8, mask2=0x27 (complementary: mask1 | mask2 = 0xFF)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i ^ xor_key) & 0xFF

        tmp = byte ^ key

        part1 = (tmp & mask1) ^ mask1
        part2 = tmp & mask2
        result = (part2 - part1) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type4(encrypted_bytes, xor_key, xor_val, shl_mask, length):
    """
    Type4 algorithm with SHL + AND + SUB (used for Content-Type etc.)

    Assembly pattern:
        mov    ecx, eax          ; ecx = tmp
        xor    ecx, 14h          ; ecx = tmp ^ xor_val
        shl    eax, 1            ; eax = tmp << 1
        and    eax, 0D6h         ; eax = (tmp << 1) & shl_mask
        sub    eax, ecx          ; result = eax - ecx

    Algorithm:
    for i in range(length):
        key = (i ^ xor_key) & 0xFF
        tmp = byte ^ key
        result = ((tmp << 1) & shl_mask) - (tmp ^ xor_val)

    Common values: xor_val=0x14, shl_mask=0xD6
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i ^ xor_key) & 0xFF

        tmp = byte ^ key

        part1 = tmp ^ xor_val
        part2 = (tmp << 1) & shl_mask
        result = (part2 - part1) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type5(encrypted_bytes, xor_key, xor_val, shl_mask, length):
    """
    Type5: Combined MBA (Type1-like) + Type4 transformation

    Assembly pattern (from 0x02819140):
        xor    ecx, KEY          ; key = i ^ xor_key
        not    ecx               ; ~key
        and    edx, ecx          ; A = byte & ~key
        ... (complex MBA)
        or     eax, ecx          ; MBA result = byte XOR key
        xor    ecx, 0xCC         ; part1 = result ^ xor_val
        shl    eax, 1            ; part2 = result << 1
        and    eax, 0x66         ; part2 = (result << 1) & shl_mask
        sub    eax, ecx          ; final = part2 - part1

    Algorithm:
    for i in range(length):
        key = (i ^ xor_key) & 0xFF
        mba_result = byte ^ key  # MBA reduces to XOR
        result = ((mba_result << 1) & shl_mask) - (mba_result ^ xor_val)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i ^ xor_key) & 0xFF

        # MBA transformation reduces to XOR
        mba_result = byte ^ key

        # Type4 transformation on MBA result
        part1 = mba_result ^ xor_val
        part2 = (mba_result << 1) & shl_mask
        result = (part2 - part1) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type6(encrypted_bytes, key_mask, key_const, sub_val, length):
    """
    Type6: Modified key calculation with MBA XOR and subtraction.

    Key formula: key = i - ((2 * i) & key_mask) + key_const

    Assembly pattern (from sub_281C040):
        for ( i = 0; i < 0x32; ++i )
            *(_BYTE *)(a1 + i) = (~*(_BYTE *)(a1 + i) & (i - ((2 * i) & 0x34) + 26)
                               | ~(i - ((2 * i) & 0x34) + 26) & *(_BYTE *)(a1 + i)) - 24;

    Algorithm:
    for i in range(length):
        key = (i - ((2 * i) & key_mask) + key_const) & 0xFF
        mba_result = byte ^ key  # MBA reduces to XOR
        result = (mba_result - sub_val) & 0xFF

    Common values: key_mask=0x34, key_const=26, sub_val=24
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i - ((2 * i) & key_mask) + key_const) & 0xFF

        # MBA transformation reduces to XOR
        mba_result = byte ^ key

        # Subtraction
        result = (mba_result - sub_val) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type7(encrypted_bytes, xor_key, mask1, mask2, length):
    """
    Type7: Simple XOR key + MBA + mask-based subtraction.

    Decompiled pattern (from sub_2824410):
        for ( i = 0; i < 0x14; ++i )
            *(_BYTE *)(a1 + i) = ((~byte & (i ^ 0x1C) | ~(i ^ 0x1C) & byte) & 0x6F)
                               - ((~byte & (i ^ 0x1C) | ~(i ^ 0x1C) & byte) & 0x90 ^ 0x90);

    Algorithm:
        key = (i ^ xor_key) & 0xFF
        mba_result = byte ^ key
        part1 = mba_result & mask1
        part2 = (mba_result & mask2) ^ mask2
        result = (part1 - part2) & 0xFF

    Common values: xor_key=0x1C, mask1=0x6F, mask2=0x90
    Note: mask1 | mask2 = 0xFF (complementary masks)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i ^ xor_key) & 0xFF

        # MBA transformation reduces to XOR
        mba_result = byte ^ key

        # Mask-based subtraction
        part1 = mba_result & mask1
        part2 = (mba_result & mask2) ^ mask2
        result = (part1 - part2) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type8(encrypted_bytes, key_mask, key_const, add_val, length):
    """
    Type8: Modified key calculation with MBA XOR and addition.
    (Variant of Type6 using ADD instead of SUB)

    Key formula: key = i - ((2 * i) & key_mask) + key_const

    Decompiled pattern (from sub_2824380):
        for ( i = 0; i < 0x14; ++i )
            *(_BYTE *)(a1 + i) = (~*(_BYTE *)(a1 + i) & (i - ((2 * i) & 0x5E) - 81)
                               | ~(i - ((2 * i) & 0x5E) - 81) & *(_BYTE *)(a1 + i)) + 124;

    Algorithm:
    for i in range(length):
        key = (i - ((2 * i) & key_mask) + key_const) & 0xFF
        mba_result = byte ^ key  # MBA reduces to XOR
        result = (mba_result + add_val) & 0xFF

    Known instance: key_mask=0x5E, key_const=-81, add_val=124
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i - ((2 * i) & key_mask) + key_const) & 0xFF

        # MBA transformation reduces to XOR
        mba_result = byte ^ key

        # Addition
        result = (mba_result + add_val) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type9(encrypted_bytes, sub_val, length):
    """
    Type9: XNOR-based MBA with special rotating key sequence.

    Decompiled pattern (from sub_28293C0):
        for ( i = 0; i < 0x10; i++ )
            *(_BYTE *)(a1 + i) = (~*(_BYTE *)(a1 + i) & ~((~(_BYTE)i | 7) & (i | 0xF8))
                               | ((~(_BYTE)i | 7) & (i | 0xF8)) & *(_BYTE *)(a1 + i)) - 36;

    Key formula: key = ((~i | 7) & (i | 0xF8)) & 0xFF
    Key sequence (16-byte cycle): F8 F9 FA FB FC FD FE FF F0 F1 F2 F3 F4 F5 F6 F7

    MBA: (~byte & ~key) | (key & byte) = ~(byte ^ key) = XNOR
    Result: (XNOR - sub_val) & 0xFF

    Known instance: sub_val=36, decrypts to "key4.db" (UTF-16LE)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = ((~i | 7) & (i | 0xF8)) & 0xFF

        # XNOR: (~byte & ~key) | (key & byte) = ~(byte ^ key)
        not_byte = (~byte) & 0xFF
        not_key = (~key) & 0xFF
        mba_result = (not_byte & not_key) | (key & byte)

        # Subtraction
        result = (mba_result - sub_val) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type10(encrypted_bytes, key_offset, length):
    """
    Type10: Simple XOR with key = (i + key_offset)

    Decompiled pattern (from sub_282A8A0):
        for ( i = 0; i < 0x10; i++ )
            *(_BYTE *)(a1 + i) = ~*(_BYTE *)(a1 + i) & (i + 0x80) | ~(i + 0x80) & *(_BYTE *)(a1 + i);

    MBA: (~byte & key) | (~key & byte) = byte XOR key
    Result: byte XOR (i + key_offset)

    Known instance: key_offset=0x80
    Note: May produce binary data (GUIDs, structures) rather than strings.
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = (i + key_offset) & 0xFF

        # MBA reduces to XOR
        result = byte ^ key

        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type12(encrypted_bytes, or_val1, or_val2, add_val, length):
    """
    Type12: XNOR with complex key calculation, then add.

    Decompiled pattern (from sub_28459F0):
        for ( i = 0; i < 0x3E; ++i )
            *(_BYTE *)(a1 + i) = (~((~(_BYTE)i | 0x6B) & (i | 0x94)) & (byte + ~(2 * byte))
                               | ((~(_BYTE)i | 0x6B) & (i | 0x94)) & byte) + 108;

    Key formula: key = (~i | or_val1) & (i | or_val2)
    MBA simplification: byte + ~(2*byte) = ~byte
    So: (~key & ~byte) | (key & byte) = ~(key XOR byte) = XNOR
    Result: XNOR(key, byte) + add_val

    Known instance: or_val1=0x6B, or_val2=0x94, add_val=108
    Decrypts: "This country is not supported!"
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]

        # Complex key calculation
        key = ((~i | or_val1) & (i | or_val2)) & 0xFF

        # XNOR: (~key & ~byte) | (key & byte)
        not_byte = (~byte) & 0xFF
        not_key = (~key) & 0xFF
        xnor = (not_key & not_byte) | (key & byte)

        result = (xnor + add_val) & 0xFF
        decrypted.append(result)

    return bytes(decrypted)


def decrypt_string_type11(encrypted_bytes, xor_key, sub_val, length, index_offset=0):
    """
    Type11: XOR with key = (i + index_offset) ^ xor_key, then subtract.

    Decompiled pattern (from sub_282E1F0):
        for ( i = 0; i < 0x64; ++i )
        {
            v1 = *(_BYTE *)(a1 + i);
            *(_BYTE *)(a1 + i) = (~v1 & (i ^ 0x91) ^ ~(i ^ 0x91) & v1)
                               + (~(i ^ 0x91) & v1)
                               - (~(~v1 & (i ^ 0x91)) & ~(i ^ 0x91) & v1)
                               - 124;
        }

    The complex MBA simplifies to: byte XOR (i ^ xor_key)
    Full formula: result = (byte ^ ((i + index_offset) ^ xor_key)) - sub_val

    index_offset: Calculated from buffer layout when encrypted data doesn't start
                  at the beginning of the allocated buffer.
                  Example: Buffer at var_14C, data at var_12F -> offset = 0x1D = 29

    Known instance: xor_key=0x91, sub_val=124
    Decrypts: application/x-www-form-urlencoded (HTTP Content-Type header)
    """
    decrypted = bytearray()

    for i in range(min(length, len(encrypted_bytes))):
        byte = encrypted_bytes[i]
        key = ((i + index_offset) ^ xor_key) & 0xFF

        # XOR then subtract
        result = ((byte ^ key) - sub_val) & 0xFF

        decrypted.append(result)

    return bytes(decrypted)


def debug_detect_functions(limit=10):
    """
    Debug function to show what patterns are being found
    """
    print("[*] Debug: Scanning for sub esp, 0x14 pattern...")

    # Get .text section bounds
    text_seg = None
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        print(f"[*] Segment: {seg_name}")
        if ".text" in seg_name.lower() or seg_name == ".text":
            text_seg = seg

    if not text_seg:
        # Try first executable segment
        for seg in idautils.Segments():
            if idc.get_segm_attr(seg, idc.SEGATTR_PERM) & 1:  # Executable
                text_seg = seg
                print(f"[*] Using executable segment at 0x{seg:08X}")
                break

    if not text_seg:
        print("[!] No suitable segment found")
        return

    seg_start = idc.get_segm_start(text_seg)
    seg_end = idc.get_segm_end(text_seg)
    print(f"[*] Segment range: 0x{seg_start:08X} - 0x{seg_end:08X}")

    pattern = "83 EC 14"
    ea = seg_start
    count = 0

    while ea < seg_end and count < limit:
        ea = ida_search.find_binary(ea, seg_end, pattern, 16, ida_search.SEARCH_DOWN)
        if ea == idc.BADADDR:
            break

        print(f"\n[*] Found pattern at 0x{ea:08X}")

        # Show next 20 instructions
        check_ea = ea
        loop_count = None
        xor_key = None
        add_val = 0
        has_ret = False

        for i in range(20):
            check_ea = idc.next_head(check_ea)
            if check_ea == idc.BADADDR:
                break

            mnem = idc.print_insn_mnem(check_ea)
            op0 = idc.print_operand(check_ea, 0)
            op1 = idc.print_operand(check_ea, 1)

            # Check for patterns
            marker = ""
            if mnem == "cmp" and ("esp" in op0.lower() or "var_" in op0.lower()):
                op1_type = idc.get_operand_type(check_ea, 1)
                if op1_type == idc.o_imm:
                    loop_count = idc.get_operand_value(check_ea, 1)
                    marker = f" <-- LOOP_COUNT={loop_count}"

            if mnem == "xor" and op0.lower() == "eax":
                op1_type = idc.get_operand_type(check_ea, 1)
                if op1_type == idc.o_imm:
                    val = idc.get_operand_value(check_ea, 1)
                    if val != 0:
                        xor_key = val
                        marker = f" <-- XOR_KEY=0x{val:08X}"

            if mnem == "add" and op0.lower() == "al":
                op1_type = idc.get_operand_type(check_ea, 1)
                if op1_type == idc.o_imm:
                    add_val = idc.get_operand_value(check_ea, 1) & 0xFF
                    marker = f" <-- ADD_VAL=0x{add_val:02X}"

            if mnem in ["ret", "retn"]:
                has_ret = True
                marker = " <-- RET"

            print(f"    0x{check_ea:08X}: {mnem:6} {op0}, {op1}{marker}")

            if has_ret:
                break

        valid = "YES" if (loop_count and xor_key and has_ret) else "NO"
        print(f"    Valid decrypt function: {valid} (loop={loop_count}, xor={xor_key}, ret={has_ret})")

        count += 1
        ea += 1

    print(f"\n[*] Shown {count} matches")


def auto_detect_decrypt_functions():
    """
    Automatically detect decryption functions by pattern matching.

    Pattern:
    1. sub esp, 0x14
    2. cmp with immediate value (loop count)
    3. xor eax, 0xXXXXXXXX (XOR key)
    4. Type1: add al, 0xXX (add value)
       Type3: and ecx, 0xD8; xor ecx, 0xD8; and eax, 0x27; sub
       Type4: xor ecx, 0x14; shl eax, 1; and eax, 0xD6; sub
    5. ret
    """
    global DECRYPT_FUNCTIONS
    DECRYPT_FUNCTIONS = {}

    print("[*] Auto-detecting decryption functions...")

    # Get .text section bounds - try multiple methods
    text_seg = None
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if ".text" in seg_name.lower() or seg_name == ".text":
            text_seg = seg
            break

    if not text_seg:
        # Try first executable segment
        for seg in idautils.Segments():
            if idc.get_segm_attr(seg, idc.SEGATTR_PERM) & 1:
                text_seg = seg
                break

    if not text_seg:
        print("[!] No suitable segment found")
        return 0

    seg_start = idc.get_segm_start(text_seg)
    seg_end = idc.get_segm_end(text_seg)

    # Search for multiple prologue patterns
    patterns = [
        "83 EC 14",  # sub esp, 0x14
        "83 EC 18",  # sub esp, 0x18
        "83 EC 10",  # sub esp, 0x10
        "56 83 EC 14",  # push esi; sub esp, 0x14
        "57 83 EC 14",  # push edi; sub esp, 0x14
        "53 83 EC 14",  # push ebx; sub esp, 0x14
        "56 83 EC 18",  # push esi; sub esp, 0x18
        "57 83 EC 18",  # push edi; sub esp, 0x18
        "56 83 EC 10",  # push esi; sub esp, 0x10
        "56 57 83 EC",  # push esi; push edi; sub esp, XX
    ]

    found_count = 0
    type1_count = 0
    type3_count = 0
    type4_count = 0

    for pattern in patterns:
        ea = seg_start

        while ea < seg_end:
            # Find next occurrence of pattern
            ea = ida_search.find_binary(ea, seg_end, pattern, 16, ida_search.SEARCH_DOWN)
            if ea == idc.BADADDR:
                break

            # Get actual function start (may be earlier due to push instructions)
            func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
            if func_start == idc.BADADDR:
                func_start = ea  # Fallback to pattern address

            # Skip if already detected
            if func_start in DECRYPT_FUNCTIONS:
                ea += 1
                continue

            loop_count = None
            xor_key = None
            add_val = 0
            has_ret = False
            algo_type = 1  # Default to Type1
            mask1 = 0
            mask2 = 0

            # Track mask detection for Type3
            has_and_mask1 = False
            has_xor_mask1 = False
            has_and_mask2 = False
            has_sub = False
            detected_mask1 = None
            detected_mask2 = None

            # Track Type4 detection
            has_shl = False
            has_xor_small = False
            has_and_shl_mask = False
            detected_xor_val = None
            detected_shl_mask = None

            # Check next 80 instructions (increased for Type3/Type4 detection)
            check_ea = ea
            instructions_checked = []

            for _ in range(80):
                check_ea = idc.next_head(check_ea)
                if check_ea == idc.BADADDR:
                    break

                mnem = idc.print_insn_mnem(check_ea)
                op0 = idc.print_operand(check_ea, 0).lower()
                op1_type = idc.get_operand_type(check_ea, 1)
                op1_val = idc.get_operand_value(check_ea, 1) if op1_type == idc.o_imm else None

                instructions_checked.append((check_ea, mnem, op0, op1_val))

                # Look for loop count: cmp with immediate (more flexible matching)
                if mnem == "cmp" and loop_count is None:
                    # Match [esp], [ebp-XX], var_XX, or register patterns (e.g., cmp eax, 64h)
                    if op1_type == idc.o_imm:
                        val = idc.get_operand_value(check_ea, 1)
                        if 0 < val < 0x200:  # Reasonable string length
                            # Accept if operand contains stack reference OR is a register
                            if "esp" in op0 or "ebp" in op0 or "var_" in op0 or op0 in ["eax", "ecx", "edx", "ebx"]:
                                loop_count = val

                # Look for XOR key: xor reg, 0xXXXXXXXX
                if mnem == "xor" and xor_key is None:
                    if op0 in ["eax", "ecx", "edx", "ebx"] and op1_type == idc.o_imm:
                        val = idc.get_operand_value(check_ea, 1)
                        if val != 0 and val != 0xffffffff and val > 0xFFFF:
                            xor_key = val

                # Also check for LEA with large constant (alternative key generation)
                # The displacement in the LEA encodes the xor_key via MBA:
                #   key = i - (2*i & MASK) - CONST  (where CONST is the LEA displacement)
                # IDA may display negative displacements as -XXXXXXXXh.
                # The actual unsigned displacement (two's complement) is the correct xor_key.
                if mnem == "lea" and xor_key is None:
                    op1_str = idc.print_operand(check_ea, 1)
                    import re
                    lea_match = re.search(r'([\-\+])(0?[0-9A-Fa-f]{6,8})h?\]', op1_str)
                    if lea_match:
                        sign = lea_match.group(1)
                        val = int(lea_match.group(2), 16)
                        if sign == '-':
                            # Negative display: -166E2BEFh means actual displacement is 0xE991D411
                            val = (-val) & 0xFFFFFFFF
                        if val > 0xFFFF:
                            xor_key = val

                # Type4/Type5 detection: xor with small value after MBA
                if mnem == "xor" and op1_type == idc.o_imm:
                    val = op1_val & 0xFF
                    # Small XOR values used in Type4/5 (expanded list)
                    if 0 < val < 0x100 and val not in [0xFF]:
                        has_xor_small = True
                        detected_xor_val = val

                # Type4/Type5 detection: shl eax, 1
                if mnem == "shl":
                    if op1_type == idc.o_imm and op1_val == 1:
                        has_shl = True

                # Type4/Type5 detection: and with mask after shl
                # Accept AND with immediate >= 0x06 after SHL (excludes counter ops like i&1, i&3)
                # Known Type4/5 masks: 0x0E,0x1E,0x2E,0x3E,0x66,0x7E,0x96,0xD6,0xFE
                if mnem == "and" and op1_type == idc.o_imm and has_shl:
                    val = op1_val & 0xFF
                    if val >= 0x06 and val != 0xFF:
                        has_and_shl_mask = True
                        detected_shl_mask = val

                # Look for add value (Type1): add al, 0xXX
                if mnem == "add":
                    if op0 == "al" and op1_type == idc.o_imm:
                        add_val = idc.get_operand_value(check_ea, 1) & 0xFF

                # Type3/Type7 detection: and with complementary mask pattern
                if mnem == "and" and op1_type == idc.o_imm:
                    val = op1_val & 0xFF
                    if val != 0 and val != 0xFF:
                        complement = (~val) & 0xFF
                        if not has_and_mask1:
                            has_and_mask1 = True
                            detected_mask1 = val
                        elif not has_and_mask2 and val == ((~detected_mask1) & 0xFF):
                            # Found complementary pair (mask1 | mask2 = 0xFF)
                            has_and_mask2 = True
                            detected_mask2 = val

                # Type3 detection: xor with same value as mask1
                if mnem == "xor" and op1_type == idc.o_imm:
                    val = op1_val & 0xFF
                    if detected_mask1 and val == detected_mask1:
                        has_xor_mask1 = True

                # Type3 detection: sub instruction
                if mnem == "sub":
                    has_sub = True

                # Check for ret
                if mnem == "retn" or mnem == "ret":
                    has_ret = True
                    break

            # Determine algorithm type
            # Type5: MBA (Type1-like with or) + Type4 transformation (shl, and, xor small, sub)
            if has_shl and has_and_shl_mask and has_xor_small and has_sub:
                # Type5 has both MBA and Type4 patterns
                algo_type = 5
                mask1 = detected_xor_val if detected_xor_val else 0xCC
                mask2 = detected_shl_mask if detected_shl_mask else 0x66
                type4_count += 1  # Count as Type4 variant
            elif has_and_mask1 and has_xor_mask1 and has_and_mask2 and has_sub:
                algo_type = 3
                mask1 = detected_mask1 if detected_mask1 else 0xD8
                mask2 = detected_mask2 if detected_mask2 else (0xFF ^ mask1)
                type3_count += 1
            elif has_and_mask1 and has_and_mask2 and has_sub and not has_xor_mask1:
                # Type7: complementary masks with SUB but NO xor-mask (distinguishes from Type3)
                algo_type = 7
                mask1 = detected_mask1
                mask2 = detected_mask2
                type3_count += 1  # Count with type3 variants
            else:
                algo_type = 1
                mask1 = 0
                mask2 = 0
                type1_count += 1

            # Valid decryption function must have loop count, XOR key, and ret
            if loop_count and xor_key and has_ret:
                DECRYPT_FUNCTIONS[func_start] = (loop_count, xor_key, add_val, algo_type, mask1, mask2)
                found_count += 1

            ea += 1

    # Merge known decrypt functions (Type6-11 with non-standard patterns)
    # IMPORTANT: Known functions ALWAYS override auto-detected ones
    known_added = 0
    for addr, params in KNOWN_DECRYPT_FUNCTIONS.items():
        if addr in DECRYPT_FUNCTIONS:
            # Override auto-detected with known (more accurate)
            DECRYPT_FUNCTIONS[addr] = params
        else:
            DECRYPT_FUNCTIONS[addr] = params
            known_added += 1

    print(f"[*] Found {found_count} decryption functions (Type1: {type1_count}, Type3: {type3_count}, Type4/5: {type4_count})")
    print(f"[*] Added {known_added} known decrypt functions (Type6-10)")
    print(f"[*] Total: {len(DECRYPT_FUNCTIONS)} decrypt functions")
    return len(DECRYPT_FUNCTIONS)


def try_read_global_data(call_addr, size):
    """
    Fallback: try to read encrypted data from a global/static address.
    Detects patterns like:
      push offset unk_XXXX   ; buffer pointer to global data
      ...
      call decrypt_func
    Or:
      lea reg, unk_XXXX
      push reg
      ...
      call decrypt_func
    """
    # Walk backwards up to 6 instructions looking for the buffer pointer
    current = call_addr
    for _ in range(6):
        current = idc.prev_head(current)
        if current == idc.BADADDR:
            return None
        mnem = idc.print_insn_mnem(current)

        if mnem == "push":
            op_type = idc.get_operand_type(current, 0)
            # push immediate (address) or push offset
            if op_type in (idc.o_imm, idc.o_mem):
                addr = idc.get_operand_value(current, 0)
                # Filter out small constants (not addresses)
                if addr > 0x10000:
                    data = idc.get_bytes(addr, size)
                    if data and len(data) == size:
                        # Verify it's not all zeros (likely uninitialized)
                        if any(b != 0 for b in data):
                            return data

        elif mnem == "lea":
            # lea reg, ds:XXXX or lea reg, [XXXX]
            op1_type = idc.get_operand_type(current, 1)
            if op1_type in (idc.o_mem, idc.o_imm):
                addr = idc.get_operand_value(current, 1)
                if addr > 0x10000:
                    data = idc.get_bytes(addr, size)
                    if data and len(data) == size:
                        if any(b != 0 for b in data):
                            return data

        elif mnem in ["ret", "retn"]:
            break

    return None


def extract_from_raw_bytes(call_addr, expected_size, max_scan=512):
    """
    Fallback extractor: scan raw bytes before call_addr for MOV [esp+XX] patterns.
    Handles cases where IDA treats code as data (garbled disassembly).
    Patterns:
      C7 44 24 XX YY YY YY YY  = mov dword ptr [esp+XXh], imm32
      66 C7 44 24 XX YY YY     = mov word ptr [esp+XXh], imm16
      C6 44 24 XX YY           = mov byte ptr [esp+XXh], imm8
    """
    import struct as _struct

    # Read raw bytes before call
    start = call_addr - max_scan
    raw = idc.get_bytes(start, max_scan)
    if not raw:
        return None, 0

    esp_moves = {}  # {offset: (size, value)}
    i = 0
    while i < len(raw):
        # mov dword ptr [esp+XX], imm32: C7 44 24 XX YY YY YY YY (8 bytes)
        if i + 8 <= len(raw) and raw[i] == 0xC7 and raw[i+1] == 0x44 and raw[i+2] == 0x24:
            off = raw[i+3]
            val = _struct.unpack_from('<I', raw, i+4)[0]
            if off not in esp_moves:
                esp_moves[off] = (4, val)
            i += 8
            continue
        # mov word ptr [esp+XX], imm16: 66 C7 44 24 XX YY YY (7 bytes)
        if i + 7 <= len(raw) and raw[i] == 0x66 and raw[i+1] == 0xC7 and raw[i+2] == 0x44 and raw[i+3] == 0x24:
            off = raw[i+4]
            val = _struct.unpack_from('<H', raw, i+5)[0]
            if off not in esp_moves:
                esp_moves[off] = (2, val)
            i += 7
            continue
        # mov byte ptr [esp+XX], imm8: C6 44 24 XX YY (5 bytes)
        if i + 5 <= len(raw) and raw[i] == 0xC6 and raw[i+1] == 0x44 and raw[i+2] == 0x24:
            off = raw[i+3]
            val = raw[i+4]
            if off not in esp_moves:
                esp_moves[off] = (1, val)
            i += 5
            continue
        i += 1

    if not esp_moves:
        return None, 0

    # Find contiguous group that matches expected_size
    # Group by proximity: find a cluster of offsets spanning ~expected_size bytes
    sorted_offs = sorted(esp_moves.keys())

    # Try to find a group starting from each offset
    best_group = None
    best_coverage = 0
    for start_off in sorted_offs:
        end_off = start_off + expected_size
        group = {k: v for k, v in esp_moves.items() if start_off <= k < end_off}
        # Calculate byte coverage
        coverage = sum(s for s, v in group.values())
        if coverage > best_coverage:
            best_coverage = coverage
            best_group = group
            best_base = start_off

    if not best_group or best_coverage < expected_size * 0.5:
        return None, 0

    # Build result
    moves = {k - best_base: v for k, v in best_group.items()}
    total_size = max(k + s for k, (s, v) in moves.items())
    result = bytearray(max(total_size, expected_size))
    for offset, (size, value) in moves.items():
        for j in range(size):
            pos = offset + j
            if pos < len(result):
                result[pos] = (value >> (j * 8)) & 0xFF

    return bytes(result[:expected_size]), 0


def extract_stack_bytes_before_call(call_addr, max_bytes=256):
    """
    Extract stack string bytes constructed before a call instruction.
    Handles BYTE, WORD, and DWORD moves with var_XX and esp+offset patterns.
    """
    _DEBUG_EXTRACT = (call_addr in (0x028122CB, 0x02813EB2))
    current = call_addr

    # Four collections - will use the one with more data
    var_moves = {}      # {var_num: (size, value)}
    esp_moves = {}      # {absolute_offset: (size, value)}
    ebp_moves = {}      # {offset: (size, value)} for [ebp-XXh] pattern
    # Track reg_moves per register to avoid mixing different buffers
    reg_moves_by_reg = {}  # {reg_name: {offset: (size, value)}}

    # Track buffer base from lea instruction
    buffer_base_arg = None   # for arg_XXX pattern
    buffer_base_var = None   # for var_XX pattern
    buffer_base_esp = None   # for plain [esp+XXh] pattern
    buffer_base_ebp = None   # for [ebp-XXh] pattern

    # Detect which register is pushed as buffer argument (look at instruction before call)
    push_reg = None
    prev_insn = idc.prev_head(call_addr)
    if prev_insn != idc.BADADDR:
        prev_mnem = idc.print_insn_mnem(prev_insn)
        if prev_mnem == "push":
            push_op = idc.print_operand(prev_insn, 0).lower()
            if push_op in ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"]:
                push_reg = push_op
        elif prev_mnem == "mov":
            # Detect "sub esp, 4; mov [esp+XX], reg" pattern (equivalent to push reg)
            dest_op = idc.print_operand(prev_insn, 0).lower()
            src_op = idc.print_operand(prev_insn, 1).lower()
            if re.search(r'\[esp', dest_op) and src_op in ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"]:
                push_reg = src_op

    stop_collecting = False
    stop_addr = None

    # Track pending register-to-memory stores for patterns like:
    #   mov eax, 0x12345678; mov [esp+XX], eax
    # In backwards walk: we see mov [mem], reg first, then mov reg, imm later
    pending_reg_stores = {}  # {reg_name: [(collection_type, key, size), ...]}

    def _parse_mem_dest(op0_str):
        """Parse memory destination operand and return (collection_type, key) or None."""
        m = re.search(r'var_([0-9A-Fa-f]+)(?:\+([0-9A-Fa-f]+))?', op0_str)
        if m:
            var_num = int(m.group(1), 16)
            extra = int(m.group(2), 16) if m.group(2) else 0
            return ('var', var_num - extra)
        m = re.search(r'\[esp([+-])([0-9A-Fa-f]+)h?\+arg_([0-9A-Fa-f]+)\]', op0_str, re.IGNORECASE)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            return ('esp', sign * int(m.group(2), 16) + int(m.group(3), 16))
        m = re.search(r'\[esp\+arg_([0-9A-Fa-f]+)\]', op0_str, re.IGNORECASE)
        if m:
            return ('esp', int(m.group(1), 16))
        m = re.search(r'\[esp\+([0-9A-Fa-f]+)h?\]$', op0_str, re.IGNORECASE)
        if m:
            return ('esp', int(m.group(1), 16))
        m = re.search(r'\[esp\]', op0_str, re.IGNORECASE)
        if m:
            return ('esp', 0)
        m = re.search(r'\[ebp-([0-9A-Fa-f]+)h?\]$', op0_str, re.IGNORECASE)
        if m:
            return ('ebp', int(m.group(1), 16))
        m = re.search(r'\[(eax|ecx|edx|ebx|esi|edi)\+([0-9A-Fa-f]+)h?\]', op0_str, re.IGNORECASE)
        if m:
            return ('reg', (m.group(1).lower(), int(m.group(2), 16)))
        m = re.search(r'\[(eax|ecx|edx|ebx|esi|edi)\](?!\s*\+)', op0_str, re.IGNORECASE)
        if m:
            return ('reg', (m.group(1).lower(), 0))
        return None

    def _resolve_pending(entries, imm_val):
        """Resolve pending register stores with the given immediate value."""
        for (coll, key, sz) in entries:
            if coll == 'var':
                if imm_val != 0 and key not in var_moves:
                    var_moves[key] = (sz, imm_val)
            elif coll == 'esp':
                if imm_val != 0 and key not in esp_moves:
                    esp_moves[key] = (sz, imm_val)
            elif coll == 'ebp':
                if key not in ebp_moves:
                    ebp_moves[key] = (sz, imm_val)
            elif coll == 'reg':
                rn, off = key
                if rn not in reg_moves_by_reg:
                    reg_moves_by_reg[rn] = {}
                if off not in reg_moves_by_reg[rn]:
                    reg_moves_by_reg[rn][off] = (sz, imm_val)

    for _ in range(300):
        current = idc.prev_head(current)
        if current == idc.BADADDR:
            break

        mnem = idc.print_insn_mnem(current)

        # Only break on ret/retn - don't break on call since there may be
        # intermediate calls (like nullsub_1) between data setup and decrypt call
        if mnem in ["retn", "ret"]:
            break

        # Stop collecting MOV data at calls to other decrypt functions to avoid
        # mixing data from different decrypt call sites that reuse the same stack
        # slots. But continue walking to find LEA instructions for buffer base
        # detection (the LEA may be before the previous decrypt call).
        if mnem == "call":
            call_target = idc.get_operand_value(current, 0)
            if call_target in DECRYPT_FUNCTIONS:
                if not stop_collecting:
                    stop_addr = current
                stop_collecting = True
                pending_reg_stores.clear()

        # Detect lea instruction for buffer base (even past decrypt calls)
        # Only set buffer base if LEA loads the pushed register (buffer pointer)
        # or if no push register was detected
        if mnem == "lea":
            lea_dst = idc.print_operand(current, 0).lower()
            op1 = idc.print_operand(current, 1)
            is_buffer_lea = (push_reg is None or lea_dst == push_reg)
            # Pattern: lea reg, [esp+XXh+arg_YY] or [esp-XXh+arg_YY] or [esp+arg_YY]
            match = re.search(r'\[esp([+-])([0-9A-Fa-f]+)h?\+arg_([0-9A-Fa-f]+)\]', op1, re.IGNORECASE)
            if match and is_buffer_lea:
                sign = 1 if match.group(1) == '+' else -1
                esp_off = sign * int(match.group(2), 16)
                arg_off = int(match.group(3), 16)
                if buffer_base_arg is None:
                    buffer_base_arg = esp_off + arg_off
            elif is_buffer_lea:
                # Pattern: lea reg, [esp+arg_YY] (no hex offset between esp and arg)
                match = re.search(r'\[esp\+arg_([0-9A-Fa-f]+)\]', op1, re.IGNORECASE)
                if match:
                    if buffer_base_arg is None:
                        buffer_base_arg = int(match.group(1), 16)
            # Pattern: lea reg, [esp+XXh+var_YY] or [esp+XXh+var_YY+N]
            match = re.search(r'\[esp\+[0-9A-Fa-f]+h?\+var_([0-9A-Fa-f]+)(?:\+[0-9A-Fa-f]+)?\]', op1, re.IGNORECASE)
            if match:
                if is_buffer_lea and buffer_base_var is None:
                    buffer_base_var = int(match.group(1), 16)
                continue
            # Pattern: lea reg, [esp+XXh] - plain esp offset (no var/arg)
            match = re.search(r'\[esp\+([0-9A-Fa-f]+)h?\]$', op1, re.IGNORECASE)
            if match:
                if is_buffer_lea and buffer_base_esp is None:
                    buffer_base_esp = int(match.group(1), 16)
                continue
            # Pattern: lea reg, [ebp-XXh] - ebp-relative offset
            match = re.search(r'\[ebp-([0-9A-Fa-f]+)h?\]$', op1, re.IGNORECASE)
            if match:
                if is_buffer_lea and buffer_base_ebp is None:
                    buffer_base_ebp = int(match.group(1), 16)
            continue

        # Track register modifications by non-mov instructions to invalidate pending stores
        if mnem not in ("mov", "lea", "call", "retn", "ret", "push", "nop", "jmp", "jz", "jnz",
                        "je", "jne", "jb", "jbe", "ja", "jae", "jl", "jle", "jg", "jge", "js",
                        "jns", "cmp", "test"):
            if mnem in ("xor", "add", "sub", "and", "or", "pop", "inc", "dec", "neg", "not",
                        "shl", "shr", "sar", "imul", "cdq", "movzx", "movsx", "setz", "setnz",
                        "setb", "seta", "cmovz", "cmovnz"):
                op0_reg = idc.print_operand(current, 0).lower()
                if op0_reg in pending_reg_stores:
                    del pending_reg_stores[op0_reg]

        # Skip non-MOV instructions for data collection
        if mnem != "mov":
            continue

        op0 = idc.print_operand(current, 0)
        op1 = idc.print_operand(current, 1)
        op1_type = idc.get_operand_type(current, 1)

        if _DEBUG_EXTRACT:
            print(f"  [DBG] 0x{current:08X}: mov {op0}, {op1}  (op1_type={op1_type}, stop={stop_collecting})")

        # Case: mov reg, ... (no memory destination)
        if "[" not in op0:
            dst_reg = op0.lower()
            if dst_reg in pending_reg_stores:
                if not stop_collecting and op1_type == idc.o_imm:
                    # mov reg, imm: resolve all pending stores for this register
                    imm_val = idc.get_operand_value(current, 1)
                    if _DEBUG_EXTRACT:
                        print(f"    [DBG] RESOLVE pending for {dst_reg}=0x{imm_val:X}: {pending_reg_stores[dst_reg]}")
                    _resolve_pending(pending_reg_stores[dst_reg], imm_val)
                else:
                    if _DEBUG_EXTRACT:
                        print(f"    [DBG] INVALIDATE pending for {dst_reg} (stop={stop_collecting}, op1_type={op1_type})")
                del pending_reg_stores[dst_reg]
            continue

        # Skip MOV data collection past decrypt function calls
        if stop_collecting:
            continue

        # Case: mov [mem], reg - record as pending store
        if op1_type in (idc.o_reg, 1):  # o_reg = 1
            src_reg = idc.print_operand(current, 1).lower()
            if src_reg in ("eax", "ecx", "edx", "ebx", "esi", "edi"):
                # Determine size
                size = 4
                try:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, current) > 0:
                        s = ida_ua.get_dtype_size(insn.ops[0].dtype)
                        if s > 0:
                            size = s
                except:
                    pass
                parsed = _parse_mem_dest(op0)
                if parsed:
                    coll, key = parsed
                    if src_reg not in pending_reg_stores:
                        pending_reg_stores[src_reg] = []
                    pending_reg_stores[src_reg].append((coll, key, size))
                    if _DEBUG_EXTRACT:
                        print(f"    [DBG] PENDING: mov [{coll}:{key}], {src_reg} (size={size})")
                elif _DEBUG_EXTRACT:
                    print(f"    [DBG] UNMATCHED mem dest: {op0}")
            continue

        # Case: mov [mem], imm - handle directly (existing logic)
        if op1_type != idc.o_imm:
            if _DEBUG_EXTRACT:
                print(f"    [DBG] SKIP: op1_type={op1_type} (not imm, not reg)")
            continue

        # Determine size using ida_ua for accurate detection
        size = 4  # default
        try:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, current) > 0:
                size = ida_ua.get_dtype_size(insn.ops[0].dtype)
                if size == 0:
                    size = 4  # fallback
        except:
            # Fallback to string-based detection
            op0_lower = op0.lower()
            if "byte" in op0_lower:
                size = 1
            elif "word" in op0_lower and "dword" not in op0_lower:
                size = 2

        imm_val = idc.get_operand_value(current, 1)

        try:
            # Pattern: var_XX or var_XX+N (with optional offset)
            match = re.search(r'var_([0-9A-Fa-f]+)(?:\+([0-9A-Fa-f]+))?', op0)
            if match:
                var_num = int(match.group(1), 16)
                extra_offset = int(match.group(2), 16) if match.group(2) else 0
                # Adjust var_num to account for extra offset (subtract because var offsets are negative)
                adjusted_var = var_num - extra_offset
                if imm_val != 0 and adjusted_var not in var_moves:
                    var_moves[adjusted_var] = (size, imm_val)
                continue

            # Pattern: [esp+XXh+arg_YY] or [esp-XXh+arg_YY]
            match = re.search(r'\[esp([+-])([0-9A-Fa-f]+)h?\+arg_([0-9A-Fa-f]+)\]', op0, re.IGNORECASE)
            if match:
                sign = 1 if match.group(1) == '+' else -1
                esp_key = sign * int(match.group(2), 16) + int(match.group(3), 16)
                if imm_val != 0 and esp_key not in esp_moves:
                    esp_moves[esp_key] = (size, imm_val)
                continue

            # Pattern: [esp+arg_YY] (no hex offset between esp and arg)
            match = re.search(r'\[esp\+arg_([0-9A-Fa-f]+)\]', op0, re.IGNORECASE)
            if match:
                esp_key = int(match.group(1), 16)
                if imm_val != 0 and esp_key not in esp_moves:
                    esp_moves[esp_key] = (size, imm_val)
                continue

            # Pattern: [esp+XXh]
            match = re.search(r'\[esp\+([0-9A-Fa-f]+)h?\]', op0, re.IGNORECASE)
            if match:
                esp_key = int(match.group(1), 16)
                if imm_val != 0 and esp_key not in esp_moves:
                    esp_moves[esp_key] = (size, imm_val)
                continue

            # Pattern: dword ptr [esp] (bare esp, no offset = offset 0)
            match = re.search(r'\[esp\]', op0, re.IGNORECASE)
            if match:
                if imm_val != 0 and 0 not in esp_moves:
                    esp_moves[0] = (size, imm_val)
                continue

            # Pattern: [ebp-XXh] - ebp-relative negative offset
            match = re.search(r'\[ebp-([0-9A-Fa-f]+)h?\]', op0, re.IGNORECASE)
            if match:
                offset = int(match.group(1), 16)
                if offset not in ebp_moves:
                    ebp_moves[offset] = (size, imm_val)
                continue

            # Pattern: [reg+offset] where reg is eax, ecx, edx, ebx, esi, edi
            # e.g., [eax+1], [eax+0Ah], [ecx+10h]
            match = re.search(r'\[(eax|ecx|edx|ebx|esi|edi)\+([0-9A-Fa-f]+)h?\]', op0, re.IGNORECASE)
            if match:
                reg_name = match.group(1).lower()
                offset = int(match.group(2), 16)
                if reg_name not in reg_moves_by_reg:
                    reg_moves_by_reg[reg_name] = {}
                if offset not in reg_moves_by_reg[reg_name]:
                    reg_moves_by_reg[reg_name][offset] = (size, imm_val)
                continue

            # Pattern: [reg] (offset 0) - no offset specified
            # Remove $ anchor to handle potential trailing whitespace/characters
            match = re.search(r'\[(eax|ecx|edx|ebx|esi|edi)\](?!\s*\+)', op0, re.IGNORECASE)
            if match:
                reg_name = match.group(1).lower()
                if reg_name not in reg_moves_by_reg:
                    reg_moves_by_reg[reg_name] = {}
                if 0 not in reg_moves_by_reg[reg_name]:
                    reg_moves_by_reg[reg_name][0] = (size, imm_val)
                continue

        except:
            continue

    # Calculate index offset for XOR key calculation
    index_offset = 0

    # Select the appropriate register's moves
    # Prefer the register that was pushed as buffer argument
    reg_moves = {}
    if reg_moves_by_reg:
        if push_reg and push_reg in reg_moves_by_reg:
            reg_moves = reg_moves_by_reg[push_reg]
        else:
            # Fall back to the register with most entries
            best_reg = max(reg_moves_by_reg.keys(), key=lambda r: len(reg_moves_by_reg[r]))
            reg_moves = reg_moves_by_reg[best_reg]

    # Supplement: raw byte scan to recover MOV instructions from garbled disassembly
    # Scans for C7 84 24 (mov [esp+disp32], imm32) and C7 44 24 (mov [esp+disp8], imm32)
    # Raw entries are collected separately, then delta-corrected before merging into esp_moves.
    # IDA's frame-adjusted offsets may differ from raw binary displacements by a constant delta
    # (e.g., +4 bytes due to garbled disassembly confusing IDA's stack pointer tracking).
    import struct as _struct
    ida_esp_min = min(esp_moves.keys()) if esp_moves else None
    ida_esp_max = max(esp_moves.keys()) if esp_moves else None
    # Accept raw entries within the expected buffer range: [ida_max - max_bytes + 4, ida_max + 4]
    # This covers entries below ida_min that IDA missed due to garbled disassembly
    raw_range_lo = (ida_esp_max - max_bytes + 4) if ida_esp_max is not None else 0
    raw_range_hi = (ida_esp_max + 4) if ida_esp_max is not None else 0xFFFFFFFF
    scan_start = stop_addr if stop_addr else current
    scan_size = call_addr - scan_start
    raw_esp_moves = {}  # Collect raw entries separately for delta detection
    if 0 < scan_size < 2048 and ida_esp_max is not None:
        raw = idc.get_bytes(scan_start, scan_size)
        if raw:
            ri = 0
            while ri < len(raw):
                # C7 84 24 XX XX XX XX YY YY YY YY = mov dword ptr [esp+disp32], imm32
                if ri + 11 <= len(raw) and raw[ri] == 0xC7 and raw[ri+1] == 0x84 and raw[ri+2] == 0x24:
                    offset = _struct.unpack_from('<I', raw, ri+3)[0]
                    value = _struct.unpack_from('<I', raw, ri+7)[0]
                    if value != 0 and raw_range_lo <= offset <= raw_range_hi:
                        if offset not in raw_esp_moves:
                            raw_esp_moves[offset] = (4, value)
                    ri += 11
                    continue
                # C7 44 24 XX YY YY YY YY = mov dword ptr [esp+disp8], imm32
                if ri + 8 <= len(raw) and raw[ri] == 0xC7 and raw[ri+1] == 0x44 and raw[ri+2] == 0x24:
                    offset = raw[ri+3]
                    value = _struct.unpack_from('<I', raw, ri+4)[0]
                    if value != 0 and raw_range_lo <= offset <= raw_range_hi:
                        if offset not in raw_esp_moves:
                            raw_esp_moves[offset] = (4, value)
                    ri += 8
                    continue
                # 66 C7 84 24 XX XX XX XX YY YY = mov word ptr [esp+disp32], imm16
                if ri + 10 <= len(raw) and raw[ri] == 0x66 and raw[ri+1] == 0xC7 and raw[ri+2] == 0x84 and raw[ri+3] == 0x24:
                    offset = _struct.unpack_from('<I', raw, ri+4)[0]
                    value = _struct.unpack_from('<H', raw, ri+8)[0]
                    if value != 0 and raw_range_lo <= offset <= raw_range_hi:
                        if offset not in raw_esp_moves:
                            raw_esp_moves[offset] = (2, value)
                    ri += 10
                    continue
                # 66 C7 44 24 XX YY YY = mov word ptr [esp+disp8], imm16
                if ri + 7 <= len(raw) and raw[ri] == 0x66 and raw[ri+1] == 0xC7 and raw[ri+2] == 0x44 and raw[ri+3] == 0x24:
                    offset = raw[ri+4]
                    value = _struct.unpack_from('<H', raw, ri+5)[0]
                    if value != 0 and raw_range_lo <= offset <= raw_range_hi:
                        if offset not in raw_esp_moves:
                            raw_esp_moves[offset] = (2, value)
                    ri += 7
                    continue
                ri += 1

    # Delta detection: IDA's frame-adjusted offsets may differ from raw displacements
    # by a constant delta (typically +4 due to garbled code confusing stack tracking).
    # Detect this by finding matching values between IDA and raw at different offsets.
    raw_delta = 0
    raw_found = 0
    if raw_esp_moves and esp_moves:
        delta_candidates = []
        ida_val_to_keys = {}
        for ik, (isz, iv) in esp_moves.items():
            if iv != 0:
                ida_val_to_keys.setdefault((isz, iv), []).append(ik)
        for rk, (rsz, rv) in raw_esp_moves.items():
            matching_ida_keys = ida_val_to_keys.get((rsz, rv), [])
            for ik in matching_ida_keys:
                if rk != ik:
                    delta_candidates.append(rk - ik)
        if delta_candidates:
            from collections import Counter
            delta_counts = Counter(delta_candidates)
            best_delta, best_count = delta_counts.most_common(1)[0]
            # Require at least 2 matches or all matches agree for confidence
            if best_count >= 2 or len(delta_candidates) == best_count:
                raw_delta = best_delta
        if _DEBUG_EXTRACT:
            print(f"  [DBG] Raw byte scan: {len(raw_esp_moves)} raw entries, delta_candidates={delta_candidates}, detected delta={raw_delta}")

    # Merge raw entries into esp_moves with delta correction
    for rk, rv in raw_esp_moves.items():
        adjusted_key = rk - raw_delta
        if adjusted_key not in esp_moves:
            esp_moves[adjusted_key] = rv
            raw_found += 1

    if _DEBUG_EXTRACT and (raw_esp_moves or raw_found):
        print(f"  [DBG] Raw byte scan: merged {raw_found} entries (delta={raw_delta}, scan 0x{scan_start:X}-0x{call_addr:X}, accept esp[0x{raw_range_lo:X}-0x{raw_range_hi:X}])")

    if _DEBUG_EXTRACT:
        print(f"  [DBG] Collections (after raw scan): var={len(var_moves)}, esp={len(esp_moves)}, ebp={len(ebp_moves)}, reg_by_reg={{{', '.join(f'{k}:{len(v)}' for k,v in reg_moves_by_reg.items())}}}")
        print(f"  [DBG] Bases: var={buffer_base_var}, esp={buffer_base_esp}, arg={buffer_base_arg}, ebp={buffer_base_ebp}")
        print(f"  [DBG] push_reg={push_reg}, pending_unresolved={dict(pending_reg_stores)}")
        if esp_moves:
            for k in sorted(esp_moves.keys()):
                s, v = esp_moves[k]
                print(f"    esp[0x{k:X}] = 0x{v:X} (size={s})")
        if var_moves:
            for k in sorted(var_moves.keys()):
                s, v = var_moves[k]
                print(f"    var[0x{k:X}] = 0x{v:X} (size={s})")

    # Choose collection: prefer collection with detected buffer base,
    # fall back to collection with most data
    best_type, best_moves, best_count = None, {}, 0

    # If push_reg detected and we have reg_moves for it, prefer it — the register
    # is the actual buffer pointer being passed to the decrypt function
    if push_reg and reg_moves and len(reg_moves) >= max_bytes // 4:
        best_type, best_moves, best_count = 'reg', reg_moves, len(reg_moves)
    elif buffer_base_var is not None and var_moves:
        best_type, best_moves, best_count = 'var', var_moves, len(var_moves)
    elif buffer_base_esp is not None and esp_moves:
        best_type, best_moves, best_count = 'esp', esp_moves, len(esp_moves)
    elif buffer_base_arg is not None and esp_moves:
        best_type, best_moves, best_count = 'esp', esp_moves, len(esp_moves)
    elif buffer_base_ebp is not None and ebp_moves:
        best_type, best_moves, best_count = 'ebp', ebp_moves, len(ebp_moves)
    else:
        collections = [
            (len(esp_moves), 'esp', esp_moves),
            (len(var_moves), 'var', var_moves),
            (len(reg_moves), 'reg', reg_moves),
            (len(ebp_moves), 'ebp', ebp_moves),
        ]
        collections.sort(key=lambda x: x[0], reverse=True)
        best_count, best_type, best_moves = collections[0]

    if best_count == 0:
        return None, 0

    if best_type == 'ebp':
        # ebp-relative offsets: higher offset number = lower address in stack
        # Buffer at ebp-67h, data at ebp-66h to ebp-2Ah
        # Normalize: max_offset - offset = position in buffer
        if buffer_base_ebp is not None:
            # Filter to only include offsets <= buffer_base_ebp (closer to ebp)
            filtered_ebp = {k: v for k, v in ebp_moves.items() if k <= buffer_base_ebp}
            if filtered_ebp:
                ebp_moves = filtered_ebp
        max_off = max(ebp_moves.keys())
        # For ebp-XX, larger offset = earlier in buffer
        # So we invert: position = max_off - offset
        moves = {max_off - k: v for k, v in ebp_moves.items()}
    elif best_type == 'esp':
        # If buffer_base_esp detected, filter to only include offsets >= buffer_base_esp
        if buffer_base_esp is not None:
            filtered_esp = {k: v for k, v in esp_moves.items() if k >= buffer_base_esp}
            if filtered_esp:
                esp_moves = filtered_esp
                # Normalize by buffer base
                moves = {k - buffer_base_esp: v for k, v in esp_moves.items()}
            else:
                min_off = min(esp_moves.keys())
                moves = {k - min_off: v for k, v in esp_moves.items()}
        else:
            min_off = min(esp_moves.keys())
            # If buffer_base_arg detected, calculate the index offset
            if buffer_base_arg is not None and min_off > buffer_base_arg:
                index_offset = min_off - buffer_base_arg
            moves = {k - min_off: v for k, v in esp_moves.items()}
    elif best_type == 'var':
        # If buffer_base_var detected, filter to only include vars <= buffer_base_var
        # (vars with higher numbers are before the buffer in memory)
        if buffer_base_var is not None:
            filtered_vars = {k: v for k, v in var_moves.items() if k <= buffer_base_var}
            if filtered_vars:
                var_moves = filtered_vars
            # Calculate index_offset: how far is the first data byte from buffer start
            # buffer_base_var is where the buffer starts (e.g., var_14C)
            # max(var_moves.keys()) is where data starts (e.g., var_12F)
            # index_offset = buffer_base_var - max_data_var = 0x14C - 0x12F = 29
            max_data_var = max(var_moves.keys())
            index_offset = buffer_base_var - max_data_var
        max_var = max(var_moves.keys())
        moves = {max_var - k: v for k, v in var_moves.items()}
    elif best_type == 'reg':
        # reg_moves already has offsets from 0
        min_off = min(reg_moves.keys())
        moves = {k - min_off: v for k, v in reg_moves.items()}

    # Normalize offsets so minimum is 0
    if moves:
        min_off = min(moves.keys())
        if min_off > 0:
            moves = {k - min_off: v for k, v in moves.items()}

    # Build result
    max_off = max(moves.keys()) if moves else 0
    total_size = min(max_off + 4, max_bytes)
    result = bytearray(total_size)

    # Sort by offset ascending, then by size descending (DWORD > WORD > BYTE).
    # This ensures left-to-right processing and larger entries take priority
    # over overlapping smaller entries from different data sets.
    written = set()
    for offset, (size, value) in sorted(moves.items(), key=lambda x: (x[0], -x[1][0])):
        for i in range(size):
            pos = offset + i
            if pos < total_size and pos not in written:
                result[pos] = (value >> (i * 8)) & 0xFF
                written.add(pos)

    # Don't trim trailing zeros - the caller trims to loop_count.
    # Trailing zeros may be valid encrypted data bytes.
    return (bytes(result), index_offset) if result else (None, 0)


def format_guid(data):
    """
    Format 16 bytes as a Windows GUID string.
    Returns None if data is not a valid GUID format.
    """
    if len(data) != 16:
        return None

    # Check if it looks like a COM GUID (ends with C000-000000000046 pattern)
    # Common COM interface pattern: last 8 bytes are C0 00 00 00 00 00 00 46
    is_com_guid = (data[8] == 0xC0 and data[9] == 0x00 and
                   data[14] == 0x00 and data[15] == 0x46)

    # Also check for other GUID-like patterns (mostly zeros with some data)
    zero_count = sum(1 for b in data if b == 0)
    has_guid_structure = zero_count >= 8  # GUIDs often have many zero bytes

    # Check RFC 4122 UUID structure: version 1-5 in Data3 high nibble,
    # variant 10 (DCE) in byte 8 high bits. Catches IWbemObjectSink, IClassFactory2, etc.
    version = (data[7] >> 4) & 0xF
    variant_bits = (data[8] >> 6) & 0x3
    is_rfc4122_uuid = (1 <= version <= 5) and (variant_bits == 0x2)

    if is_com_guid or has_guid_structure or is_rfc4122_uuid:
        import struct
        data1 = struct.unpack('<I', data[0:4])[0]
        data2 = struct.unpack('<H', data[4:6])[0]
        data3 = struct.unpack('<H', data[6:8])[0]
        data4 = data[8:16]
        guid = f"{{{data1:08X}-{data2:04X}-{data3:04X}-{data4[0]:02X}{data4[1]:02X}-{data4[2]:02X}{data4[3]:02X}{data4[4]:02X}{data4[5]:02X}{data4[6]:02X}{data4[7]:02X}}}"
        return guid
    return None


# Known COM interface GUIDs for annotation
KNOWN_GUIDS = {
    "{00000000-0000-0000-C000-000000000046}": "IUnknown",
    "{0000010B-0000-0000-C000-000000000046}": "IPersistFile",
    "{000214F9-0000-0000-C000-000000000046}": "IShellLinkA",
    "{000214EE-0000-0000-C000-000000000046}": "IShellLinkW",
    "{00021401-0000-0000-C000-000000000046}": "ShellLink CLSID",
    "{0000000C-0000-0000-C000-000000000046}": "IStream",
    "{0000010C-0000-0000-C000-000000000046}": "IPersist",
    "{00000109-0000-0000-C000-000000000046}": "IPersistStream",
    "{DC12A687-737F-11CF-884D-00AA004B2E24}": "IClassFactory2",
    "{4590F811-1D3A-11D0-891F-00AA004B2E24}": "IWbemObjectSink",
}


def is_shellcode(data):
    """
    Check if decrypted bytes look like x86/x64 shellcode.
    Returns a string describing the type if matched, False otherwise.
    Return values: "heavens_gate", "x64", "x86", or False.
    (All truthy strings work with existing 'if is_shellcode(...)' checks.)
    """
    if not data or len(data) < 16:
        return False

    # Heaven's Gate detection (check before NULL byte ratio - HG shellcode has NULL bytes)
    # Look for CS selector 0x33 written to stack (mov dword [reg+4], 0x33)
    # and far jump instructions (FF /5)
    hg_cs33_patterns = [
        b'\xc7\x42\x04\x33\x00\x00\x00',   # mov dword [edx+4], 0x33
        b'\xc7\x44\x24\x04\x33\x00\x00\x00', # mov dword [esp+4], 0x33
        b'\xc7\x41\x04\x33\x00\x00\x00',   # mov dword [ecx+4], 0x33
        b'\xc7\x43\x04\x33\x00\x00\x00',   # mov dword [ebx+4], 0x33
    ]
    hg_far_jmp_patterns = [
        b'\xff\x2a',           # jmp far [edx]
        b'\xff\x2c\x24',       # jmp far [esp]
        b'\xff\x29',           # jmp far [ecx]
        b'\xff\x2b',           # jmp far [ebx]
        b'\xff\x2f',           # jmp far [edi]
        b'\xff\x2e',           # jmp far [esi]
    ]
    has_cs33 = any(p in data for p in hg_cs33_patterns)
    has_far_jmp = any(p in data for p in hg_far_jmp_patterns)
    if has_cs33 and has_far_jmp:
        return "heavens_gate"

    # Also check for push 0x33 + retf pattern (alternative Heaven's Gate)
    if b'\x6a\x33' in data and b'\xcb' in data:
        # Verify retf comes after push 0x33
        push33_pos = data.index(b'\x6a\x33')
        retf_pos = data.index(b'\xcb')
        if retf_pos > push33_pos and retf_pos - push33_pos < 20:
            return "heavens_gate"

    # x86-64 code detection (REX.W prefixed instructions in a PE32 binary)
    # In a 32-bit PE, REX.W (0x48-0x4F) + valid opcode patterns indicate
    # 64-bit shellcode (Heaven's Gate target, injected x64 code, etc.)
    rex_w_opcodes = {
        0x01, 0x03, 0x09, 0x0B, 0x0F,  # add, or
        0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B,  # and, sub, xor, cmp
        0x63, 0x69, 0x6B,  # movsxd, imul
        0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D,  # arithmetic, test, xchg, mov, lea
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,  # mov r64, imm64
        0xC1, 0xC7, 0xD1, 0xD3,  # shift, mov
        0xF7, 0xFF,  # test/not/neg, inc/dec/call/jmp
    }
    rex_w_count = 0
    i = 0
    while i < len(data) - 1:
        if 0x48 <= data[i] <= 0x4F and data[i + 1] in rex_w_opcodes:
            rex_w_count += 1
            i += 2
        else:
            i += 1
    if rex_w_count >= 3:
        return "x64"

    # Check NULL byte ratio - shellcode typically avoids NULL bytes
    null_count = sum(1 for b in data if b == 0)
    if null_count / len(data) > 0.1:
        return False

    # x86 function prologue patterns
    prologue_patterns = [
        b'\x55\x89\xe5',       # push ebp; mov ebp, esp (gcc)
        b'\x55\x8b\xec',       # push ebp; mov ebp, esp (msvc)
        b'\x55\x56',           # push ebp; push esi
        b'\x55\x57',           # push ebp; push edi
        b'\x55\x53',           # push ebp; push ebx
    ]

    first_bytes = data[:3]
    for pattern in prologue_patterns:
        if first_bytes[:len(pattern)] == pattern:
            return "x86"

    # Check for push reg (53/56/57) followed by sub esp or mov
    if data[0] in (0x53, 0x56, 0x57):
        if len(data) > 2 and data[1] == 0x83 and data[2] == 0xEC:
            return "x86"
        if len(data) > 1 and data[1] in (0x53, 0x55, 0x56, 0x57):
            return "x86"

    return False


def save_shellcode(call_addr, data, func_addr):
    """
    Save shellcode to a binary file.
    Returns the saved file path.
    """
    filename = f"shellcode_{func_addr:X}.bin"
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        # Running inside IDA - try idb_path, fallback to cwd
        try:
            script_dir = os.path.dirname(idautils.GetIdbDir())
        except:
            script_dir = os.getcwd()

    filepath = os.path.join(script_dir, filename)
    with open(filepath, 'wb') as f:
        f.write(data)
    return filepath


def decode_string(data):
    """
    Try to decode bytes as string (UTF-8, UTF-16LE, or GUID)
    """
    if not data:
        return "", "empty"

    # Check if it looks like UTF-16 (check first 20 bytes instead of all)
    check_len = min(20, len(data))

    # UTF-16LE: null bytes at odd positions (61 00 70 00 ...)
    is_utf16le = len(data) >= 4 and all(data[i] == 0 for i in range(1, check_len, 2))

    # UTF-16BE or null-prefixed ASCII: null bytes at even positions (00 61 00 70 ...)
    is_utf16be = len(data) >= 4 and all(data[i] == 0 for i in range(0, check_len, 2))

    # Check if it's a GUID (16 bytes) - but only if it's NOT UTF-16LE text
    # Many 7-char UTF-16LE strings are 16 bytes and get falsely detected as GUIDs
    if len(data) == 16 and not is_utf16le:
        guid = format_guid(data)
        if guid:
            # Add interface name if known
            if guid in KNOWN_GUIDS:
                return f"{guid} ({KNOWN_GUIDS[guid]})", "GUID"
            return guid, "GUID"
    elif len(data) == 16 and is_utf16le:
        # For 16-byte UTF-16LE data, only treat as GUID if it's a known COM GUID
        # (COM GUIDs have C000-000000000046 suffix and are NOT valid text)
        is_com_guid = (data[8] == 0xC0 and data[9] == 0x00 and
                       data[14] == 0x00 and data[15] == 0x46)
        if is_com_guid:
            guid = format_guid(data)
            if guid and guid in KNOWN_GUIDS:
                return f"{guid} ({KNOWN_GUIDS[guid]})", "GUID"
            elif guid:
                return guid, "GUID"

    if is_utf16le:
        try:
            return data.decode('utf-16le').rstrip('\x00'), "UTF-16LE"
        except:
            pass

    if is_utf16be:
        try:
            # Try UTF-16BE decoding
            decoded = data.decode('utf-16be').rstrip('\x00')
            return decoded, "UTF-16BE"
        except:
            # Fallback: extract every other byte (skip null bytes)
            try:
                extracted = bytes(data[i] for i in range(1, len(data), 2))
                return extracted.decode('utf-8', errors='replace').rstrip('\x00'), "UTF-16BE"
            except:
                pass

    # Check for separator-interleaved encoding (Layer-2)
    # Pattern: D1 S D2 S D3 S ... where S is a constant separator byte
    sep_result = decode_separator_pattern(data)
    if sep_result:
        return sep_result

    try:
        return data.decode('utf-8', errors='replace').rstrip('\x00'), "UTF-8"
    except:
        return data.hex(), "hex"


def decode_separator_pattern(data, min_len=6, threshold=0.80):
    """
    Detect and decode separator-interleaved encoding.
    Every other byte is a constant 'separator'; data bytes are at the other positions.
    Decoding formula: plaintext = ((data_byte - add) & 0xFF) ^ ((sep - add) & 0xFF)

    Strategy: try SUB(d-s) and XOR first (most common in Lumma), then brute-force.
    Returns (decoded_string, encoding_label) or None.
    """
    if not data or len(data) < min_len:
        return None

    from collections import Counter

    # Check odd positions for separator
    odd_bytes = [data[i] for i in range(1, len(data), 2)]
    if not odd_bytes:
        return None

    counter = Counter(odd_bytes)
    sep_val, sep_count = counter.most_common(1)[0]

    if sep_val == 0x00:  # UTF-16LE, handled elsewhere
        return None
    if sep_count / len(odd_bytes) < threshold:
        return None

    # Extract data bytes (even positions)
    data_bytes = bytes([data[i] for i in range(0, len(data), 2)])

    # Data bytes must not be all identical
    if len(set(data_bytes)) <= 1:
        return None

    def score_candidate(decoded_strip):
        if not decoded_strip or len(decoded_strip) < 2:
            return 0.0
        n = len(decoded_strip)
        printable = sum(1 for b in decoded_strip if 0x20 <= b <= 0x7e)
        letters = sum(1 for b in decoded_strip if (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a))
        ctrl = sum(1 for b in decoded_strip if 0 < b < 0x20)
        high = sum(1 for b in decoded_strip if b > 0x7e)

        score = (printable / n) * 0.5 + (letters / n) * 0.3
        if any(c in decoded_strip for c in b'\\/.:-_*'):
            score += 0.1
        score -= (ctrl / n) * 0.3
        score -= (high / n) * 0.4  # Penalize non-ASCII bytes heavily
        return max(0.0, min(score, 1.0))

    def is_plausible_text(decoded_strip):
        """Check decoded bytes are clean ASCII text. Reject if any byte > 0x7E
        (these produce replacement chars and indicate wrong decoding).
        Also reject random-looking text: require lowercase letter sequences
        or known path/API patterns for strings longer than 5 chars."""
        if not decoded_strip:
            return False
        # All bytes must be ASCII (printable, null, or common control chars)
        if any(b > 0x7e for b in decoded_strip):
            return False
        # For longer strings, check text quality (avoid random ASCII like "TAPPD9ca\9GFT")
        if len(decoded_strip) > 5:
            text = decoded_strip.decode('ascii', errors='replace')
            # Must contain at least one 3+ char lowercase or mixed-case word-like sequence
            import re
            has_word = bool(re.search(r'[a-z]{3}|[A-Z][a-z]{2}|\\[A-Za-z]|[a-z]\.[a-z]', text))
            has_path = bool(re.search(r'[\\/].*[\\/]|\.dll|\.db|\.exe|\.txt|\.eml|\*\.', text))
            if not has_word and not has_path:
                return False
        return True

    def try_decode(add_val):
        delta = (sep_val - add_val) & 0xFF
        decoded = bytes([((b - add_val) & 0xFF) ^ delta for b in data_bytes])
        return decoded.rstrip(b'\x00')

    # Phase 1: Try SUB(d-s) — the most common Lumma layer-2 encoding
    sub_result = try_decode(sep_val)
    sub_score = score_candidate(sub_result)
    if sub_score >= 0.6 and is_plausible_text(sub_result):
        try:
            text = sub_result.decode('utf-8', errors='replace')
            if text:
                return text, f"Layer2(sep=0x{sep_val:02X},SUB)"
        except:
            pass

    # Phase 2: Try XOR (add=0)
    xor_result = try_decode(0)
    xor_score = score_candidate(xor_result)
    if xor_score >= 0.6 and is_plausible_text(xor_result):
        try:
            text = xor_result.decode('utf-8', errors='replace')
            if text:
                return text, f"Layer2(sep=0x{sep_val:02X},XOR)"
        except:
            pass

    # Phase 3: Brute-force all 256 add values (higher threshold + plausibility check)
    best_score = 0.0
    best_text = None
    best_add = 0

    for add_val in range(256):
        if add_val == sep_val or add_val == 0:
            continue  # Already tried
        decoded_strip = try_decode(add_val)
        if not is_plausible_text(decoded_strip):
            continue
        score = score_candidate(decoded_strip)

        if score > best_score:
            best_score = score
            best_add = add_val
            try:
                best_text = decoded_strip.decode('utf-8', errors='replace')
            except:
                best_text = None

    if best_score >= 0.7 and best_text:
        return best_text, f"Layer2(sep=0x{sep_val:02X},add=0x{best_add:02X})"

    return None


def try_decrypt(encrypted, params, index_offset=0, skip_fallback=False):
    """
    Try to decrypt using the detected algorithm type.
    Falls back to trying multiple algorithms if the detected one doesn't produce good results.
    Also tries skipping leading zeros if decryption produces bad results.

    index_offset: XOR key index offset when data starts at non-zero buffer offset
    skip_fallback: if True, skip trying other algorithms (used for KNOWN_DECRYPT_FUNCTIONS)
    """
    # Handle both old format (3 params) and new format (6 params)
    if len(params) == 3:
        loop_count, xor_key, add_value = params
        algo_type, mask1, mask2 = 1, 0, 0
    else:
        loop_count, xor_key, add_value, algo_type, mask1, mask2 = params

    # Count printable characters
    def printable_ratio(data):
        if not data:
            return 0
        printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in [0x00, 0x0a, 0x0d])
        return printable / len(data)

    def decrypt_with_algo(data, length, idx_off=0):
        """Decrypt data with the detected algorithm."""
        if algo_type == 12:
            # Type12: XNOR with complex key + add
            # mask1 = (or_val1 << 8) | or_val2, mask2 = add_val
            or_val1 = (mask1 >> 8) & 0xFF if mask1 else 0x6B
            or_val2 = mask1 & 0xFF if mask1 else 0x94
            add_val_t12 = mask2 if mask2 else 108
            return decrypt_string_type12(data, or_val1, or_val2, add_val_t12, length)
        elif algo_type == 11:
            # Type11: XOR + SUB with index offset
            # xor_key stored in xor_key, sub_val stored in add_value
            return decrypt_string_type11(data, xor_key, add_value, length, idx_off)
        elif algo_type == 10:
            # Type10: Simple XOR with key = (i + key_offset)
            key_offset = mask1 if mask1 else 0x80
            return decrypt_string_type10(data, key_offset, length)
        elif algo_type == 9:
            # Type9: XNOR + rotating key + SUB
            sub_val = add_value if add_value else 36
            return decrypt_string_type9(data, sub_val, length)
        elif algo_type == 8:
            # Type8: Modified key + ADD
            # mask1 = key_mask, mask2 = (key_const << 8) | add_val
            key_mask = mask1 if mask1 else 0x5E
            key_const = ((mask2 >> 8) & 0xFF) if mask2 else 175  # -81 & 0xFF = 175
            add_val_t8 = (mask2 & 0xFF) if mask2 else 124
            # Handle signed key_const
            if key_const > 127:
                key_const = key_const - 256
            return decrypt_string_type8(data, key_mask, key_const, add_val_t8, length)
        elif algo_type == 7:
            # Type7: Simple XOR key + mask-based subtraction
            m1 = mask1 if mask1 else 0x6F
            m2 = mask2 if mask2 else 0x90
            return decrypt_string_type7(data, xor_key, m1, m2, length)
        elif algo_type == 6:
            # Type6: Modified key + SUB
            # mask1 = key_mask, mask2 = (key_const << 8) | sub_val
            key_mask = mask1 if mask1 else 0x34
            key_const = ((mask2 >> 8) & 0xFF) if mask2 else 26
            sub_val_t6 = (mask2 & 0xFF) if mask2 else 24
            return decrypt_string_type6(data, key_mask, key_const, sub_val_t6, length)
        elif algo_type == 5:
            xor_val = mask1 if mask1 else 0xCC
            shl_mask = mask2 if mask2 else 0x66
            return decrypt_string_type5(data, xor_key, xor_val, shl_mask, length)
        elif algo_type == 4:
            xor_val = mask1 if mask1 else 0x14
            shl_mask = mask2 if mask2 else 0xD6
            return decrypt_string_type4(data, xor_key, xor_val, shl_mask, length)
        elif algo_type == 3:
            m1 = mask1 if mask1 else 0xD8
            m2 = mask2 if mask2 else (0xFF ^ m1)
            return decrypt_string_type3(data, xor_key, m1, m2, length)
        else:
            return decrypt_string_type1(data, xor_key, add_value, length, idx_off)

    # Try with original data first, using index_offset for XOR key calculation
    best_result = decrypt_with_algo(encrypted, loop_count, index_offset)
    best_ratio = printable_ratio(best_result)

    # If result is poor, try skipping leading zeros (adjust index_offset accordingly)
    if best_ratio < 0.7:
        skip = 0
        while skip < len(encrypted) and encrypted[skip] == 0:
            skip += 1
        if skip > 0 and skip < len(encrypted):
            trimmed = encrypted[skip:]
            result = decrypt_with_algo(trimmed, min(loop_count, len(trimmed)), index_offset + skip)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

    # If still not good, try other algorithms with different parameters
    # BUT: skip fallback for small buffers (<=8 bytes) — these are binary values
    # (DWORD/WORD/sentinel), not strings. The printable-ratio heuristic is meaningless
    # for 4-byte data and causes false replacements (e.g., 0xFFFFFFFF -> 0x4F4F4F4F).
    # Also skip fallback for KNOWN_DECRYPT_FUNCTIONS — their algorithm is verified correct.
    if best_ratio < 0.7 and loop_count > 8 and not skip_fallback:
        if algo_type != 5:
            # Try Type5 with common values
            for xv, sm in [(0xCC, 0x66), (0x33, 0x66), (0xCC, 0xFE)]:
                result = decrypt_string_type5(encrypted, xor_key, xv, sm, loop_count)
                ratio = printable_ratio(result)
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_result = result

        if algo_type != 4:
            # Try Type4 with common values
            for xv, sm in [(0x14, 0xD6), (0x14, 0xFE), (0xCC, 0x66)]:
                result = decrypt_string_type4(encrypted, xor_key, xv, sm, loop_count)
                ratio = printable_ratio(result)
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_result = result

        if algo_type != 3:
            # Try Type3 with common masks
            for m1, m2 in [(0xD8, 0x27), (0xE8, 0x17), (0xC8, 0x37)]:
                result = decrypt_string_type3(encrypted, xor_key, m1, m2, loop_count)
                ratio = printable_ratio(result)
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_result = result

        if algo_type != 1:
            # Try Type1
            result = decrypt_string_type1(encrypted, xor_key, add_value, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type2
        result2 = decrypt_string_type2(encrypted, xor_key, add_value, loop_count)
        ratio = printable_ratio(result2)
        if ratio > best_ratio:
            best_ratio = ratio
            best_result = result2

        # Try Type6 with common parameters (modified key calculation)
        # key = i - ((2 * i) & key_mask) + key_const
        for key_mask, key_const, sub_val in [(0x34, 26, 24), (0x34, 26, 0), (0x3C, 30, 24)]:
            result = decrypt_string_type6(encrypted, key_mask, key_const, sub_val, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type7 with common parameters (simple XOR key + mask-based subtraction)
        for xk, m1, m2 in [(0x1C, 0x6F, 0x90), (0x1C, 0x90, 0x6F), (0x00, 0x6F, 0x90)]:
            result = decrypt_string_type7(encrypted, xk, m1, m2, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type8 with common parameters (modified key calculation + add)
        # key = i - ((2 * i) & key_mask) + key_const, then add
        for key_mask, key_const, add_val in [(0x5E, -81, 124), (0x5E, 175, 124), (0x34, 26, 24)]:
            result = decrypt_string_type8(encrypted, key_mask, key_const, add_val, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type9 with common parameters (XNOR + rotating key + sub)
        for sub_val in [36, 24, 48]:
            result = decrypt_string_type9(encrypted, sub_val, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type10 with common parameters (simple XOR with i + offset)
        for key_offset in [0x80, 0x00, 0x40, 0xC0]:
            result = decrypt_string_type10(encrypted, key_offset, loop_count)
            ratio = printable_ratio(result)
            if ratio > best_ratio:
                best_ratio = ratio
                best_result = result

        # Try Type11 with common parameters (XOR + SUB with index offset)
        for xk, sv in [(0x91, 124), (0x91, 0), (0x00, 124)]:
            for idx_off in [0, 29]:  # Common index offsets
                result = decrypt_string_type11(encrypted, xk, sv, loop_count, idx_off)
                ratio = printable_ratio(result)
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_result = result

    return best_result


def add_comment(ea, decrypted_string, min_length=3, min_printable_ratio=0.7, func_addr=0):
    """
    Add decrypted string as comment in IDA.
    Returns: "string", "shellcode", "binary", or False
    """
    try:
        # Check for shellcode FIRST - before string decoding
        # Some shellcode (e.g. Heaven's Gate) has high printable ratio
        sc_type = is_shellcode(decrypted_string) if isinstance(decrypted_string, bytes) and len(decrypted_string) >= 16 else False
        if sc_type:
            filepath = save_shellcode(ea, decrypted_string, func_addr)
            sc_label = {"heavens_gate": "Heaven's Gate", "x64": "x64", "x86": "x86"}.get(sc_type, "")
            comment = f"[Decrypted SHELLCODE ({sc_label})] {len(decrypted_string)} bytes, saved to {os.path.basename(filepath)}"
            idc.set_cmt(ea, comment, 0)
            print(f"[+] 0x{ea:08X}: SHELLCODE ({sc_label}) {len(decrypted_string)} bytes -> {filepath}")
            return "shellcode"

        decoded, encoding = decode_string(decrypted_string)
        if not decoded:
            # Check raw bytes for binary data
            if isinstance(decrypted_string, bytes) and len(decrypted_string) >= min_length:
                hex_dump = decrypted_string[:64].hex(' ')
                comment = f"[Decrypted BINARY] {len(decrypted_string)} bytes: {hex_dump}"
                if len(decrypted_string) > 64:
                    comment += "..."
                idc.set_cmt(ea, comment, 0)
                print(f"[+] 0x{ea:08X}: BINARY {len(decrypted_string)} bytes")
                return "binary"
            return False

        # GUIDs are always valid - skip other checks
        if encoding == "GUID":
            idc.set_cmt(ea, f"Decrypted ({encoding}): {decoded}", 0)
            print(f"[+] 0x{ea:08X}: {decoded} ({encoding})")
            return "string"

        # Strip null bytes and whitespace for length check
        stripped = decoded.strip('\x00\r\n\t ')

        # Minimum length filter
        if len(stripped) < min_length:
            return False

        # Calculate printable ratio
        # For small buffers (<=8 bytes), use strict ASCII check on raw bytes
        # For non-UTF-16 encodings, interior null bytes indicate DWORD/binary data
        is_utf16 = encoding in ("UTF-16LE", "UTF-16BE")
        if isinstance(decrypted_string, bytes) and len(decrypted_string) <= 8 and not is_utf16:
            last_nonnull = 0
            for _bi in range(len(decrypted_string) - 1, -1, -1):
                if decrypted_string[_bi] != 0x00:
                    last_nonnull = _bi
                    break
            ascii_count = sum(1 for _bi, _bv in enumerate(decrypted_string) if 0x20 <= _bv <= 0x7E or (_bv == 0x00 and _bi > last_nonnull))
            ratio = ascii_count / len(decrypted_string) if decrypted_string else 0
            # For very small buffers (<=4 bytes), require full printability
            if len(decrypted_string) <= 4 and ascii_count < len(decrypted_string):
                ratio = 0
        else:
            printable = sum(1 for c in stripped if c.isprintable() or c in '\r\n\t')
            ratio = printable / len(stripped) if stripped else 0

        if ratio < min_printable_ratio:
            # Low printable ratio - classify as binary data
            # (shellcode already caught by early check above)
            if isinstance(decrypted_string, bytes) and len(decrypted_string) >= 16:
                hex_dump = decrypted_string[:64].hex(' ')
                comment = f"[Decrypted BINARY] {len(decrypted_string)} bytes: {hex_dump}"
                if len(decrypted_string) > 64:
                    comment += "..."
                idc.set_cmt(ea, comment, 0)
                print(f"[+] 0x{ea:08X}: BINARY {len(decrypted_string)} bytes")
                return "binary"
            return False

        # Filter out strings that are just repeated characters
        if len(set(stripped)) == 1 and len(stripped) > 2:
            return False

        # Filter out strings with too many replacement characters
        if stripped.count('\ufffd') > len(stripped) * 0.3:
            return False

        idc.set_cmt(ea, f"Decrypted ({encoding}): {decoded}", 0)
        print(f"[+] 0x{ea:08X}: {decoded} ({encoding})")
        return "string"
    except:
        pass
    return False


def deobfuscate_stack_strings():
    """
    Find calls to decryption functions and extract stack strings
    """
    print("[*] Deobfuscating stack strings...")
    decrypted_count = 0

    for func_addr, params in DECRYPT_FUNCTIONS.items():
        # Handle both old format (3 params) and new format (6 params)
        if len(params) == 3:
            loop_count, xor_key, add_value = params
        else:
            loop_count, xor_key, add_value, algo_type, mask1, mask2 = params

        # Find all calls to this function
        try:
            for xref in idautils.XrefsTo(func_addr):
                if idc.print_insn_mnem(xref.frm) != "call":
                    continue

                call_addr = xref.frm

                # Check for hardcoded results
                if call_addr in HARDCODED_RESULTS:
                    decrypted = HARDCODED_RESULTS[call_addr]
                    if add_comment(call_addr, decrypted):
                        decrypted_count += 1
                    continue

                # Extract stack string bytes
                encrypted, index_offset = extract_stack_bytes_before_call(call_addr, loop_count + 4)
                expected_len = loop_count - index_offset if index_offset > 0 else loop_count
                if not encrypted or len(encrypted) < expected_len:
                    continue

                # Trim to expected length (only if no index_offset)
                if index_offset == 0:
                    encrypted = encrypted[:loop_count]

                # Try decryption (skip fallback for known functions)
                decrypted = try_decrypt(encrypted, params, index_offset,
                                        skip_fallback=(func_addr in KNOWN_DECRYPT_FUNCTIONS))

                # Check if result is printable and add comment
                if add_comment(call_addr, decrypted):
                    decrypted_count += 1
        except:
            continue

    print(f"[*] Successfully decrypted {decrypted_count} stack strings")
    return decrypted_count


def deobfuscate_all():
    """
    Main function to deobfuscate all strings
    """
    print("[*] Lumma Stealer String Deobfuscator")

    # First, auto-detect decryption functions
    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    print(f"[*] Using {len(DECRYPT_FUNCTIONS)} decryption functions")

    # Deobfuscate stack strings
    total = deobfuscate_stack_strings()

    print(f"[*] Total: Successfully decrypted {total} strings")


def deobfuscate_all_with_comments(min_printable=0.7, min_length=3):
    """
    Comprehensive deobfuscation with IDA comments added to all call sites.

    This function:
    1. Auto-detects all decryption functions
    2. Finds all call sites
    3. Extracts and decrypts strings
    4. Adds comments to IDA database
    5. Reports statistics

    Args:
        min_printable: Minimum ratio of printable characters (default 0.7)
        min_length: Minimum string length (default 3)
    """
    global DECRYPT_FUNCTIONS

    print("=" * 70)
    print("Lumma Stealer Comprehensive Deobfuscation")
    print("=" * 70)

    # Auto-detect if needed
    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    # Statistics
    total_calls = 0
    successful = 0
    failed_extract = 0
    failed_decrypt = 0
    comments_added = 0
    shellcode_count = 0
    binary_count = 0

    # Track all algorithm types
    type_counts = {i: 0 for i in range(1, 13)}  # Type1-12

    all_strings = []

    print(f"\n[*] Processing {len(DECRYPT_FUNCTIONS)} decryption functions... [v2.4-widerange]")

    for func_addr, params in DECRYPT_FUNCTIONS.items():
        if len(params) == 6:
            loop_count, xor_key, add_value, algo_type, mask1, mask2 = params
        else:
            loop_count, xor_key, add_value = params
            algo_type = 1
            mask1, mask2 = 0, 0

        try:
            for xref in idautils.XrefsTo(func_addr):
                if idc.print_insn_mnem(xref.frm) != "call":
                    continue

                total_calls += 1
                call_addr = xref.frm

                # Check for hardcoded results (runtime-computed encrypted data)
                if call_addr in HARDCODED_RESULTS:
                    decrypted = HARDCODED_RESULTS[call_addr]
                    import struct as _st
                    # Format as GUID if 16 bytes
                    if len(decrypted) == 16:
                        d1 = _st.unpack_from('<I', decrypted, 0)[0]
                        d2 = _st.unpack_from('<H', decrypted, 4)[0]
                        d3 = _st.unpack_from('<H', decrypted, 6)[0]
                        d4 = decrypted[8:16]
                        guid_str = "{%08X-%04X-%04X-%s}" % (d1, d2, d3, d4[:2].hex().upper() + "-" + d4[2:].hex().upper())
                        comment = f"[Decrypted T{algo_type}] GUID: {guid_str}"
                        encoding = "GUID"
                        display_str = guid_str
                        ratio = 1.0
                        successful += 1
                    elif len(decrypted) == 4:
                        dw = _st.unpack_from('<I', decrypted, 0)[0]
                        comment = f"[Decrypted T{algo_type}] DWORD: {dw} (0x{dw:08X})"
                        encoding = "binary"
                        display_str = comment
                        ratio = 0
                        binary_count += 1
                    else:
                        comment = f"[Decrypted T{algo_type}] {decrypted.hex()}"
                        encoding = "binary"
                        display_str = decrypted.hex()
                        ratio = 0
                        binary_count += 1
                    idc.set_cmt(call_addr, comment, 0)
                    comments_added += 1
                    if 1 <= algo_type <= 12:
                        type_counts[algo_type] += 1
                    all_strings.append({
                        'addr': call_addr, 'string': display_str,
                        'encoding': encoding, 'algo': algo_type, 'ratio': ratio,
                        'raw_bytes': decrypted.hex(), 'func_addr': func_addr, 'size': len(decrypted)
                    })
                    print(f"[+] 0x{call_addr:08X}: [HARDCODED] {comment}")
                    continue

                # Extract encrypted bytes
                encrypted, index_offset = extract_stack_bytes_before_call(call_addr, loop_count + 4)
                # When index_offset > 0, expected data length is loop_count - index_offset
                expected_len = loop_count - index_offset if index_offset > 0 else loop_count
                # Fallback: try reading from global/static address if stack extraction failed
                if not encrypted or len(encrypted) < expected_len:
                    global_data = try_read_global_data(call_addr, loop_count)
                    if global_data and len(global_data) >= loop_count:
                        encrypted = global_data
                        index_offset = 0
                        expected_len = loop_count
                # Fallback: scan raw bytes for MOV [esp+XX] patterns in garbled code
                if not encrypted or len(encrypted) < expected_len:
                    raw_data, _ = extract_from_raw_bytes(call_addr, loop_count)
                    if raw_data and len(raw_data) >= expected_len:
                        encrypted = raw_data
                        index_offset = 0
                        expected_len = loop_count
                if not encrypted or len(encrypted) == 0:
                    # For small expected sizes (1-4 bytes), the encrypted value may be 0x00
                    # which was skipped by imm_val!=0 filter. Try with zero-filled buffer.
                    if expected_len <= 4:
                        encrypted = b'\x00' * expected_len
                        index_offset = 0
                    else:
                        failed_extract += 1
                        all_strings.append({
                            'addr': call_addr, 'string': f"[EXTRACT_FAILED] expected={loop_count}, got=0",
                            'encoding': 'extract_failed', 'algo': algo_type, 'ratio': 0,
                            'raw_bytes': '', 'func_addr': func_addr, 'size': 0
                        })
                        continue
                # Partial extraction: pad with zeros to expected length and try decryption
                if len(encrypted) < expected_len:
                    encrypted = encrypted + b'\x00' * (expected_len - len(encrypted))

                # Only trim if no index_offset (full buffer was extracted)
                if index_offset == 0:
                    encrypted = encrypted[:loop_count]

                # Decrypt (skip fallback for known functions)
                decrypted = try_decrypt(encrypted, params, index_offset,
                                        skip_fallback=(func_addr in KNOWN_DECRYPT_FUNCTIONS))

                # Debug trace for known problem addresses
                DEBUG_ADDRS = {0x0284C7CC, 0x0281FA37, 0x02822188, 0x0282FB9C, 0x028347DA}
                if call_addr in DEBUG_ADDRS:
                    _is_bytes = isinstance(decrypted, bytes)
                    _len = len(decrypted) if _is_bytes else -1
                    _sc = is_shellcode(decrypted) if _is_bytes and _len >= 16 else False
                    print(f"[DEBUG] 0x{call_addr:08X}: is_bytes={_is_bytes}, len={_len}, is_shellcode={_sc}, first16={decrypted[:16].hex() if _is_bytes else 'N/A'}")

                # Check for shellcode FIRST (before string decoding) -
                # some shellcode (e.g. Heaven's Gate) has high printable ratio
                # and would be misclassified as a garbled string
                sc_type = is_shellcode(decrypted) if isinstance(decrypted, bytes) and len(decrypted) >= 16 else False
                if sc_type:
                    filepath = save_shellcode(call_addr, decrypted, func_addr)
                    sc_label = {"heavens_gate": "Heaven's Gate", "x64": "x64", "x86": "x86"}.get(sc_type, "")
                    comment = f"[Decrypted SHELLCODE ({sc_label})] {len(decrypted)} bytes, saved to {os.path.basename(filepath)}"
                    idc.set_cmt(call_addr, comment, 0)
                    print(f"[+] 0x{call_addr:08X}: SHELLCODE ({sc_label}) {len(decrypted)} bytes -> {filepath}")
                    shellcode_count += 1
                    comments_added += 1
                    if 1 <= algo_type <= 12:
                        type_counts[algo_type] += 1
                    all_strings.append({
                        'addr': call_addr, 'string': f"[SHELLCODE ({sc_label}) {len(decrypted)} bytes]",
                        'encoding': 'shellcode', 'algo': algo_type, 'ratio': 0,
                        'raw_bytes': decrypted.hex(), 'func_addr': func_addr, 'size': len(decrypted)
                    })
                    continue

                decoded, encoding = decode_string(decrypted)

                if not decoded:
                    # Check for shellcode in raw decrypted bytes
                    sc_type2 = is_shellcode(decrypted) if isinstance(decrypted, bytes) and len(decrypted) >= 16 else False
                    if sc_type2:
                        filepath = save_shellcode(call_addr, decrypted, func_addr)
                        sc_label = {"heavens_gate": "Heaven's Gate", "x64": "x64", "x86": "x86"}.get(sc_type2, "")
                        comment = f"[Decrypted SHELLCODE ({sc_label})] {len(decrypted)} bytes, saved to {os.path.basename(filepath)}"
                        idc.set_cmt(call_addr, comment, 0)
                        print(f"[+] 0x{call_addr:08X}: SHELLCODE ({sc_label}) {len(decrypted)} bytes -> {filepath}")
                        shellcode_count += 1
                        comments_added += 1
                        if 1 <= algo_type <= 12:
                            type_counts[algo_type] += 1
                        all_strings.append({
                            'addr': call_addr, 'string': f"[SHELLCODE ({sc_label}) {len(decrypted)} bytes]",
                            'encoding': 'shellcode', 'algo': algo_type, 'ratio': 0,
                            'raw_bytes': decrypted.hex(), 'func_addr': func_addr, 'size': len(decrypted)
                        })
                        continue
                    # Classify as binary data (any size >= 1)
                    if isinstance(decrypted, bytes) and len(decrypted) >= 1:
                        import struct
                        if len(decrypted) <= 8:
                            if len(decrypted) == 4:
                                dword_val = struct.unpack('<I', decrypted)[0]
                                comment = f"[Decrypted T{algo_type}] DWORD: {dword_val} (0x{dword_val:08X})"
                            elif len(decrypted) == 2:
                                word_val = struct.unpack('<H', decrypted)[0]
                                comment = f"[Decrypted T{algo_type}] WORD: {word_val} (0x{word_val:04X})"
                            elif len(decrypted) == 1:
                                comment = f"[Decrypted T{algo_type}] BYTE: {decrypted[0]} (0x{decrypted[0]:02X})"
                            else:
                                comment = f"[Decrypted T{algo_type}] {decrypted.hex()}"
                        else:
                            hex_dump = decrypted[:64].hex(' ')
                            comment = f"[Decrypted BINARY] {len(decrypted)} bytes: {hex_dump}"
                            if len(decrypted) > 64:
                                comment += "..."
                        idc.set_cmt(call_addr, comment, 0)
                        print(f"[+] 0x{call_addr:08X}: BINARY {len(decrypted)} bytes")
                        binary_count += 1
                        comments_added += 1
                        if 1 <= algo_type <= 12:
                            type_counts[algo_type] += 1
                        all_strings.append({
                            'addr': call_addr, 'string': f"[BINARY {len(decrypted)} bytes]",
                            'encoding': 'binary', 'algo': algo_type, 'ratio': 0,
                            'raw_bytes': decrypted.hex(), 'func_addr': func_addr, 'size': len(decrypted)
                        })
                        continue
                    failed_decrypt += 1
                    all_strings.append({
                        'addr': call_addr, 'string': f"[DECRYPT_FAILED] decoded empty, raw={decrypted[:16].hex() if isinstance(decrypted, bytes) else ''}",
                        'encoding': 'decrypt_failed', 'algo': algo_type, 'ratio': 0,
                        'raw_bytes': decrypted.hex() if isinstance(decrypted, bytes) else '', 'func_addr': func_addr,
                        'size': len(decrypted) if isinstance(decrypted, bytes) else 0
                    })
                    continue

                stripped = decoded.strip('\x00\r\n\t ')
                if not stripped:
                    # String decodes to only whitespace/control chars — treat as binary
                    if isinstance(decrypted, bytes) and len(decrypted) >= 1:
                        import struct
                        if len(decrypted) == 4:
                            dword_val = struct.unpack('<I', decrypted)[0]
                            comment = f"[Decrypted T{algo_type}] DWORD: {dword_val} (0x{dword_val:08X})"
                        elif len(decrypted) == 2:
                            word_val = struct.unpack('<H', decrypted)[0]
                            comment = f"[Decrypted T{algo_type}] WORD: {word_val} (0x{word_val:04X})"
                        elif len(decrypted) == 1:
                            comment = f"[Decrypted T{algo_type}] BYTE: {decrypted[0]} (0x{decrypted[0]:02X})"
                        elif len(decrypted) <= 8:
                            comment = f"[Decrypted T{algo_type}] {decrypted.hex()}"
                        else:
                            hex_dump = decrypted[:64].hex(' ')
                            comment = f"[Decrypted BINARY] {len(decrypted)} bytes: {hex_dump}"
                            if len(decrypted) > 64:
                                comment += "..."
                        idc.set_cmt(call_addr, comment, 0)
                        binary_count += 1
                        comments_added += 1
                        if 1 <= algo_type <= 12:
                            type_counts[algo_type] += 1
                        all_strings.append({
                            'addr': call_addr, 'string': f"[BINARY {len(decrypted)} bytes]",
                            'encoding': 'binary', 'algo': algo_type, 'ratio': 0,
                            'raw_bytes': decrypted.hex(), 'func_addr': func_addr, 'size': len(decrypted)
                        })
                        continue
                    failed_decrypt += 1
                    all_strings.append({
                        'addr': call_addr, 'string': f"[DECRYPT_FAILED] stripped empty, raw={decrypted[:16].hex() if isinstance(decrypted, bytes) else ''}",
                        'encoding': 'decrypt_failed', 'algo': algo_type, 'ratio': 0,
                        'raw_bytes': decrypted.hex() if isinstance(decrypted, bytes) else '', 'func_addr': func_addr,
                        'size': len(decrypted) if isinstance(decrypted, bytes) else 0
                    })
                    continue

                # GUIDs are always valid
                is_guid = (encoding == "GUID")

                # For small buffers (<=8 bytes), use strict ASCII check on RAW bytes
                # to prevent Latin-1 extended chars (e.g. 0x89='‰') from inflating ratio
                # For non-UTF-16 encodings, interior null bytes indicate DWORD/binary data
                is_utf16 = encoding in ("UTF-16LE", "UTF-16BE")
                if not is_guid and isinstance(decrypted, bytes) and len(decrypted) <= 8 and not is_utf16:
                    last_nonnull = 0
                    for _bi in range(len(decrypted) - 1, -1, -1):
                        if decrypted[_bi] != 0x00:
                            last_nonnull = _bi
                            break
                    ascii_count = sum(1 for _bi, _bv in enumerate(decrypted) if 0x20 <= _bv <= 0x7E or (_bv == 0x00 and _bi > last_nonnull))
                    ratio = ascii_count / len(decrypted) if decrypted else 0
                    # For very small buffers (<=4 bytes), require full printability.
                    # A single non-printable byte in 4 bytes indicates DWORD data, not text.
                    if len(decrypted) <= 4 and ascii_count < len(decrypted):
                        ratio = 0
                else:
                    printable = sum(1 for c in stripped if c.isprintable())
                    ratio = printable / len(stripped) if not is_guid else 1.0

                # Store result
                raw_hex = decrypted.hex() if isinstance(decrypted, bytes) else ""
                all_strings.append({
                    'addr': call_addr,
                    'string': stripped,
                    'encoding': encoding,
                    'algo': algo_type,
                    'ratio': ratio,
                    'raw_bytes': raw_hex,
                    'func_addr': func_addr,
                    'size': len(decrypted) if isinstance(decrypted, bytes) else len(stripped)
                })

                # Add comment if quality is good (GUIDs always pass)
                if is_guid or (ratio >= min_printable and len(stripped) >= min_length):
                    successful += 1
                    if 1 <= algo_type <= 12:
                        type_counts[algo_type] += 1

                    # Add comment to IDA
                    # Remove any null bytes that might truncate the comment
                    clean_str = stripped.replace('\x00', '')
                    comment = f"[Decrypted T{algo_type}] {clean_str}"
                    if len(comment) > 120:
                        comment = comment[:117] + "..."

                    idc.set_cmt(call_addr, comment, 0)
                    comments_added += 1
                else:
                    # Low printable ratio - handle small binary values (e.g. DWORD)
                    if isinstance(decrypted, bytes) and 1 <= len(decrypted) <= 8:
                        import struct
                        if len(decrypted) == 4:
                            dword_val = struct.unpack('<I', decrypted)[0]
                            comment = f"[Decrypted T{algo_type}] DWORD: {dword_val} (0x{dword_val:08X})"
                        elif len(decrypted) == 2:
                            word_val = struct.unpack('<H', decrypted)[0]
                            comment = f"[Decrypted T{algo_type}] WORD: {word_val} (0x{word_val:04X})"
                        else:
                            comment = f"[Decrypted T{algo_type}] {decrypted.hex()}"
                        idc.set_cmt(call_addr, comment, 0)
                        binary_count += 1
                        comments_added += 1
                        if 1 <= algo_type <= 12:
                            type_counts[algo_type] += 1
                        all_strings[-1]['encoding'] = 'binary'
                        all_strings[-1]['string'] = comment.split('] ', 1)[1]
                        all_strings[-1]['raw_bytes'] = decrypted.hex()
                        continue
                    # Check for binary data (shellcode already caught by early check)
                    if isinstance(decrypted, bytes) and len(decrypted) > 8:
                        hex_dump = decrypted[:64].hex(' ')
                        comment = f"[Decrypted BINARY] {len(decrypted)} bytes: {hex_dump}"
                        if len(decrypted) > 64:
                            comment += "..."
                        idc.set_cmt(call_addr, comment, 0)
                        print(f"[+] 0x{call_addr:08X}: BINARY {len(decrypted)} bytes")
                        binary_count += 1
                        comments_added += 1
                        if 1 <= algo_type <= 12:
                            type_counts[algo_type] += 1
                        all_strings[-1]['encoding'] = 'binary'
                        all_strings[-1]['string'] = f"[BINARY {len(decrypted)} bytes]"
                        all_strings[-1]['raw_bytes'] = decrypted.hex()
                        all_strings[-1]['size'] = len(decrypted)
                        continue
                    failed_decrypt += 1
                    all_strings.append({
                        'addr': call_addr, 'string': f"[DECRYPT_FAILED] low ratio={ratio:.2f}, raw={decrypted[:16].hex() if isinstance(decrypted, bytes) else ''}",
                        'encoding': 'decrypt_failed', 'algo': algo_type, 'ratio': ratio,
                        'raw_bytes': decrypted.hex() if isinstance(decrypted, bytes) else '', 'func_addr': func_addr,
                        'size': len(decrypted) if isinstance(decrypted, bytes) else 0
                    })

        except Exception as e:
            import traceback
            print(f"[!] Error processing func 0x{func_addr:08X}: {e}")
            traceback.print_exc()
            continue

    # Print summary
    print(f"\n{'='*70}")
    print("DEOBFUSCATION SUMMARY")
    print(f"{'='*70}")
    print(f"\nCall Sites:")
    print(f"  Total call sites found: {total_calls}")
    print(f"  Successfully decrypted:  {successful}")
    print(f"  Shellcode detected:      {shellcode_count}")
    print(f"  Binary data detected:    {binary_count}")
    print(f"  Failed (extraction):     {failed_extract}")
    print(f"  Failed (decrypt/filter): {failed_decrypt}")

    print(f"\nAlgorithm Breakdown:")
    algo_names = {
        1: "XOR+NOT+OR+ADD",
        2: "Alternative XOR",
        3: "Mask-based SUB",
        4: "SHL+AND+SUB",
        5: "MBA+Type4",
        6: "ModKey+SUB",
        7: "XOR+MaskSUB",
        8: "ModKey+ADD",
        9: "XNOR+RotKey",
        10: "Simple XOR+i",
        11: "XOR+SUB+IdxOff",
        12: "XNOR+ComplexKey"
    }
    for t in range(1, 13):
        if type_counts[t] > 0:
            print(f"  Type{t:2} ({algo_names.get(t, 'Unknown'):15}): {type_counts[t]} strings")

    print(f"\nIDA Comments:")
    print(f"  Comments added: {comments_added}")

    # Show some interesting strings
    print(f"\n{'='*70}")
    print("NOTABLE DECRYPTED STRINGS")
    print(f"{'='*70}")

    keywords = ['http', 'steam', '.dll', '.exe', 'select', 'registry',
                'cookie', 'password', 'wallet', 'crypto', 'appdata', 'ntdll',
                'kernel32', 'advapi', 'powershell', 'cmd', 'key4', 'login',
                'thunderbird', 'firefox', 'chrome', 'telegram', 'discord',
                '{', 'ipersist', 'ishell', 'iunknown']  # GUIDs and COM interfaces

    for item in all_strings:
        if item['ratio'] >= min_printable:
            s_lower = item['string'].lower()
            for kw in keywords:
                if kw in s_lower:
                    print(f"0x{item['addr']:08X}: {item['string'][:70]}")
                    break

    # Export to JSON files
    export_json(all_strings)

    # Export comprehensive results file (for external analysis)
    summary = {
        "total_calls": total_calls,
        "successful": successful,
        "shellcode_count": shellcode_count,
        "binary_count": binary_count,
        "failed_extract": failed_extract,
        "failed_decrypt": failed_decrypt,
        "comments_added": comments_added,
        "type_counts": {f"type{k}": v for k, v in type_counts.items() if v > 0},
    }
    try:
        export_all_results(all_strings, summary)
    except Exception as e:
        import traceback
        print(f"[!] Failed to export all_results.json: {e}")
        traceback.print_exc()

    # Dump diagnostic info for extract_failed entries
    failed_entries = [e for e in all_strings if e.get('encoding') == 'extract_failed']
    if failed_entries:
        diag = []
        for entry in failed_entries:
            call_addr = entry['addr'] if isinstance(entry['addr'], int) else int(entry['addr'], 16)
            insns = []
            cur = call_addr
            for _ in range(40):
                cur = idc.prev_head(cur)
                if cur == idc.BADADDR:
                    break
                m = idc.print_insn_mnem(cur)
                op0 = idc.print_operand(cur, 0)
                op1 = idc.print_operand(cur, 1)
                op0_type = idc.get_operand_type(cur, 0)
                op1_type = idc.get_operand_type(cur, 1)
                op0_val = idc.get_operand_value(cur, 0)
                op1_val = idc.get_operand_value(cur, 1)
                line = f"0x{cur:08X}: {m:6} {op0}, {op1}"
                insns.append({
                    'addr': f"0x{cur:08X}",
                    'mnem': m,
                    'op0': op0, 'op1': op1,
                    'op0_type': op0_type, 'op1_type': op1_type,
                    'op0_val': f"0x{op0_val:X}" if op0_val else "0",
                    'op1_val': f"0x{op1_val:X}" if op1_val else "0"
                })
                if m in ["retn", "ret"]:
                    break
            diag.append({
                'call_addr': f"0x{call_addr:08X}",
                'func_addr': entry.get('func_addr', ''),
                'expected': entry.get('string', ''),
                'instructions_before_call': insns
            })
        diag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_diagnostics.json")
        try:
            with open(diag_path, 'w', encoding='utf-8') as f:
                json.dump(diag, f, ensure_ascii=True, indent=2, default=str)
            print(f"[*] Diagnostic info for {len(diag)} failed extractions written to extract_diagnostics.json")
        except Exception as e:
            print(f"[!] Failed to write diagnostics: {e}")

    print(f"\n{'='*70}")
    print(f"[*] Done. Added {comments_added} comments to IDA database.")
    print(f"[*] JSON files: decrypted_strings.json, decrypted_binary.json, all_results.json")
    print(f"{'='*70}")

    return all_strings


def deobfuscate_verbose(limit=100):
    """
    Deobfuscate and show ALL results (including filtered ones) for analysis
    """
    print("[*] Verbose deobfuscation mode...")

    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    results = []
    count = 0

    for func_addr, params in DECRYPT_FUNCTIONS.items():
        if count >= limit:
            break

        # Handle both old format (3 params) and new format (6 params)
        if len(params) == 3:
            loop_count, xor_key, add_value = params
            algo_type = 1
        else:
            loop_count, xor_key, add_value, algo_type, mask1, mask2 = params

        try:
            for xref in idautils.XrefsTo(func_addr):
                if count >= limit:
                    break

                if idc.print_insn_mnem(xref.frm) != "call":
                    continue

                call_addr = xref.frm
                encrypted, index_offset = extract_stack_bytes_before_call(call_addr, loop_count + 4)

                expected_len = loop_count - index_offset if index_offset > 0 else loop_count
                if not encrypted or len(encrypted) < expected_len:
                    continue

                if index_offset == 0:
                    encrypted = encrypted[:loop_count]
                decrypted = try_decrypt(encrypted, params, index_offset,
                                        skip_fallback=(func_addr in KNOWN_DECRYPT_FUNCTIONS))
                decoded, encoding = decode_string(decrypted)

                # Show all results
                stripped = decoded.strip('\x00\r\n\t ') if decoded else ""
                printable = sum(1 for c in stripped if c.isprintable()) if stripped else 0
                ratio = printable / len(stripped) * 100 if stripped else 0

                algo_str = f"T{algo_type}"
                print(f"0x{call_addr:08X} | {algo_str} | len={loop_count:3} | xor=0x{xor_key:08X} | "
                      f"{ratio:5.1f}% | {encoding:8} | {repr(stripped)[:50]}")

                results.append((call_addr, stripped, ratio, encoding))
                count += 1
        except:
            continue

    print(f"\n[*] Shown {count} results")
    return results


def export_json(all_strings, strings_file="decrypted_strings.json", binary_file="decrypted_binary.json"):
    """
    Export decrypted results to two separate JSON files.
      - strings_file: printable strings (encoding != shellcode/binary)
      - binary_file:  shellcode and binary byte data
    Each entry includes the call-site address for cross-referencing in IDA.
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        try:
            script_dir = os.path.dirname(idautils.GetIdbDir())
        except:
            script_dir = os.getcwd()

    str_entries = []
    bin_entries = []

    for item in sorted(all_strings, key=lambda x: x['addr']):
        addr_hex = f"0x{item['addr']:08X}"
        func_hex = f"0x{item.get('func_addr', 0):08X}"
        algo = item.get('algo', 0)
        enc = item.get('encoding', '')

        if enc in ('shellcode', 'binary'):
            entry = {
                "address": addr_hex,
                "func_address": func_hex,
                "type": enc,
                "algo_type": algo,
                "size": item.get('size', 0),
                "hex": item.get('raw_bytes', ''),
            }
            bin_entries.append(entry)
        else:
            entry = {
                "address": addr_hex,
                "func_address": func_hex,
                "encoding": enc,
                "algo_type": algo,
                "printable_ratio": round(item.get('ratio', 0), 4),
                "string": item.get('string', ''),
            }
            raw = item.get('raw_bytes', '')
            if raw:
                entry["raw_hex"] = raw
            str_entries.append(entry)

    str_path = os.path.join(script_dir, strings_file)
    bin_path = os.path.join(script_dir, binary_file)

    with open(str_path, 'w', encoding='utf-8') as f:
        json.dump({"count": len(str_entries), "entries": str_entries}, f, ensure_ascii=False, indent=2)

    with open(bin_path, 'w', encoding='utf-8') as f:
        json.dump({"count": len(bin_entries), "entries": bin_entries}, f, ensure_ascii=False, indent=2)

    print(f"[*] Exported {len(str_entries)} strings  -> {str_path}")
    print(f"[*] Exported {len(bin_entries)} binary   -> {bin_path}")
    return str_path, bin_path


def export_all_results(all_strings, summary, filename="all_results.json"):
    """
    Export ALL decrypted results (strings + binary + shellcode) to a single
    comprehensive JSON file with summary statistics.
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        try:
            script_dir = os.path.dirname(idautils.GetIdbDir())
        except:
            script_dir = os.getcwd()

    entries = []
    for item in sorted(all_strings, key=lambda x: x['addr']):
        entry = {
            "address": f"0x{item['addr']:08X}",
            "func_address": f"0x{item.get('func_addr', 0):08X}",
            "encoding": str(item.get('encoding', '')),
            "algo_type": int(item.get('algo', 0)),
            "printable_ratio": round(float(item.get('ratio', 0)), 4),
            "size": int(item.get('size', 0)),
            "string": str(item.get('string', '')),
            "raw_hex": str(item.get('raw_bytes', '')),
        }
        entries.append(entry)

    # Ensure summary values are JSON-serializable plain types
    safe_summary = {}
    for k, v in summary.items():
        if isinstance(v, dict):
            safe_summary[k] = {str(dk): int(dv) for dk, dv in v.items()}
        else:
            safe_summary[k] = int(v) if isinstance(v, (int, float)) else str(v)

    result = {
        "summary": safe_summary,
        "count": len(entries),
        "entries": entries,
    }

    out_path = os.path.join(script_dir, filename)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=True, indent=2, default=str)

    print(f"[*] Exported {len(entries)} total results -> {out_path}")
    return out_path


def export_strings(filename="decrypted_strings.txt"):
    """
    Export all decrypted strings to a file
    """
    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    strings = []

    for func_addr, params in DECRYPT_FUNCTIONS.items():
        # Handle both old format (3 params) and new format (6 params)
        if len(params) == 3:
            loop_count, xor_key, add_value = params
        else:
            loop_count, xor_key, add_value, algo_type, mask1, mask2 = params

        try:
            for xref in idautils.XrefsTo(func_addr):
                if idc.print_insn_mnem(xref.frm) != "call":
                    continue

                call_addr = xref.frm
                encrypted, index_offset = extract_stack_bytes_before_call(call_addr, loop_count + 4)

                expected_len = loop_count - index_offset if index_offset > 0 else loop_count
                if not encrypted or len(encrypted) < expected_len:
                    continue

                if index_offset == 0:
                    encrypted = encrypted[:loop_count]
                decrypted = try_decrypt(encrypted, params, index_offset,
                                        skip_fallback=(func_addr in KNOWN_DECRYPT_FUNCTIONS))

                # Check for shellcode first (before string decoding)
                sc_type = is_shellcode(decrypted) if isinstance(decrypted, bytes) and len(decrypted) >= 16 else False
                if sc_type:
                    sc_label = {"heavens_gate": "Heaven's Gate", "x64": "x64", "x86": "x86"}.get(sc_type, "")
                    strings.append((call_addr, f"[SHELLCODE ({sc_label}) {len(decrypted)} bytes: {decrypted[:32].hex(' ')}]", "shellcode"))
                    continue

                decoded, encoding = decode_string(decrypted)

                if decoded:
                    stripped = decoded.strip('\x00\r\n\t ')
                    printable = sum(1 for c in stripped if c.isprintable()) if stripped else 0
                    ratio = printable / len(stripped) if stripped else 0

                    if ratio >= 0.7 and len(stripped) >= 3:
                        strings.append((call_addr, stripped, encoding))
                    elif isinstance(decrypted, bytes) and len(decrypted) >= 16:
                        strings.append((call_addr, f"[BINARY {len(decrypted)} bytes: {decrypted[:32].hex(' ')}]", "binary"))
                elif isinstance(decrypted, bytes) and len(decrypted) >= 16:
                    if len(decrypted) >= 3:
                        strings.append((call_addr, f"[BINARY {len(decrypted)} bytes: {decrypted[:32].hex(' ')}]", "binary"))
        except:
            continue

    # Sort by address
    strings.sort(key=lambda x: x[0])

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("# Lumma Stealer Decrypted Strings\n")
        f.write(f"# Total: {len(strings)} entries\n\n")
        for addr, s, enc in strings:
            f.write(f"0x{addr:08X} ({enc}): {s}\n")

    print(f"[*] Exported {len(strings)} entries to {filename}")
    return strings


def scan_for_stack_strings():
    """
    Scan for stack string patterns (mov byte ptr [reg+offset], imm)
    """
    print("[*] Scanning for stack strings...")

    stack_string_locations = []

    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        seg_name = idc.get_segm_name(seg)

        if ".text" not in seg_name.lower():
            continue

        ea = seg_start
        while ea < seg_end:
            consecutive = 0
            first_ea = ea

            while consecutive < 50:
                mnem = idc.print_insn_mnem(ea)
                if mnem != "mov":
                    break

                op1 = idc.print_operand(ea, 0).lower()
                if "byte" not in op1 or "ptr" not in op1:
                    break

                op2_type = idc.get_operand_type(ea, 1)
                if op2_type != idc.o_imm:
                    break

                consecutive += 1
                ea = idc.next_head(ea)
                if ea == idc.BADADDR:
                    break

            if consecutive >= 4:
                stack_string_locations.append((first_ea, consecutive))
            else:
                ea = idc.next_head(first_ea)
                if ea == idc.BADADDR:
                    break

    print(f"[*] Found {len(stack_string_locations)} potential stack strings")
    return stack_string_locations


# ============================================================================
# Manual decryption test function
# ============================================================================

def test_decrypt(encrypted_hex, xor_key, add_value):
    """
    Test decryption manually
    Usage: test_decrypt("aa5f9d59975ba45573", 0x4c18518c, 0x30)
    """
    encrypted = bytes.fromhex(encrypted_hex.replace(" ", ""))
    result1 = decrypt_string_type1(encrypted, xor_key, add_value, len(encrypted))
    result2 = decrypt_string_type2(encrypted, xor_key, add_value, len(encrypted))

    print(f"Type1 hex: {result1.hex()}")
    print(f"Type2 hex: {result2.hex()}")

    decoded1, enc1 = decode_string(result1)
    decoded2, enc2 = decode_string(result2)
    print(f"Type1 ({enc1}): {decoded1}")
    print(f"Type2 ({enc2}): {decoded2}")


def test_decrypt_type3(encrypted_hex, xor_key, mask1=0xD8, mask2=0x27):
    """
    Test Type3 decryption manually
    Usage: test_decrypt_type3("2ab324b1...", 0x39ADE96A)
    """
    encrypted = bytes.fromhex(encrypted_hex.replace(" ", ""))
    result = decrypt_string_type3(encrypted, xor_key, mask1, mask2, len(encrypted))

    print(f"Type3 hex: {result.hex()}")
    decoded, enc = decode_string(result)
    print(f"Type3 ({enc}): {decoded}")


def test_decrypt_type4(encrypted_hex, xor_key, xor_val=0x14, shl_mask=0xD6):
    """
    Test Type4 decryption manually
    Usage: test_decrypt_type4("dc9e0a9c...", 0x8025028B)
    """
    encrypted = bytes.fromhex(encrypted_hex.replace(" ", ""))
    result = decrypt_string_type4(encrypted, xor_key, xor_val, shl_mask, len(encrypted))

    print(f"Type4 hex: {result.hex()}")
    decoded, enc = decode_string(result)
    print(f"Type4 ({enc}): {decoded}")


def debug_decrypt_function(func_addr):
    """
    Debug a specific decrypt function to show detected algorithm type and parameters
    """
    print(f"\n{'='*70}")
    print(f"Analyzing decrypt function at 0x{func_addr:08X}")
    print(f"{'='*70}")

    check_ea = func_addr
    loop_count = None
    xor_key = None
    add_val = 0
    has_ret = False

    # Track mask detection for Type3
    has_and_mask1 = False
    has_xor_mask1 = False
    has_and_mask2 = False
    has_sub = False
    detected_mask1 = None
    detected_mask2 = None

    for i in range(80):
        check_ea = idc.next_head(check_ea)
        if check_ea == idc.BADADDR:
            break

        mnem = idc.print_insn_mnem(check_ea)
        op0 = idc.print_operand(check_ea, 0).lower()
        op1 = idc.print_operand(check_ea, 1)
        op1_type = idc.get_operand_type(check_ea, 1)
        op1_val = idc.get_operand_value(check_ea, 1) if op1_type == idc.o_imm else None

        marker = ""

        # Detect patterns
        if mnem == "cmp" and loop_count is None:
            if op1_type == idc.o_imm and ("esp" in op0 or "ebp" in op0 or "var_" in op0):
                val = idc.get_operand_value(check_ea, 1)
                if 0 < val < 0x200:
                    loop_count = val
                    marker = f" <-- LOOP_COUNT={val}"

        if mnem == "xor" and xor_key is None:
            if op0 == "eax" and op1_type == idc.o_imm:
                val = idc.get_operand_value(check_ea, 1)
                if val != 0 and val != 0xffffffff and val > 0xFFFF:
                    xor_key = val
                    marker = f" <-- XOR_KEY=0x{val:08X}"

        if mnem == "add" and op0 == "al" and op1_type == idc.o_imm:
            add_val = idc.get_operand_value(check_ea, 1) & 0xFF
            marker = f" <-- ADD_VAL=0x{add_val:02X} (Type1)"

        if mnem == "and" and op1_type == idc.o_imm:
            val = op1_val & 0xFF
            if val in [0xD8, 0xE8, 0xC8, 0xF8]:
                has_and_mask1 = True
                detected_mask1 = val
                marker = f" <-- MASK1=0x{val:02X} (Type3)"
            elif val in [0x27, 0x17, 0x37, 0x07]:
                has_and_mask2 = True
                detected_mask2 = val
                marker = f" <-- MASK2=0x{val:02X} (Type3)"

        if mnem == "xor" and op1_type == idc.o_imm:
            val = op1_val & 0xFF
            if detected_mask1 and val == detected_mask1:
                has_xor_mask1 = True
                marker = f" <-- XOR_MASK1=0x{val:02X} (Type3)"

        if mnem == "sub":
            has_sub = True
            if has_and_mask1 and has_xor_mask1 and has_and_mask2:
                marker = " <-- SUB (Type3 confirmed)"

        if mnem in ["retn", "ret"]:
            has_ret = True
            marker = " <-- RET"

        print(f"0x{check_ea:08X}: {mnem:6} {op0}, {op1}{marker}")

        if has_ret:
            break

    print(f"\n{'='*70}")
    print("Detection Result:")
    print(f"  Loop count: {loop_count}")
    print(f"  XOR key: 0x{xor_key:08X}" if xor_key else "  XOR key: None")
    print(f"  Add value: 0x{add_val:02X}")

    if has_and_mask1 and has_xor_mask1 and has_and_mask2 and has_sub:
        print(f"  Algorithm: Type3 (mask1=0x{detected_mask1:02X}, mask2=0x{detected_mask2:02X})")
    else:
        print(f"  Algorithm: Type1 (add)")
        print(f"    Type3 indicators: and_mask1={has_and_mask1}, xor_mask1={has_xor_mask1}, "
              f"and_mask2={has_and_mask2}, sub={has_sub}")
    print(f"{'='*70}")


def list_decrypt_functions():
    """
    List all detected decryption functions
    """
    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    print(f"\n{'='*80}")
    print(f"Detected {len(DECRYPT_FUNCTIONS)} decryption functions:")
    print(f"{'='*80}")
    print(f"{'Address':<12} {'Type':<5} {'Loop':<6} {'XOR Key':<12} {'Add':<6} {'Params':<16}")
    print(f"{'-'*12} {'-'*5} {'-'*6} {'-'*12} {'-'*6} {'-'*16}")

    type1_count = 0
    type3_count = 0
    type4_count = 0

    for addr, params in sorted(DECRYPT_FUNCTIONS.items()):
        if len(params) == 3:
            loop, xor_k, add_v = params
            algo_type, mask1, mask2 = 1, 0, 0
        else:
            loop, xor_k, add_v, algo_type, mask1, mask2 = params

        if algo_type == 1:
            type1_count += 1
            param_str = "-"
        elif algo_type == 3:
            type3_count += 1
            param_str = f"m1=0x{mask1:02X}/m2=0x{mask2:02X}"
        elif algo_type == 4:
            type4_count += 1
            param_str = f"xv=0x{mask1:02X}/sm=0x{mask2:02X}"
        elif algo_type == 5:
            type4_count += 1  # Count with Type4
            param_str = f"xv=0x{mask1:02X}/sm=0x{mask2:02X} (MBA+T4)"
        else:
            param_str = "-"

        print(f"0x{addr:08X}  T{algo_type:<4} 0x{loop:02X}   0x{xor_k:08X}   0x{add_v:02X}   {param_str}")

    print(f"\n[*] Summary: Type1={type1_count}, Type3={type3_count}, Type4/5={type4_count}")


def debug_call_site(call_addr, num_instructions=30):
    """
    Show instructions before a call to understand stack string construction
    """
    print(f"\n{'='*70}")
    print(f"Instructions before call at 0x{call_addr:08X}")
    print(f"{'='*70}")

    current = call_addr
    instructions = []

    # Collect instructions going backwards
    for _ in range(num_instructions):
        current = idc.prev_head(current)
        if current == idc.BADADDR:
            break

        mnem = idc.print_insn_mnem(current)
        op0 = idc.print_operand(current, 0)
        op1 = idc.print_operand(current, 1)
        op1_type = idc.get_operand_type(current, 1)

        # Mark interesting instructions
        marker = ""
        if mnem == "mov":
            if "byte" in op0.lower() and op1_type == idc.o_imm:
                marker = " <-- BYTE"
            elif "dword" in op0.lower() and op1_type == idc.o_imm:
                marker = " <-- DWORD"
            elif "word" in op0.lower() and op1_type == idc.o_imm:
                marker = " <-- WORD"

        instructions.append((current, mnem, op0, op1, marker))

        if mnem in ["call", "ret", "retn"]:
            break

    # Print in forward order
    for addr, mnem, op0, op1, marker in reversed(instructions):
        print(f"0x{addr:08X}: {mnem:6} {op0}, {op1}{marker}")

    print(f"0x{call_addr:08X}: call   ...")


def analyze_calls():
    """
    Analyze all calls to decryption functions and show extraction stats
    """
    if not DECRYPT_FUNCTIONS:
        auto_detect_decrypt_functions()

    total_calls = 0
    successful_extractions = 0
    failed_extractions = 0
    funcs_with_calls = 0

    print(f"\n{'='*70}")
    print("Analyzing calls to decryption functions...")
    print(f"{'='*70}")

    for func_addr, params in sorted(DECRYPT_FUNCTIONS.items()):
        # Handle both old format (3 params) and new format (6 params)
        if len(params) == 3:
            loop_count, xor_key, add_value = params
            algo_type = 1
        else:
            loop_count, xor_key, add_value, algo_type, mask1, mask2 = params

        call_count = 0
        extract_success = 0

        try:
            for xref in idautils.XrefsTo(func_addr):
                if idc.print_insn_mnem(xref.frm) != "call":
                    continue

                call_count += 1
                call_addr = xref.frm

                encrypted, _ = extract_stack_bytes_before_call(call_addr, loop_count + 4)
                if encrypted and len(encrypted) >= loop_count:
                    extract_success += 1
        except:
            pass

        if call_count > 0:
            funcs_with_calls += 1
            total_calls += call_count
            successful_extractions += extract_success
            failed_extractions += (call_count - extract_success)

            if call_count != extract_success:
                print(f"0x{func_addr:08X} (T{algo_type}): {call_count} calls, {extract_success} extracted, "
                      f"{call_count - extract_success} failed (len={loop_count})")

    print(f"\n{'='*70}")
    print(f"Summary:")
    print(f"  Total decrypt functions: {len(DECRYPT_FUNCTIONS)}")
    print(f"  Functions with calls: {funcs_with_calls}")
    print(f"  Total calls: {total_calls}")
    print(f"  Successful extractions: {successful_extractions}")
    print(f"  Failed extractions: {failed_extractions}")
    print(f"{'='*70}")


# Run automatically when script is loaded
if __name__ == "__main__":
    print("=" * 70)
    print("Lumma Stealer String Deobfuscator (12 Algorithm Types)")
    print("=" * 70)
    print("")
    print("Supported Algorithm Types:")
    print("  Type1:  XOR+NOT+OR+ADD      [most common]")
    print("  Type3:  Mask-based SUB      [steamcommunity URL]")
    print("  Type4:  SHL+AND+SUB         [Content-Type headers]")
    print("  Type5:  MBA+Type4           [combined]")
    print("  Type6:  ModKey+SUB          [powershell]")
    print("  Type7:  XOR+MaskSUB         [NT functions]")
    print("  Type8:  ModKey+ADD          [NtFreeVirtualMemory]")
    print("  Type9:  XNOR+RotKey+SUB     [key4.db]")
    print("  Type10: Simple XOR(i+off)   [GUIDs]")
    print("  Type11: XOR+SUB+IdxOff      [HTTP Content-Type]")
    print("  Type12: XNOR+ComplexKey     [complex key derivation]")
    print("")
    print("Available functions:")
    print("  deobfuscate_all_with_comments() - Full analysis + IDA comments (RECOMMENDED)")
    print("  auto_detect_decrypt_functions() - Detect decryption functions")
    print("  list_decrypt_functions()        - List detected functions with types")
    print("  export_strings(filename)        - Export strings to text file")
    print("  export_json(all_strings)        - Export strings + binary to JSON")
    print("")
    print("To add new decrypt functions:")
    print("  add_decrypt_function(0xADDR, loop, type, key_mask=X, key_const=Y, ...)")
    print("")

    # Auto-run if in IDA
    try:
        if idaapi.get_imagebase():
            deobfuscate_all_with_comments()
    except NameError:
        print("[!] Run this script in IDA Pro")
    except Exception as e:
        import traceback
        print(f"[!] Error during execution: {e}")
        traceback.print_exc()
