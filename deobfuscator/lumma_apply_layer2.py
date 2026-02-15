"""
Lumma Stealer - Apply Layer 2 Decoded Results to IDA Comments
=============================================================
IDA Python script that reads Layer 2 decoded results from JSON files
and updates IDA comments for entries that were improved by Layer 2 decoding.

Usage (IDA Pro):
    File -> Script file -> lumma_apply_layer2.py
    apply_layer2_comments()    # Apply all Layer 2 comments
    revert_layer2_comments()   # Revert to original Layer 1 comments
"""

import json
import os
import idaapi
import idautils
import idc

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Store original comments for revert
_original_comments = {}


def load_json(filename):
    """Load a JSON file from the script directory."""
    filepath = os.path.join(SCRIPT_DIR, filename)
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return None
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def apply_layer2_comments():
    """
    Read decrypted_strings_v2.json and decrypted_binary_v2.json,
    compare with the original L1 results, and update IDA comments
    for entries improved by Layer 2 decoding.
    """
    global _original_comments

    # Load Layer 1 results
    l1_strings = load_json("decrypted_strings.json")
    l1_binary = load_json("decrypted_binary.json")

    # Load Layer 2 results
    l2_strings = load_json("decrypted_strings_v2.json")
    l2_binary = load_json("decrypted_binary_v2.json")

    if not l1_strings or not l2_strings:
        print("[!] Cannot load required JSON files")
        return

    # Build L1 string lookup: address -> string
    l1_str_map = {}
    for entry in l1_strings.get("entries", []):
        addr = int(entry["address"], 16)
        l1_str_map[addr] = entry.get("string", "")

    # Build L1 binary lookup: address -> hex
    l1_bin_map = {}
    if l1_binary:
        for entry in l1_binary.get("entries", []):
            addr = int(entry["address"], 16)
            l1_bin_map[addr] = entry.get("hex", "")

    updated_count = 0
    skipped_count = 0

    # Process string entries
    for entry in l2_strings.get("entries", []):
        addr = int(entry["address"], 16)
        l2_decoded = entry.get("layer2_decoded", "")
        l2_pattern = entry.get("layer2_pattern", "")
        l2_conf = entry.get("layer2_confidence", 0)
        l2_context = entry.get("layer2_context_match", "")

        if not l2_pattern:
            # No Layer 2 decoding applied
            continue

        # Use context match if available (more accurate), otherwise decoded
        l2_string = l2_context if l2_context else l2_decoded
        if not l2_string:
            continue

        l1_string = l1_str_map.get(addr, "")

        if l1_string == l2_string:
            # No improvement
            continue

        if l2_conf < 0.50:
            skipped_count += 1
            continue

        # Save original comment for revert
        orig_comment = idc.get_cmt(addr, 0) or ""
        if addr not in _original_comments:
            _original_comments[addr] = orig_comment

        # Truncate display string
        display = l2_string
        if len(display) > 80:
            display = display[:77] + "..."

        # Build new comment
        conf_str = f"{l2_conf:.2f}"
        comment = f"[Decrypted L2] ({l2_pattern}, conf={conf_str}) {display}"

        idc.set_cmt(addr, comment, 0)
        updated_count += 1
        print(f"  0x{addr:08X}: {comment}")

    # Process binary entries
    if l2_binary:
        for entry in l2_binary.get("entries", []):
            addr = int(entry["address"], 16)
            l2_decoded = entry.get("layer2_decoded", "")
            l2_pattern = entry.get("layer2_pattern", "")
            l2_conf = entry.get("layer2_confidence", 0)
            l2_context = entry.get("layer2_context_match", "")

            # Use context match if available, otherwise decoded
            l2_string = l2_context if l2_context else l2_decoded
            if not l2_pattern or not l2_string:
                continue

            if l2_conf < 0.50:
                skipped_count += 1
                continue

            # Save original comment for revert
            orig_comment = idc.get_cmt(addr, 0) or ""
            if addr not in _original_comments:
                _original_comments[addr] = orig_comment

            # Truncate display string
            display = l2_string
            if len(display) > 80:
                display = display[:77] + "..."

            # Build new comment
            conf_str = f"{l2_conf:.2f}"
            comment = f"[Decrypted L2] ({l2_pattern}, conf={conf_str}) {display}"

            idc.set_cmt(addr, comment, 0)
            updated_count += 1
            print(f"  0x{addr:08X}: {comment}")

    print(f"\n[+] Layer 2 comments applied: {updated_count} entries updated")
    if skipped_count:
        print(f"    ({skipped_count} low-confidence entries skipped, conf < 0.50)")
    print(f"    Use revert_layer2_comments() to undo")


def revert_layer2_comments():
    """Revert all Layer 2 comments to original Layer 1 comments."""
    if not _original_comments:
        print("[!] No comments to revert")
        return

    count = 0
    for addr, orig_comment in _original_comments.items():
        idc.set_cmt(addr, orig_comment, 0)
        count += 1

    _original_comments.clear()
    print(f"[+] Reverted {count} comments to original Layer 1 state")


# Auto-run when loaded
if __name__ == "__main__" or idaapi.IDA_SDK_VERSION:
    print("\n" + "=" * 60)
    print("Lumma Stealer - Layer 2 Comment Updater")
    print("=" * 60)
    print("\nCommands:")
    print("  apply_layer2_comments()   - Update IDA comments with L2 results")
    print("  revert_layer2_comments()  - Revert to original L1 comments")
    print()
