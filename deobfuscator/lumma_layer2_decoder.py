#!/usr/bin/env python3
"""
Lumma Stealer Layer 2 Decoder
=============================
Processes decrypted_strings.json and decrypted_binary.json to apply
second-layer decoding on partially-decoded entries.

Layer 1 (outer XOR/MBA) was already removed by lumma_deobfuscator.py.
This script handles the inner encoding layer that remains in some entries.

Patterns detected:
  Pattern 1: [encrypted wchar prefix][UTF-16LE body] - wide strings with encrypted head
  Pattern 2: (data)(sep)(data)(sep)... - separator-interleaved encoding
  Pattern 3: [repeated byte prefix][readable text] - keystream residue prefix
  Pattern 4: Fully encoded binary blobs (cannot decode statically)

Usage:
    python3 lumma_layer2_decoder.py [--input-dir DIR] [--output-dir DIR]
"""

import json
import os
import sys
import argparse
from collections import Counter


# ===========================================================================
# Known strings for contextual matching / verification
# ===========================================================================
KNOWN_CONTEXT_STRINGS = [
    # Network / HTTP
    "HTTP", "HTTPS", "https://", "http://",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Disposition: form-data; name=",
    "multipart/form-data; boundary=",
    # Registry
    "\\REGISTRY\\MACHINE",
    "\\REGISTRY\\USER",
    # Crypto / DLLs
    "Microsoft Software Key Storage Provider",
    "advapi32.dll",
    "crypt32.dll",
    "crypt.dll",
    "ncrypt.dll",
    "bcrypt.dll",
    "nss3.dll",
    # Outlook / MAPI profiles
    "Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\",
    "Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\",
    "Microsoft\\Office\\14.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\",
    "Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676\\",
    "Microsoft\\Windows Messaging Subsystem\\Profiles\\",
    # Mail
    "\\Windows Mail\\Local Folders",
    "Software\\Windows Mail\\Local Folders",
    "\\LocalState\\Indexed\\LiveComm\\",
    # Commands
    "powershell -exec bypass -f \"",
    "rundll32 \"",
    # Paths / Files
    "%TEMP%\\",
    "\\Local State",
    "\\Local Storage\\leveldb\\",
    "key4.db",
    "\\key4.db",
    "debug.txt",
    "dump.txt",
    "Processes.txt",
    "*.eml",
    "account",
    # Browser data
    "Login Data",
    "Web Data",
    "Cookies",
    "default\\moz-extension",
    "\\default\\moz-extension+++",
    # Software
    "Discord",
    "Canary",
    "Software\\Microsoft\\",
    "InstallLocation",
    # System
    "Privilege",
    "VirtualMemory",
    "bound_encrypted_key",
    "AppData",
    "Application",
]

# Minimum decoded string length for context matching
MIN_CONTEXT_MATCH_LEN = 4


# ===========================================================================
# Pattern Detection
# ===========================================================================

def detect_separator_pattern(raw_bytes, min_len=6, threshold=0.80):
    """
    Detect if raw_bytes has separator encoding: every other byte is a constant.
    Returns (sep_position, sep_value, confidence) or None.
    sep_position: 'odd' means separator at odd indices (1,3,5,...),
                  data at even indices (0,2,4,...).
    """
    if len(raw_bytes) < min_len:
        return None

    # Check odd positions first (most common: data at 0,2,4... sep at 1,3,5...)
    odd_bytes = [raw_bytes[i] for i in range(1, len(raw_bytes), 2)]
    if len(odd_bytes) >= 3:
        counter = Counter(odd_bytes)
        val, cnt = counter.most_common(1)[0]
        ratio = cnt / len(odd_bytes)
        if ratio >= threshold and val != 0x00:
            # Verify data bytes are not all the same (would be just repeating pattern)
            data_bytes = [raw_bytes[i] for i in range(0, len(raw_bytes), 2)]
            if len(set(data_bytes)) > 1:
                return ('odd', val, ratio)

    # Check even positions
    even_bytes = [raw_bytes[i] for i in range(0, len(raw_bytes), 2)]
    if len(even_bytes) >= 3:
        counter = Counter(even_bytes)
        val, cnt = counter.most_common(1)[0]
        ratio = cnt / len(even_bytes)
        if ratio >= threshold and val != 0x00:
            data_bytes = [raw_bytes[i] for i in range(1, len(raw_bytes), 2)]
            if len(set(data_bytes)) > 1:
                return ('even', val, ratio)

    return None


def detect_multi_separator(raw_bytes):
    """
    Detect entries with two different separator segments.
    Returns list of (start, end, sep_val) tuples or None.
    """
    if len(raw_bytes) < 8:
        return None

    # Check if odd-position bytes change value partway through
    odd_bytes = [(i, raw_bytes[i]) for i in range(1, len(raw_bytes), 2)]
    if len(odd_bytes) < 4:
        return None

    # Find transition point
    segments = []
    seg_start = 0
    current_sep = odd_bytes[0][1]

    for idx, (pos, val) in enumerate(odd_bytes[1:], 1):
        if val != current_sep:
            # End of segment
            seg_end = odd_bytes[idx - 1][0] + 1
            if idx - seg_start >= 3:
                segments.append((seg_start * 2, seg_end + 1, current_sep))
            seg_start = idx
            current_sep = val

    # Last segment
    if len(odd_bytes) - seg_start >= 3:
        seg_end = odd_bytes[-1][0] + 1
        segments.append((seg_start * 2, seg_end + 1, current_sep))

    if len(segments) >= 2:
        return segments
    return None


def detect_plain_utf16le(raw_bytes):
    """
    Detect if raw_bytes is already plain UTF-16LE (no encryption).
    Strict: ALL wchar hi-bytes before the null terminator must be 0x00.
    Allows trailing garbage after the null terminator.
    Returns decoded string or None.
    """
    if len(raw_bytes) < 4 or len(raw_bytes) % 2 != 0:
        return None

    # Find null terminator (0x0000)
    null_pos = -1
    for i in range(0, len(raw_bytes) - 1, 2):
        if raw_bytes[i] == 0x00 and raw_bytes[i + 1] == 0x00:
            null_pos = i
            break

    if null_pos < 0:
        # No null terminator; check all wchars
        check_end = len(raw_bytes)
    else:
        check_end = null_pos

    if check_end < 4:
        return None

    # ALL hi-bytes before null must be 0x00 (no encrypted wchars at all)
    for i in range(0, check_end, 2):
        if raw_bytes[i + 1] != 0x00:
            return None

    # Decode only up to null terminator
    data_to_decode = raw_bytes[:check_end + 2] if null_pos >= 0 else raw_bytes
    try:
        text = data_to_decode.decode('utf-16-le').rstrip('\x00')
    except (UnicodeDecodeError, ValueError):
        return None

    if text and printable_ratio(text.encode('ascii', errors='replace')) > 0.7:
        return text
    return None


def detect_utf16le_prefix(raw_bytes):
    """
    Detect Pattern 1: encrypted wchar prefix followed by clean UTF-16LE body.
    Also handles embedded encrypted wchars (e.g., wchar[0] is plain, wchar[1]
    is encrypted, wchar[2+] are plain).
    Returns dict with prefix info and decoded body, or None.
    """
    if len(raw_bytes) < 4 or len(raw_bytes) % 2 != 0:
        return None

    # Classify each wchar as encrypted (hi != 0x00) or plain (hi == 0x00)
    n_wchars = len(raw_bytes) // 2
    wchar_types = []  # True = encrypted, False = plain
    for i in range(n_wchars):
        hi = raw_bytes[i * 2 + 1]
        wchar_types.append(hi != 0x00)

    # Find the first plain wchar
    first_plain = -1
    for i, is_enc in enumerate(wchar_types):
        if not is_enc:
            first_plain = i
            break

    if first_plain < 0:
        return None  # All encrypted -> not this pattern

    # Count encrypted wchars before the main plain body starts
    # Handle two cases:
    #   Case A: prefix of encrypted wchars, then plain body
    #   Case B: mixed (e.g., plain[0], enc[1], plain[2:])

    # Find the start of the main contiguous plain body
    body_start = -1
    for i in range(first_plain, n_wchars):
        # Look for a run of at least 3 plain wchars
        if i + 2 < n_wchars and not any(wchar_types[i:i + 3]):
            body_start = i
            break
        elif i + 1 < n_wchars and not any(wchar_types[i:i + 2]):
            body_start = i
            break

    if body_start < 0:
        # Maybe just a single encrypted wchar followed by all-plain
        if first_plain == 0 and sum(wchar_types) <= 2:
            # Find first encrypted wchar
            for i, is_enc in enumerate(wchar_types):
                if is_enc:
                    body_start = 0
                    break
        if body_start < 0:
            return None

    # Count encrypted wchars before body_start
    n_prefix_encrypted = sum(1 for t in wchar_types[:body_start] if t)
    # Also count encrypted wchars within the body (embedded)
    n_embedded_encrypted = sum(1 for t in wchar_types[body_start:] if t)

    if n_prefix_encrypted == 0 and n_embedded_encrypted <= 1:
        # Handle embedded encrypted wchar case
        if n_embedded_encrypted == 0:
            return None  # All plain, no encryption

    # Extract body bytes
    prefix_end = body_start * 2
    body_bytes = raw_bytes[prefix_end:]
    if len(body_bytes) < 4:
        return None

    # Verify body has mostly plain wchars
    body_hi_bytes = [body_bytes[i + 1] for i in range(0, len(body_bytes) - 1, 2)]
    zero_ratio = sum(1 for b in body_hi_bytes if b == 0x00) / max(len(body_hi_bytes), 1)
    if zero_ratio < 0.7:
        return None

    prefix_bytes = raw_bytes[:prefix_end]
    n_prefix_wchars = body_start

    try:
        body_text = body_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
    except (UnicodeDecodeError, ValueError):
        return None

    if not body_text:
        return None

    # Collect hi bytes from prefix
    hi_bytes = [raw_bytes[i + 1] for i in range(0, prefix_end, 2)]

    return {
        'prefix_bytes': prefix_bytes,
        'prefix_wchars': n_prefix_wchars,
        'body_text': body_text,
        'hi_bytes': hi_bytes,
        'body_start_offset': prefix_end,
        'embedded_encrypted': n_embedded_encrypted,
    }


def detect_repeated_prefix(raw_bytes, max_prefix=8):
    """
    Detect Pattern 3: repeated identical byte prefix + different content.
    Returns dict or None.
    """
    if len(raw_bytes) < 4:
        return None

    first = raw_bytes[0]
    if first == 0x00:
        return None

    # Find how many leading bytes are the same
    repeat_count = 1
    for i in range(1, min(len(raw_bytes), max_prefix + 1)):
        if raw_bytes[i] == first:
            repeat_count += 1
        else:
            break

    # Need at least 2 repeated bytes and they should be even count for wchar alignment
    if repeat_count < 2:
        return None

    rest = raw_bytes[repeat_count:]
    if len(rest) < 2:
        return None

    # Check if rest looks different from prefix byte
    if rest[0] == first:
        return None

    return {
        'prefix_byte': first,
        'prefix_len': repeat_count,
        'body': rest,
    }


# ===========================================================================
# Decoding Functions
# ===========================================================================

def printable_ratio(data):
    """Fraction of bytes that are printable ASCII (0x20-0x7e)."""
    if not data:
        return 0.0
    return sum(1 for b in data if 0x20 <= b <= 0x7e) / len(data)


def ascii_letter_ratio(data):
    """Fraction of bytes that are ASCII letters (a-z, A-Z)."""
    if not data:
        return 0.0
    return sum(1 for b in data if (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a)) / len(data)


def has_path_chars(text):
    """Check if text contains path-like characters."""
    return '\\' in text or '/' in text or '.' in text or ':' in text


def char_similarity(a, b):
    """
    Character-level positional similarity between two strings.
    Returns fraction of matching characters at aligned positions.
    """
    if not a or not b:
        return 0.0
    shorter = min(len(a), len(b))
    longer = max(len(a), len(b))
    if longer == 0:
        return 0.0
    matches = sum(1 for i in range(shorter) if a[i] == b[i])
    return matches / longer


def try_similarity_match(decoded_text, min_similarity=0.55, min_len=4):
    """
    Find known strings similar to decoded text using character-level alignment.
    Handles both direct alignment and suffix alignment.
    Returns list of (known_string, similarity, alignment_type) sorted by similarity.
    """
    clean = decoded_text.rstrip('\x00').rstrip('+')
    if len(clean) < min_len:
        return []

    results = []
    clean_upper = clean.upper()

    for known in KNOWN_CONTEXT_STRINGS:
        known_upper = known.upper()

        # Direct alignment (same start position)
        sim = char_similarity(clean_upper, known_upper)
        if sim >= min_similarity:
            results.append({
                'known': known,
                'similarity': sim,
                'alignment': 'direct',
            })

        # Suffix alignment (decoded is suffix of known)
        if len(clean) < len(known):
            offset = len(known) - len(clean)
            suffix = known_upper[offset:]
            sim = char_similarity(clean_upper, suffix)
            if sim >= min_similarity:
                prefix = known[:offset]
                results.append({
                    'known': known,
                    'similarity': sim,
                    'alignment': 'suffix',
                    'missing_prefix': prefix,
                })

        # Prefix alignment (decoded starts at beginning of known)
        if len(clean) <= len(known):
            prefix = known_upper[:len(clean)]
            sim = char_similarity(clean_upper, prefix)
            if sim >= min_similarity and sim > 0.0:
                results.append({
                    'known': known,
                    'similarity': sim,
                    'alignment': 'prefix',
                })

    # Deduplicate: keep best alignment per known string
    best = {}
    for r in results:
        k = r['known']
        if k not in best or r['similarity'] > best[k]['similarity']:
            best[k] = r

    return sorted(best.values(), key=lambda x: -x['similarity'])


def score_decode(decoded_bytes, method_name=""):
    """
    Score a decoded byte sequence. Higher = more likely correct.
    Returns (score, decoded_text).
    """
    if not decoded_bytes:
        return 0.0, ""

    pr = printable_ratio(decoded_bytes)
    lr = ascii_letter_ratio(decoded_bytes)

    # Try to interpret as text
    try:
        text = decoded_bytes.decode('ascii', errors='replace')
    except Exception:
        text = ""

    score = pr * 0.5 + lr * 0.3

    # Bonus for path-like characters
    if has_path_chars(text):
        score += 0.1

    # Bonus for known substrings
    text_upper = text.upper()
    for known in KNOWN_CONTEXT_STRINGS:
        if known.upper() in text_upper or text_upper in known.upper():
            score += 0.3
            break

    # Penalty for control characters
    ctrl_count = sum(1 for b in decoded_bytes if b < 0x20 and b != 0x00)
    if decoded_bytes:
        score -= (ctrl_count / len(decoded_bytes)) * 0.3

    return min(score, 1.0), text


def decode_separator_entry(raw_bytes, sep_pos, sep_val):
    """
    Decode a separator-encoded entry.
    Tries:
      1. Classic methods: SUB(d-s), XOR(d^s), SUB(s-d), SUB(d-s)+upper
      2. Generalized formula: plaintext = (d - add) ^ (sep - add) for add in [0..255]
      3. Similarity matching against known strings
    Returns (best_method, best_score, best_text, all_results).
    """
    if sep_pos == 'odd':
        data_bytes = bytes([raw_bytes[i] for i in range(0, len(raw_bytes), 2)])
    else:
        data_bytes = bytes([raw_bytes[i] for i in range(1, len(raw_bytes), 2)])

    all_results = {}

    # --- Classic methods ---
    methods = {
        'SUB(d-s)': bytes([(b - sep_val) & 0xFF for b in data_bytes]),
        'XOR': bytes([b ^ sep_val for b in data_bytes]),
        'SUB(s-d)': bytes([(sep_val - b) & 0xFF for b in data_bytes]),
    }

    # SUB(d-s) with bit5 clear (uppercase normalization for case-flipped residuals)
    sub_result = methods['SUB(d-s)']
    upper_norm = bytes([b & 0xDF if 0x60 <= b <= 0x7f else b for b in sub_result])
    if upper_norm != sub_result:
        methods['SUB(d-s)+upper'] = upper_norm

    # SUB(s-d) with bit5 clear
    sub_inv = methods['SUB(s-d)']
    upper_inv = bytes([b & 0xDF if 0x60 <= b <= 0x7f else b for b in sub_inv])
    if upper_inv != sub_inv:
        methods['SUB(s-d)+upper'] = upper_inv

    for method, decoded in methods.items():
        decoded_strip = decoded.rstrip(b'\x00')
        sc, text = score_decode(decoded_strip, method)
        all_results[method] = {'score': sc, 'text': text, 'raw': decoded_strip}

    # --- Generalized formula: plaintext = (d - add) ^ (sep - add) ---
    # add=0 → XOR, add=sep → SUB(d-s), already covered above.
    # Try remaining add values that might produce better results.
    gen_best_score = -1
    gen_best_add = 0
    gen_best_decoded = b''
    for add_val in range(256):
        if add_val == 0 or add_val == sep_val:
            continue  # Already covered by XOR and SUB
        delta = (sep_val - add_val) & 0xFF
        decoded = bytes([((b - add_val) & 0xFF) ^ delta for b in data_bytes])
        decoded_strip = decoded.rstrip(b'\x00')
        sc, text = score_decode(decoded_strip)
        if sc > gen_best_score:
            gen_best_score = sc
            gen_best_add = add_val
            gen_best_decoded = decoded_strip

    if gen_best_score > 0.3:
        method_name = f'GEN(add=0x{gen_best_add:02x})'
        try:
            gen_text = gen_best_decoded.decode('ascii', errors='replace')
        except Exception:
            gen_text = ""
        all_results[method_name] = {
            'score': gen_best_score, 'text': gen_text, 'raw': gen_best_decoded
        }

    # --- Find best method ---
    best_method = None
    best_score = -1
    best_text = ""

    for method, info in all_results.items():
        if info['score'] > best_score:
            best_score = info['score']
            best_method = method
            best_text = info['text']

    # --- Similarity matching boost ---
    # Check if any decoded result is similar to a known string.
    # Only boost if the base decode is already decent (score >= 0.4).
    # Cap the boosted score at 0.85 to avoid false confidence.
    for method, info in all_results.items():
        if info['score'] < 0.4:
            continue
        sim_matches = try_similarity_match(info['text'])
        if sim_matches:
            best_sim = sim_matches[0]
            boosted = info['score'] + best_sim['similarity'] * 0.2
            if boosted > best_score:
                best_score = min(boosted, 0.85)
                best_method = method
                best_text = info['text']
                info['similarity_match'] = best_sim

    return best_method, best_score, best_text, all_results


def decode_multi_separator_entry(raw_bytes, segments):
    """
    Decode an entry with multiple separator segments.
    Each segment may use a different separator and method.
    Uses weighted scoring: well-decoded sections count more.
    Also checks combined result against known strings for context boost.
    """
    parts = []
    for seg_start, seg_end, sep_val in segments:
        seg_data = raw_bytes[seg_start:seg_end]
        if len(seg_data) < 4:
            continue
        method, score, text, results = decode_separator_entry(seg_data, 'odd', sep_val)
        parts.append({
            'offset': seg_start,
            'sep': sep_val,
            'method': method,
            'score': score,
            'text': text,
            'length': len(text),
        })

    if not parts:
        return None

    combined_text = ''.join(p['text'] for p in parts)

    # Weighted average: longer and better-scoring sections count more
    total_weight = sum(max(p['length'], 1) for p in parts)
    weighted_score = sum(p['score'] * max(p['length'], 1) for p in parts) / max(total_weight, 1)

    # Context matching on combined text
    sim_matches = try_similarity_match(combined_text)
    if sim_matches:
        best_sim = sim_matches[0]
        boosted = weighted_score + best_sim['similarity'] * 0.3
        weighted_score = min(boosted, 1.0)

    # Also check: if the best section alone matches a known string prefix,
    # we can infer the full string with high confidence
    best_part = max(parts, key=lambda p: p['score'])
    if best_part['score'] >= 0.5:
        ctx = try_context_match(best_part['text'])
        if ctx:
            best_ctx = ctx[0]
            if best_ctx['confidence'] >= 0.6:
                return {
                    'combined_text': best_ctx['known'],
                    'avg_score': max(weighted_score, best_ctx['confidence']),
                    'parts': parts,
                    'context_inferred': best_ctx['known'],
                }

    return {
        'combined_text': combined_text,
        'avg_score': weighted_score,
        'parts': parts,
    }


def try_context_match(partial_text, prefix_len=0):
    """
    Try to match partial text against known strings to infer the full string.
    prefix_len: number of missing prefix characters.
    Uses both exact substring matching and similarity-based matching.
    Requires decoded text to be at least MIN_CONTEXT_MATCH_LEN chars.
    """
    matches = []
    partial_clean = partial_text.rstrip('\x00').rstrip('+')
    partial_upper = partial_clean.upper()

    # Don't match very short strings unless we have a specific prefix_len
    if len(partial_clean) < MIN_CONTEXT_MATCH_LEN and prefix_len == 0:
        return []

    for known in KNOWN_CONTEXT_STRINGS:
        known_upper = known.upper()

        # Exact match
        if partial_upper == known_upper:
            matches.append({
                'known': known,
                'missing_prefix': '',
                'confidence': 1.0,
            })
            continue

        # Check if partial text is a suffix of a known string
        if len(partial_clean) >= MIN_CONTEXT_MATCH_LEN and known_upper.endswith(partial_upper):
            missing = known[:len(known) - len(partial_clean)]
            if prefix_len == 0 or len(missing) == prefix_len:
                coverage = len(partial_clean) / len(known)
                conf = 0.6 + 0.3 * coverage
                if len(missing) == prefix_len and prefix_len > 0:
                    conf = min(conf + 0.1, 0.95)
                matches.append({
                    'known': known,
                    'missing_prefix': missing,
                    'confidence': conf,
                })

        # Check if partial text is contained in a known string
        elif len(partial_clean) >= MIN_CONTEXT_MATCH_LEN and partial_upper in known_upper:
            idx = known_upper.index(partial_upper)
            missing = known[:idx]
            suffix = known[idx + len(partial_clean):]
            if prefix_len == 0 or len(missing) == prefix_len:
                coverage = len(partial_clean) / len(known)
                conf = 0.5 + 0.3 * coverage
                if len(missing) == prefix_len and prefix_len > 0:
                    conf = min(conf + 0.1, 0.90)
                matches.append({
                    'known': known,
                    'missing_prefix': missing,
                    'missing_suffix': suffix,
                    'confidence': conf,
                })

    # Similarity-based matching for near-miss decodes
    if len(partial_clean) >= MIN_CONTEXT_MATCH_LEN:
        sim_results = try_similarity_match(partial_clean, min_similarity=0.60)
        for sim in sim_results:
            # Don't duplicate exact matches already found
            if any(m['known'] == sim['known'] for m in matches):
                continue
            missing = sim.get('missing_prefix', '')
            # If prefix_len is specified, only accept matches where
            # the missing prefix length is compatible
            if prefix_len > 0 and missing and len(missing) != prefix_len:
                continue
            conf = 0.4 + 0.4 * sim['similarity']
            entry = {
                'known': sim['known'],
                'missing_prefix': missing,
                'confidence': min(conf, 0.90),
                'similarity_based': True,
                'similarity': sim['similarity'],
            }
            matches.append(entry)

    return sorted(matches, key=lambda m: -m['confidence'])


# ===========================================================================
# Entry Processors
# ===========================================================================

def detect_separator_with_offset(raw_bytes, min_sep_len=8):
    """
    Detect separator pattern that starts after an encrypted prefix.
    Scans from the beginning to find where the separator pattern starts.
    Returns (offset, sep_pos, sep_val, sep_confidence) or None.
    """
    # Try offsets from 2 up to 20 bytes (1-10 encrypted prefix bytes)
    for offset in range(2, min(len(raw_bytes) - min_sep_len, 22), 2):
        remaining = raw_bytes[offset:]
        if len(remaining) < min_sep_len:
            break
        sep_info = detect_separator_pattern(remaining, min_len=min_sep_len, threshold=0.85)
        if sep_info:
            return (offset, sep_info[0], sep_info[1], sep_info[2])
    return None


def process_string_entry(entry):
    """
    Process a single entry from decrypted_strings.json.
    Returns decoded info or None if no Layer 2 pattern detected.
    """
    raw_hex = entry.get('raw_hex', '')
    if not raw_hex:
        return None

    try:
        raw_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    if len(raw_bytes) < 4:
        return None

    result = {
        'address': entry['address'],
        'original_string': entry.get('string', ''),
        'pattern': None,
        'decoded': None,
        'confidence': 0.0,
        'method': None,
        'notes': '',
    }

    # Check Pattern 2 (Separator) first - most common in strings JSON
    sep_info = detect_separator_pattern(raw_bytes)
    if sep_info:
        sep_pos, sep_val, sep_confidence = sep_info
        method, score, text, all_results = decode_separator_entry(
            raw_bytes, sep_pos, sep_val
        )

        if score >= 0.3:
            result['pattern'] = 'separator'
            result['decoded'] = text.rstrip('\x00')
            result['confidence'] = score
            result['method'] = f'{method} (sep=0x{sep_val:02x})'
            result['separator'] = sep_val
            result['all_methods'] = {
                k: {'score': v['score'], 'text': v['text']}
                for k, v in all_results.items()
                if not k.startswith('GEN(')  # Don't store all 256 GEN results
            }

            # Try context matching
            ctx = try_context_match(text)
            if ctx:
                result['context_match'] = ctx[0]['known']
                result['confidence'] = max(result['confidence'], ctx[0]['confidence'])
                if ctx[0].get('similarity_based'):
                    result['notes'] += f'Similarity match ({ctx[0]["similarity"]:.2f}). '

            # Also check for multi-separator
            multi = detect_multi_separator(raw_bytes)
            if multi:
                multi_result = decode_multi_separator_entry(raw_bytes, multi)
                if multi_result and multi_result['avg_score'] > score:
                    result['decoded'] = multi_result['combined_text'].rstrip('\x00')
                    result['confidence'] = multi_result['avg_score']
                    result['method'] = 'multi-separator'
                    result['multi_parts'] = multi_result['parts']
                    if 'context_inferred' in multi_result:
                        result['context_match'] = multi_result['context_inferred']

            return result

    # Check for multi-separator even without single separator detection
    multi = detect_multi_separator(raw_bytes)
    if multi:
        multi_result = decode_multi_separator_entry(raw_bytes, multi)
        if multi_result and multi_result['avg_score'] >= 0.3:
            result['pattern'] = 'multi-separator'
            result['decoded'] = multi_result['combined_text'].rstrip('\x00')
            result['confidence'] = multi_result['avg_score']
            result['method'] = 'multi-separator'
            result['multi_parts'] = multi_result['parts']
            if 'context_inferred' in multi_result:
                result['context_match'] = multi_result['context_inferred']
            return result

    # Check for prefix + separator pattern (encrypted prefix before separator body)
    offset_info = detect_separator_with_offset(raw_bytes)
    if offset_info:
        offset, sep_pos, sep_val, sep_conf = offset_info
        body = raw_bytes[offset:]
        method, score, text, all_results = decode_separator_entry(
            body, sep_pos, sep_val
        )
        if score >= 0.3:
            prefix_bytes = raw_bytes[:offset]
            result['pattern'] = 'prefix_separator'
            result['decoded'] = text.rstrip('\x00')
            result['confidence'] = score
            result['method'] = f'{method} (sep=0x{sep_val:02x}, prefix={offset}B)'
            result['separator'] = sep_val
            result['prefix_len'] = offset
            result['notes'] = f'{offset}-byte encrypted prefix before separator body. '

            # Context matching with prefix awareness
            ctx = try_context_match(text, prefix_len=offset // 2)
            if ctx:
                result['context_match'] = ctx[0]['known']
                result['confidence'] = max(result['confidence'], ctx[0]['confidence'])
            return result

    return None


def process_binary_entry(entry):
    """
    Process a single entry from decrypted_binary.json.
    Returns decoded info or None.
    """
    raw_hex = entry.get('hex', '')
    if not raw_hex:
        return None

    try:
        raw_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    if len(raw_bytes) < 4:
        return None

    result = {
        'address': entry['address'],
        'original_size': entry.get('size', len(raw_bytes)),
        'pattern': None,
        'decoded': None,
        'confidence': 0.0,
        'method': None,
        'notes': '',
    }

    # Check for plain UTF-16LE first (no encryption, just misclassified as binary)
    if len(raw_bytes) % 2 == 0:
        plain_text = detect_plain_utf16le(raw_bytes)
        if plain_text:
            result['pattern'] = 'plain_utf16le'
            result['decoded'] = plain_text
            result['confidence'] = 0.95
            result['method'] = 'Plain UTF-16LE (was misclassified as binary)'
            result['notes'] = 'Entry is already decoded - just needs UTF-16LE interpretation'
            return result

    # Check Pattern 1 (Prefix + UTF-16LE) - most common in binary JSON
    utf16_info = detect_utf16le_prefix(raw_bytes)
    if utf16_info:
        body_text = utf16_info['body_text']
        n_prefix = utf16_info['prefix_wchars']
        n_embedded = utf16_info.get('embedded_encrypted', 0)

        result['pattern'] = 'prefix_utf16le'
        result['decoded'] = body_text
        result['prefix_wchars'] = n_prefix
        result['confidence'] = 0.7
        if n_embedded > 0:
            result['method'] = f'UTF-16LE body (prefix={n_prefix} wchars, {n_embedded} embedded enc)'
        else:
            result['method'] = f'UTF-16LE body (prefix={n_prefix} wchars)'
        result['hi_bytes'] = [f'0x{b:02x}' for b in utf16_info['hi_bytes']]

        # Try context matching to infer the prefix
        ctx = try_context_match(body_text, prefix_len=n_prefix)
        if ctx:
            best = ctx[0]
            missing = best.get('missing_prefix', '')
            # Accept if: exact match (no missing prefix), OR prefix length matches
            if len(missing) == 0 or len(missing) == n_prefix:
                result['inferred_full'] = best['known']
                result['inferred_prefix'] = missing
                result['confidence'] = max(result['confidence'], best['confidence'])
                result['decoded'] = best['known']
            elif best.get('similarity_based') and best.get('similarity', 0) >= 0.8:
                # High similarity but prefix mismatch - note it but keep body text
                result['inferred_full'] = best['known']
                result['confidence'] = max(result['confidence'], best['confidence'] * 0.8)
                result['notes'] += f'Possible match: {best["known"]} (prefix mismatch). '

        # Check if prefix has repeated bytes (Pattern 3 overlap)
        prefix_bytes = utf16_info['prefix_bytes']
        if prefix_bytes:
            rep_info = detect_repeated_prefix(prefix_bytes)
            if rep_info:
                result['notes'] += f'Prefix has repeated byte 0x{rep_info["prefix_byte"]:02x}. '

        return result

    # Check Pattern 2 (Separator)
    sep_info = detect_separator_pattern(raw_bytes)
    if sep_info:
        sep_pos, sep_val, sep_confidence = sep_info
        method, score, text, all_results = decode_separator_entry(
            raw_bytes, sep_pos, sep_val
        )

        if score >= 0.2:
            result['pattern'] = 'separator'
            result['decoded'] = text.rstrip('\x00')
            result['confidence'] = score
            result['method'] = f'{method} (sep=0x{sep_val:02x})'
            result['separator'] = sep_val

            ctx = try_context_match(text)
            if ctx:
                result['context_match'] = ctx[0]['known']
                result['confidence'] = max(result['confidence'], ctx[0]['confidence'])
                if ctx[0].get('similarity_based'):
                    result['notes'] += f'Similarity match ({ctx[0]["similarity"]:.2f}). '

            return result

    # Check Pattern 3 (Repeated prefix)
    rep_info = detect_repeated_prefix(raw_bytes)
    if rep_info:
        body = rep_info['body']
        # Try UTF-16LE decode of body
        if len(body) >= 2 and len(body) % 2 == 0:
            try:
                body_text = body.decode('utf-16-le').rstrip('\x00')
                if body_text and printable_ratio(body_text.encode('ascii', errors='replace')) > 0.6:
                    result['pattern'] = 'repeated_prefix'
                    result['decoded'] = body_text
                    result['confidence'] = 0.6
                    result['method'] = f'Strip prefix 0x{rep_info["prefix_byte"]:02x}x{rep_info["prefix_len"]}'
                    result['prefix_byte'] = f'0x{rep_info["prefix_byte"]:02x}'
                    result['prefix_len'] = rep_info['prefix_len']

                    ctx = try_context_match(body_text)
                    if ctx:
                        result['inferred_full'] = ctx[0]['known']
                        result['confidence'] = max(result['confidence'], ctx[0]['confidence'])

                    return result
            except (UnicodeDecodeError, ValueError):
                pass

        # Try ASCII decode
        try:
            body_text = body.decode('ascii', errors='replace').rstrip('\x00')
            if printable_ratio(body.rstrip(b'\x00')) > 0.7:
                result['pattern'] = 'repeated_prefix'
                result['decoded'] = body_text
                result['confidence'] = 0.5
                result['method'] = f'Strip prefix 0x{rep_info["prefix_byte"]:02x}x{rep_info["prefix_len"]}'
                return result
        except Exception:
            pass

    # Pattern 4: Fully encoded
    result['pattern'] = 'fully_encoded'
    result['confidence'] = 0.0
    result['notes'] = 'Cannot decode statically - requires runtime key schedule'
    return result


# ===========================================================================
# Main Processing
# ===========================================================================

def load_json(filepath):
    """Load a JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def process_all(input_dir, output_dir):
    """
    Process both JSON files and output Layer 2 decoded results.
    """
    strings_path = os.path.join(input_dir, 'decrypted_strings.json')
    binary_path = os.path.join(input_dir, 'decrypted_binary.json')

    strings_data = load_json(strings_path)
    binary_data = load_json(binary_path)

    # ===== Process string entries =====
    string_results = []
    improved_strings = []
    unchanged_strings = []

    for entry in strings_data['entries']:
        decoded = process_string_entry(entry)
        if decoded and decoded['confidence'] >= 0.3:
            string_results.append(decoded)
            # Create improved entry
            improved = dict(entry)
            improved['layer2_decoded'] = decoded['decoded']
            improved['layer2_pattern'] = decoded['pattern']
            improved['layer2_method'] = decoded['method']
            improved['layer2_confidence'] = round(decoded['confidence'], 3)
            if 'context_match' in decoded:
                improved['layer2_context_match'] = decoded['context_match']
            improved_strings.append(improved)
        else:
            unchanged_strings.append(entry)

    # ===== Process binary entries =====
    binary_results = []
    improved_binaries = []
    unchanged_binaries = []

    for entry in binary_data['entries']:
        decoded = process_binary_entry(entry)
        if decoded and decoded['pattern'] != 'fully_encoded':
            binary_results.append(decoded)
            improved = dict(entry)
            improved['layer2_decoded'] = decoded['decoded']
            improved['layer2_pattern'] = decoded['pattern']
            improved['layer2_method'] = decoded['method']
            improved['layer2_confidence'] = round(decoded['confidence'], 3)
            if 'inferred_full' in decoded:
                improved['layer2_inferred_full'] = decoded['inferred_full']
            if 'prefix_wchars' in decoded:
                improved['layer2_prefix_wchars'] = decoded['prefix_wchars']
            if decoded.get('hi_bytes'):
                improved['layer2_hi_bytes'] = decoded['hi_bytes']
            if decoded.get('notes'):
                improved['layer2_notes'] = decoded['notes']
            improved_binaries.append(improved)
        else:
            if decoded:
                decoded_info = dict(entry)
                decoded_info['layer2_pattern'] = decoded['pattern']
                decoded_info['layer2_notes'] = decoded.get('notes', '')
                unchanged_binaries.append(decoded_info)
            else:
                unchanged_binaries.append(entry)

    # ===== Combine all decoded results =====
    all_decoded = {
        'summary': {
            'total_string_entries': len(strings_data['entries']),
            'total_binary_entries': len(binary_data['entries']),
            'layer2_decoded_strings': len(string_results),
            'layer2_decoded_binaries': len(binary_results),
            'layer2_undecoded_binaries': len(unchanged_binaries),
        },
        'decoded_strings': improved_strings,
        'decoded_binaries': improved_binaries,
        'undecoded_binaries': unchanged_binaries,
    }

    # ===== Merge into unified output =====
    # Create final merged strings: original unchanged + layer2 improved
    final_strings = []
    decoded_addresses = {e['address'] for e in improved_strings}

    for entry in strings_data['entries']:
        if entry['address'] in decoded_addresses:
            # Find the improved version
            for imp in improved_strings:
                if imp['address'] == entry['address']:
                    final_entry = dict(imp)
                    # Update the main string field with decoded value
                    final_entry['string'] = imp['layer2_decoded']
                    final_entry['original_layer1_string'] = entry['string']
                    final_strings.append(final_entry)
                    break
        else:
            final_strings.append(entry)

    final_binaries = []
    decoded_bin_addresses = {e['address'] for e in improved_binaries}

    for entry in binary_data['entries']:
        if entry['address'] in decoded_bin_addresses:
            for imp in improved_binaries:
                if imp['address'] == entry['address']:
                    final_entry = dict(imp)
                    if 'layer2_decoded' in final_entry and final_entry['layer2_decoded']:
                        final_entry['decoded_string'] = final_entry['layer2_decoded']
                    final_binaries.append(final_entry)
                    break
        else:
            final_binaries.append(entry)

    # ===== Write outputs =====
    # Detailed layer2 results
    layer2_path = os.path.join(output_dir, 'layer2_decoded.json')
    with open(layer2_path, 'w', encoding='utf-8') as f:
        json.dump(all_decoded, f, indent=2, ensure_ascii=False)

    # Updated merged strings JSON
    merged_strings_path = os.path.join(output_dir, 'decrypted_strings_v2.json')
    merged_strings = {
        'count': len(final_strings),
        'layer2_improved_count': len(improved_strings),
        'entries': final_strings,
    }
    with open(merged_strings_path, 'w', encoding='utf-8') as f:
        json.dump(merged_strings, f, indent=2, ensure_ascii=False)

    # Updated merged binary JSON
    merged_binary_path = os.path.join(output_dir, 'decrypted_binary_v2.json')
    merged_binary = {
        'count': len(final_binaries),
        'layer2_improved_count': len(improved_binaries),
        'entries': final_binaries,
    }
    with open(merged_binary_path, 'w', encoding='utf-8') as f:
        json.dump(merged_binary, f, indent=2, ensure_ascii=False)

    return all_decoded, string_results, binary_results


# ===========================================================================
# Report Generation
# ===========================================================================

def generate_report(all_decoded, string_results, binary_results, output_dir):
    """Generate a human-readable summary report."""
    lines = []
    lines.append("=" * 78)
    lines.append("Lumma Stealer Layer 2 Decoding Report")
    lines.append("=" * 78)
    lines.append("")

    summary = all_decoded['summary']
    lines.append("## Summary")
    lines.append(f"  String entries (total):        {summary['total_string_entries']}")
    lines.append(f"  String entries (L2 decoded):    {summary['layer2_decoded_strings']}")
    lines.append(f"  Binary entries (total):         {summary['total_binary_entries']}")
    lines.append(f"  Binary entries (L2 decoded):    {summary['layer2_decoded_binaries']}")
    lines.append(f"  Binary entries (undecoded):     {summary['layer2_undecoded_binaries']}")
    lines.append("")

    # --- Decoded strings from separator pattern ---
    lines.append("=" * 78)
    lines.append("## Pattern 2: Separator-Decoded Strings (from decrypted_strings.json)")
    lines.append("=" * 78)
    lines.append("")

    sep_strings = [r for r in string_results if r.get('pattern') in ('separator', 'multi-separator')]
    sep_strings.sort(key=lambda x: x['confidence'], reverse=True)

    # Split into high-confidence and low-confidence
    high_conf = [r for r in sep_strings if r['confidence'] >= 0.6]
    low_conf = [r for r in sep_strings if r['confidence'] < 0.6]

    if high_conf:
        lines.append(f"{'Address':<14} {'Sep':>5} {'Method':<22} {'Conf':>5} {'Decoded String'}")
        lines.append("-" * 78)
        for r in high_conf:
            sep_str = f"0x{r.get('separator', 0):02x}" if 'separator' in r else "multi"
            decoded = r.get('decoded', '')[:45]
            ctx = r.get('context_match', '')
            line = f"{r['address']:<14} {sep_str:>5} {r['method']:<22} {r['confidence']:>5.2f} {decoded}"
            lines.append(line)
            if ctx and ctx != decoded:
                lines.append(f"{'':>50} -> {ctx[:40]}")
    else:
        lines.append("  (none found)")

    if low_conf:
        lines.append("")
        lines.append(f"### Low Confidence ({len(low_conf)} entries, conf < 0.60)")
        lines.append("  (These may need IDA runtime analysis for verification)")
        for r in low_conf:
            sep_str = f"0x{r.get('separator', 0):02x}" if 'separator' in r else "multi"
            decoded = r.get('decoded', '')[:40]
            lines.append(f"  {r['address']} sep={sep_str} conf={r['confidence']:.2f} -> {decoded}")

    lines.append("")

    # --- Decoded binary entries ---
    lines.append("=" * 78)
    lines.append("## Pattern 1/3: Decoded Binary Entries (from decrypted_binary.json)")
    lines.append("=" * 78)
    lines.append("")

    bin_decoded = [r for r in binary_results if r.get('pattern') != 'fully_encoded']
    bin_decoded.sort(key=lambda x: x['confidence'], reverse=True)

    if bin_decoded:
        for r in bin_decoded:
            lines.append(f"  Address: {r['address']}")
            lines.append(f"  Pattern: {r['pattern']}")
            lines.append(f"  Method:  {r['method']}")
            lines.append(f"  Conf:    {r['confidence']:.2f}")
            decoded = r.get('decoded', '')
            if len(decoded) > 60:
                decoded = decoded[:57] + "..."
            lines.append(f"  Decoded: {decoded}")
            if r.get('inferred_full'):
                full = r['inferred_full']
                if len(full) > 60:
                    full = full[:57] + "..."
                lines.append(f"  Full:    {full}")
            if r.get('prefix_wchars'):
                lines.append(f"  Prefix:  {r['prefix_wchars']} encrypted wchars")
            if r.get('notes'):
                lines.append(f"  Notes:   {r['notes']}")
            lines.append("")
    else:
        lines.append("  (none found)")

    lines.append("")

    # --- Undecoded entries ---
    lines.append("=" * 78)
    lines.append("## Pattern 4: Undecoded Binary Entries (requires runtime analysis)")
    lines.append("=" * 78)
    lines.append("")

    undecoded = all_decoded.get('undecoded_binaries', [])
    for u in undecoded:
        addr = u.get('address', '?')
        size = u.get('size', '?')
        pattern = u.get('layer2_pattern', 'unknown')
        notes = u.get('layer2_notes', '')
        lines.append(f"  {addr}: {size} bytes, pattern={pattern}")
        if notes:
            lines.append(f"    Notes: {notes}")

    lines.append("")
    lines.append("=" * 78)
    lines.append("## All Decoded Strings (combined Layer 1 + Layer 2)")
    lines.append("=" * 78)
    lines.append("")

    # Combine and list all meaningful decoded strings
    all_strings = []

    # From improved strings - only high confidence
    for r in string_results:
        if r.get('confidence', 0) >= 0.5:
            text = r.get('context_match', r.get('decoded', ''))
            if text and len(text) >= 3:
                all_strings.append((r['address'], text, 'L2-separator',
                                    r.get('confidence', 0)))

    # From improved binaries
    for r in binary_results:
        if r.get('pattern') != 'fully_encoded':
            text = r.get('inferred_full', r.get('decoded', ''))
            if text:
                all_strings.append((r['address'], text, f'L2-{r["pattern"]}',
                                    r.get('confidence', 0)))

    all_strings.sort(key=lambda x: -x[3])  # Sort by confidence
    for addr, text, src, conf in all_strings:
        if len(text) > 60:
            text = text[:57] + "..."
        lines.append(f"  {addr} [{src:<18}] ({conf:.2f}) {text}")

    lines.append("")
    lines.append("=" * 78)
    lines.append("End of Report")
    lines.append("=" * 78)

    report_text = '\n'.join(lines)
    report_path = os.path.join(output_dir, 'layer2_report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_text)

    return report_text


# ===========================================================================
# CLI
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Lumma Stealer Layer 2 Decoder'
    )
    parser.add_argument(
        '--input-dir', '-i',
        default='.',
        help='Directory containing decrypted_strings.json and decrypted_binary.json'
    )
    parser.add_argument(
        '--output-dir', '-o',
        default=None,
        help='Output directory (default: same as input)'
    )
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    output_dir = os.path.abspath(args.output_dir) if args.output_dir else input_dir

    # Verify input files exist
    strings_path = os.path.join(input_dir, 'decrypted_strings.json')
    binary_path = os.path.join(input_dir, 'decrypted_binary.json')

    if not os.path.exists(strings_path):
        print(f"Error: {strings_path} not found")
        sys.exit(1)
    if not os.path.exists(binary_path):
        print(f"Error: {binary_path} not found")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Input:  {input_dir}")
    print(f"[*] Output: {output_dir}")
    print()

    # Process
    all_decoded, string_results, binary_results = process_all(input_dir, output_dir)

    # Generate report
    report = generate_report(all_decoded, string_results, binary_results, output_dir)
    print(report)

    # Summary
    print()
    print(f"[+] Files written:")
    print(f"    layer2_decoded.json         - Detailed Layer 2 decoding results")
    print(f"    decrypted_strings_v2.json   - Merged strings (L1 + L2)")
    print(f"    decrypted_binary_v2.json    - Merged binary (L1 + L2)")
    print(f"    layer2_report.txt           - Human-readable report")


if __name__ == '__main__':
    main()
