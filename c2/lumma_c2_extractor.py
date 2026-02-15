#!/usr/bin/env python3
"""
LummaStealer C2 URL Extractor
=============================
PE バイナリから ChaCha20 暗号化コンフィグブロブを検出・復号し、
C2 URL を JSON 形式で出力する。

対象: LummaStealer (CAPE RULE_SOURCE_LUMMA 互換)

コンフィグブロブ構造 (1344 bytes):
  +0x00  16B   YARA prefix (固定マーカー)
  +0x10  32B   ChaCha20 鍵
  +0x30   8B   Nonce source → 0x00000000 + 8B = 12B IETF nonce
  +0x38  1288B 暗号文 (IETF ChaCha20, counter=0)

復号平文構造 (1288 bytes):
  Block 0  (0x000-0x07F): メタデータ (128B, バイナリ)
  Block 1-9(0x080-0x4FF): C2 URL (各128B, null-terminated ASCII)
  Trailer  (0x500-0x507): 8B (チェックサム/パディング)

使用法:
  python lumma_c2_extractor.py <PE_FILE> [--raw-offset OFFSET]
  python lumma_c2_extractor.py <PE_FILE> --yara-prefix HEXSTRING
"""

import argparse
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    sys.exit("Error: 'cryptography' パッケージが必要です: pip install cryptography")


# CAPE RULE_SOURCE_LUMMA で使われる既知の YARA prefix パターン
KNOWN_YARA_PREFIXES = [
    bytes.fromhex("321d30f94877825a3cbf737fdd4f1575"),
]

BLOB_SIZE = 1344        # YARA prefix + key + nonce + ciphertext
KEY_OFFSET = 0x10       # prefix からの相対オフセット
KEY_SIZE = 32
NONCE_OFFSET = 0x30
NONCE_SIZE = 8          # 4-byte zero prefix 付加で 12-byte IETF nonce
CT_OFFSET = 0x38
CT_SIZE = 1288
BLOCK_SIZE = 128
C2_BLOCK_START = 1      # Block 0 はメタデータ
C2_BLOCK_COUNT = 9


def find_config_blob(data: bytes, yara_prefix: bytes | None = None) -> int:
    """PE データ中からコンフィグブロブの先頭オフセットを検索する。

    検索順序:
      1. 指定された yara_prefix
      2. 既知の YARA prefix リスト
      3. ヒューリスティック: 16B marker + 32B key の後に
         復号可能な ASCII URL が続くパターン
    """
    prefixes = [yara_prefix] if yara_prefix else KNOWN_YARA_PREFIXES

    for prefix in prefixes:
        offset = 0
        while True:
            pos = data.find(prefix, offset)
            if pos == -1:
                break
            # 十分なデータが残っているか確認
            if pos + BLOB_SIZE <= len(data):
                return pos
            offset = pos + 1

    return -1


def decrypt_chacha20(key: bytes, nonce_src: bytes, ciphertext: bytes) -> bytes:
    """IETF ChaCha20 (RFC 8439) で復号する。

    nonce_src (8B) に 4-byte zero prefix を付加して 12-byte IETF nonce を構築。
    cryptography ライブラリは 16B = counter(4B LE) + nonce(12B) を要求するため、
    counter=0 を先頭に付加する。
    """
    # 12-byte IETF nonce: 4-byte zero prefix + 8-byte nonce source
    ietf_nonce = b"\x00\x00\x00\x00" + nonce_src
    # cryptography lib: 16B = counter(4B, LE, =0) || nonce(12B)
    full_nonce = b"\x00\x00\x00\x00" + ietf_nonce
    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def extract_c2_urls(plaintext: bytes) -> list[str]:
    """復号平文から C2 URL を抽出する。

    各 128B ブロックの null-terminated ASCII 文字列を読み取る。
    """
    urls = []
    for i in range(C2_BLOCK_COUNT):
        block_offset = (C2_BLOCK_START + i) * BLOCK_SIZE
        block = plaintext[block_offset : block_offset + BLOCK_SIZE]
        # null 終端で切り取り
        null_pos = block.find(b"\x00")
        if null_pos > 0:
            try:
                url = block[:null_pos].decode("ascii")
                if url and len(url) > 3:  # 最低限のバリデーション
                    urls.append(url)
            except UnicodeDecodeError:
                continue
    return urls


def extract_metadata(plaintext: bytes) -> dict:
    """Block 0 メタデータの概要を抽出する。"""
    meta_block = plaintext[:BLOCK_SIZE]
    dwords = struct.unpack("<32I", meta_block)
    return {
        "size": BLOCK_SIZE,
        "first_byte": meta_block[0],
        "non_zero_dwords": sum(1 for d in dwords if d != 0),
        "hex": meta_block.hex(),
    }


def extract_trailer(plaintext: bytes) -> str:
    """末尾 8 バイトのトレーラーを16進文字列で返す。"""
    trailer = plaintext[C2_BLOCK_COUNT * BLOCK_SIZE + BLOCK_SIZE :]
    return trailer.hex() if trailer else ""


def process_pe(
    filepath: str,
    raw_offset: int | None = None,
    yara_prefix_hex: str | None = None,
) -> dict:
    """PE ファイルを処理し、C2 情報を辞書で返す。"""
    data = Path(filepath).read_bytes()
    yara_prefix = bytes.fromhex(yara_prefix_hex) if yara_prefix_hex else None

    # コンフィグブロブ検索
    if raw_offset is not None:
        blob_offset = raw_offset
    else:
        blob_offset = find_config_blob(data, yara_prefix)

    if blob_offset == -1:
        return {"error": "コンフィグブロブが見つかりません", "file": filepath}

    if blob_offset + BLOB_SIZE > len(data):
        return {
            "error": f"ブロブサイズ不足 (offset=0x{blob_offset:X}, "
            f"残り={len(data) - blob_offset}B, 必要={BLOB_SIZE}B)",
            "file": filepath,
        }

    blob = data[blob_offset : blob_offset + BLOB_SIZE]

    # フィールド抽出
    prefix = blob[:KEY_OFFSET]
    key = blob[KEY_OFFSET : KEY_OFFSET + KEY_SIZE]
    nonce_src = blob[NONCE_OFFSET : NONCE_OFFSET + NONCE_SIZE]
    ciphertext = blob[CT_OFFSET : CT_OFFSET + CT_SIZE]
    nonce_full = b"\x00\x00\x00\x00" + nonce_src

    # 復号
    plaintext = decrypt_chacha20(key, nonce_src, ciphertext)

    # C2 URL 抽出
    c2_urls = extract_c2_urls(plaintext)

    # 結果構築
    result = {
        "file": filepath,
        "sha256": None,
        "config_offset": {
            "file_offset": f"0x{blob_offset:X}",
            "blob_size": BLOB_SIZE,
        },
        "chacha20": {
            "key": key.hex(),
            "nonce": nonce_full.hex(),
            "nonce_source": nonce_src.hex(),
            "ciphertext_size": CT_SIZE,
        },
        "yara_prefix": prefix.hex(),
        "c2_urls": c2_urls,
        "c2_count": len(c2_urls),
        "metadata_block0": extract_metadata(plaintext),
        "trailer": extract_trailer(plaintext),
    }

    # SHA256 計算
    import hashlib

    result["sha256"] = hashlib.sha256(data).hexdigest()

    return result


def main():
    parser = argparse.ArgumentParser(
        description="LummaStealer C2 URL Extractor — PE から ChaCha20 暗号化コンフィグを復号"
    )
    parser.add_argument("pe_file", help="対象の PE ファイルパス")
    parser.add_argument(
        "--raw-offset",
        type=lambda x: int(x, 0),
        default=None,
        help="コンフィグブロブのファイルオフセット (例: 0x51228)。省略時は自動検索",
    )
    parser.add_argument(
        "--yara-prefix",
        default=None,
        help="検索する YARA prefix の16進文字列 (例: 321d30f9...)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="JSON をコンパクト出力 (C2 URL のみ)",
    )

    args = parser.parse_args()

    if not Path(args.pe_file).exists():
        sys.exit(f"Error: ファイルが見つかりません: {args.pe_file}")

    result = process_pe(args.pe_file, args.raw_offset, args.yara_prefix)

    if "error" in result:
        print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)

    if args.compact:
        output = {
            "sha256": result["sha256"],
            "c2_urls": result["c2_urls"],
        }
    else:
        output = result

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
