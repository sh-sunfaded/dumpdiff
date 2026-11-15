"""複数時点のメモリダンプイメージの読み込みと指紋。"""
from __future__ import annotations

import hashlib
import re

from .entropy import shannon_entropy

# 採取ツールがダンプ先頭に付けるテキストヘッダ
# (例: "REGION image addr=0x140000000 size=688128" + 改行)。
_HEADER_RE = re.compile(rb"^REGION [^\r\n]*\r?\n")


def strip_header(data: bytes) -> bytes:
    """採取ツール独自のテキストヘッダを除去する。無ければそのまま返す。"""
    m = _HEADER_RE.match(data)
    return data[m.end():] if m else data


def load_image(path: str) -> bytes:
    """ダンプイメージを読み込む。

    RVA==ファイルオフセット形式を想定。先頭テキストヘッダは自動除去。
    """
    with open(path, "rb") as fh:
        return strip_header(fh.read())


def fingerprint(data: bytes) -> dict:
    """イメージの指紋(サイズ・ハッシュ・全体エントロピー)。"""
    return {
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon_entropy(data), 4),
    }
