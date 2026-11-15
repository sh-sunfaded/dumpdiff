"""画像のエントロピー分析(全体およびページ単位)。"""
from __future__ import annotations

import math
from collections import Counter

DEFAULT_PAGE = 0x1000


def shannon_entropy(data: bytes) -> float:
    """バイト列のシャノンエントロピー(ビット/バイト、0.0〜8.0)。"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def entropy_map(data: bytes, page: int = DEFAULT_PAGE):
    """ページ単位のエントロピー。

    返り値: [(offset, entropy, chunk_size), ...] (最終ページは端数になる)。
    """
    out = []
    for off in range(0, len(data), page):
        chunk = data[off:off + page]
        out.append((off, shannon_entropy(chunk), len(chunk)))
    return out


def high_entropy_ranges(data: bytes, threshold: float = 7.0,
                        page: int = DEFAULT_PAGE):
    """threshold 以上のエントロピーを持つページの連続領域を列挙する。

    暗号化・圧縮領域の候補探しに使う。
    返り値: [(start, end, max_entropy), ...] (end は排他)。
    """
    ranges = []
    cur = None
    for off, ent, size in entropy_map(data, page):
        if ent >= threshold:
            if cur is None:
                cur = [off, off + size, ent]
            else:
                cur[1] = off + size
                if ent > cur[2]:
                    cur[2] = ent
        elif cur is not None:
            ranges.append(tuple(cur))
            cur = None
    if cur is not None:
        ranges.append(tuple(cur))
    return ranges
