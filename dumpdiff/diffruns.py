"""ダンプ間の差分ラン列挙とページ分類。"""
from __future__ import annotations

import hashlib

DEFAULT_PAGE = 0x1000

# ページ分類ラベル:
#   static   全時点一致                    … 静的領域(暗号文も含めて安定)
#   flip     時点1==時点3 かつ時点2が異なる … 一時的にだけ内容が変わる
#                                            (復号→実行→復元の候補)
#   settled  時点1≠時点2==時点3            … 遷移後の状態書込
#   volatile それ以外(全不一致含む)        … 状態書込・ヒープ等
LABELS = ("static", "flip", "settled", "volatile")


def diff_runs(a: bytes, b: bytes, merge_gap: int = 0, min_length: int = 1):
    """a vs b の不一致連続領域(ラン)を列挙する。

    返り値: [{"offset": int, "length": int, "kind": "diff"|"a-only"|"b-only"}]
      kind=diff   両イメージ範囲内で内容が不一致の区間
      kind=a-only / b-only  片方のイメージが尽きた以降の領域
    merge_gap>0 のとき、gap バイト以内の一致区間で隔てられた diff ランを
    1本に併合する(併合後の長さにはスキップされた一致バイトを含む)。
    min_length 未満のランは除外する(併合後に適用)。
    """
    runs: list[dict] = []
    n = min(len(a), len(b))
    off = 0
    while off < n:
        end = min(off + 0x1000, n)
        if a[off:end] != b[off:end]:
            start = None
            for i in range(off, end):
                if a[i] != b[i]:
                    if start is None:
                        start = i
                elif start is not None:
                    runs.append({"offset": start, "length": i - start,
                                 "kind": "diff"})
                    start = None
            if start is not None:
                runs.append({"offset": start, "length": end - start,
                             "kind": "diff"})
        off = end
    if len(a) > len(b):
        runs.append({"offset": n, "length": len(a) - n, "kind": "a-only"})
    elif len(b) > len(a):
        runs.append({"offset": n, "length": len(b) - n, "kind": "b-only"})
    runs = _merge(runs, merge_gap)
    return [r for r in runs if r["length"] >= min_length]


def _merge(runs: list[dict], gap: int) -> list[dict]:
    if gap <= 0:
        return runs
    out: list[dict] = []
    for r in runs:
        if out and r["kind"] == "diff" and out[-1]["kind"] == "diff":
            prev_end = out[-1]["offset"] + out[-1]["length"]
            if r["offset"] - prev_end <= gap:
                out[-1]["length"] = r["offset"] + r["length"] - out[-1]["offset"]
                continue
        out.append(dict(r))
    return out


def _page_hashes(data: bytes, page: int):
    return [hashlib.md5(data[o:o + page]).digest()
            for o in range(0, len(data), page)]


def classify_pages(images, page: int = DEFAULT_PAGE):
    """2〜3イメージのページ単位分類。

    返り値: [(offset, label)] — 全イメージの共通ページ範囲のみ
    (長さが異なるイメージの超出ページは無視)。
    2イメージの場合は static / volatile のみを返す。
    """
    if len(images) < 2:
        raise ValueError("2つ以上のイメージが必要です")
    if len(images) > 3:
        raise ValueError("比較できるのは3イメージまでです(ラベル定義の制約)")
    hashes = [_page_hashes(img, page) for img in images]
    npages = min(len(h) for h in hashes)
    out = []
    for i in range(npages):
        hs = [h[i] for h in hashes]
        if all(x == hs[0] for x in hs):
            label = "static"
        elif len(hs) == 3 and hs[0] == hs[2]:
            label = "flip"
        elif len(hs) == 3 and hs[1] == hs[2]:
            label = "settled"
        else:
            label = "volatile"
        out.append((i * page, label))
    return out


def summarize(items, page: int = DEFAULT_PAGE):
    """[(offset, label)] から {label: (pages, bytes)} へ集計。"""
    acc = {}
    for _, label in items:
        p, b = acc.get(label, (0, 0))
        acc[label] = (p + 1, b + page)
    return acc


def label_ranges(items, page: int = DEFAULT_PAGE):
    """隣接する同一ラベルを連続領域に併合する。

    返り値: {label: [(start, end), ...]} (end は排他)。
    """
    out = {}
    for off, label in items:
        ranges = out.setdefault(label, [])
        if ranges and ranges[-1][1] == off:
            ranges[-1] = (ranges[-1][0], off + page)
        else:
            ranges.append((off, off + page))
    return out
