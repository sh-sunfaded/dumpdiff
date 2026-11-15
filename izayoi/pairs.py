"""暗文↔平文ページ対の推定。

エントロピー差と平文らしさ(コード密度・文字列率)のパターンから
「一方のダンプでは暗号化され、他方では平文に展開されている」
領域の候補を列挙し、展開エンジン側(Toka等)の記述子形式で出力する。
"""
from __future__ import annotations

from . import fastpath
from .diffruns import classify_pages, diff_runs
from .entropy import shannon_entropy

DEFAULT_PAGE = 0x1000

# 平文側として意味があるとみなす page_class の kind
PLAIN_KINDS = ("code", "strings")

# x86-64 コードで高頻度な 2 バイトパターン。
# 単バイトパターン(call ret 等の 1 バイト命令)はランダムデータとの
# 誤区別が避けられないため採用しない。
_CODE_PATTERNS = (
    b"\x48\x89", b"\x48\x8b", b"\x48\x83", b"\x48\x8d", b"\x48\x3b",
    b"\x0f\x1f", b"\x0f\x84", b"\x0f\x85", b"\x85\xc0", b"\x84\xc0",
    b"\x55\x48", b"\x89\x55", b"\x8b\x45", b"\x74\x0a", b"\x75\x0a",
)

# code 判定のしきい値(256 バイトあたりのパターンヒット数)
CODE_DENSITY_MIN = 1.5
# strings 判定の印刷可能文字比率
PRINTABLE_MIN = 0.55
# zero 判定の 0x00 比率
ZERO_MIN = 0.9

# 印刷可能 ASCII(タブ/CR/LF を含む)— 純実装の translate 用
_PRINTABLE_BYTES = bytes(range(0x20, 0x7f)) + b"\t\n\r"


def code_density(data: bytes) -> float:
    """x86 風パターンの出現密度(256 バイトあたりのヒット数)。"""
    if not data:
        return 0.0
    hits = sum(data.count(p) for p in _CODE_PATTERNS)
    return hits / (len(data) / 256.0)


def printable_ratio(data: bytes) -> float:
    """印刷可能 ASCII の比率(タブ/CR/LF を含む)。"""
    if fastpath.HAVE_NUMPY:
        return fastpath.printable_ratio(data)
    if not data:
        return 0.0
    # translate の delete で印刷可能バイトを削り、差分から数える
    deleted = data.translate(None, _PRINTABLE_BYTES)
    return (len(data) - len(deleted)) / len(data)


def zero_ratio(data: bytes) -> float:
    return data.count(0) / len(data) if data else 0.0


def page_class(data: bytes, cipher_entropy: float = 7.0) -> dict:
    """ページ内容の分類。

    返り値: {"kind": cipher|zero|code|strings|data, "entropy": float}
      cipher  — エントロピー >= cipher_entropy(暗号・圧縮候補)
      zero    — ほぼ全 0x00
      code    — x86 風パターン密度が高い
      strings — 印刷可能文字が多い
      data    — それ以外
    """
    ent = shannon_entropy(data)
    if ent >= cipher_entropy:
        kind = "cipher"
    elif zero_ratio(data) >= ZERO_MIN:
        kind = "zero"
    elif code_density(data) >= CODE_DENSITY_MIN:
        kind = "code"
    elif printable_ratio(data) >= PRINTABLE_MIN:
        kind = "strings"
    else:
        kind = "data"
    return {"kind": kind, "entropy": ent}


def _classify_all(images, page, cipher_entropy):
    if fastpath.HAVE_NUMPY:
        return [fastpath.page_classifications(
            img, page, cipher_entropy=cipher_entropy,
            code_density_min=CODE_DENSITY_MIN, printable_min=PRINTABLE_MIN,
            zero_min=ZERO_MIN, patterns=_CODE_PATTERNS) for img in images]
    out = []
    for img in images:
        pages = [page_class(img[o:o + page], cipher_entropy)
                 for o in range(0, len(img), page)]
        out.append(pages)
    return out


def _cand(i, page, ci, pi, c, p, basis):
    return {
        "start": i * page, "end": (i + 1) * page, "pages": 1,
        "cipher": ci, "plain": pi,
        "cipher_entropy": round(c["entropy"], 4),
        "plain_entropy": round(p["entropy"], 4),
        "plain_kind": p["kind"], "basis": basis,
    }


def _merge_candidates(cands):
    """隣接する同条件ページの候補を 1 本に併合する。"""
    out = []
    for c in cands:
        prev = out[-1] if out else None
        if (prev and prev["cipher"] == c["cipher"]
                and prev["plain"] == c["plain"]
                and prev["plain_kind"] == c["plain_kind"]
                and prev["basis"] == c["basis"]
                and prev["end"] == c["start"]):
            prev["end"] = c["end"]
            prev["pages"] += 1
            prev["cipher_entropy"] = max(prev["cipher_entropy"],
                                        c["cipher_entropy"])
            prev["plain_entropy"] = min(prev["plain_entropy"],
                                        c["plain_entropy"])
        else:
            out.append(dict(c))
    return out


def find_pairs(images, page: int = DEFAULT_PAGE,
               cipher_entropy: float = 7.0, entropy_gap: float = 0.5):
    """暗文↔平文対候補を推定する。

    2 イメージ: 一方が cipher(エントロピー >= cipher_entropy)で
      他方が code/strings、かつエントロピー差 >= entropy_gap のページ。
    3 イメージ: compare の flip ページ(時点1==時点3 で時点2だけ異なる)
      を候補とし、2 状態のエントロピー比較で暗文側/平文側を決める
      (平文側が zero のページは除外)。

    返り値: 候補 dict のリスト(隣接ページ併合済み)。
    """
    if not 2 <= len(images) <= 3:
        raise ValueError("2〜3イメージが必要です")
    cls = _classify_all(images, page, cipher_entropy)
    n = min(len(c) for c in cls)
    found = []
    if len(images) == 2:
        for i in range(n):
            a, b = cls[0][i], cls[1][i]
            for ci, pi in ((0, 1), (1, 0)):
                c, p = cls[ci][i], cls[pi][i]
                if (c["kind"] == "cipher" and p["kind"] in PLAIN_KINDS
                        and c["entropy"] - p["entropy"] >= entropy_gap):
                    found.append(_cand(i, page, ci, pi, c, p, "score"))
    else:
        labels = classify_pages(images, page)
        for i in range(min(n, len(labels))):
            if labels[i][1] != "flip":
                continue
            c1, c2 = cls[0][i], cls[1][i]  # flip なら img2==img3
            if abs(c1["entropy"] - c2["entropy"]) < entropy_gap:
                continue
            if c1["entropy"] > c2["entropy"]:
                ci, pi, c, p = 0, 1, c1, c2
            else:
                ci, pi, c, p = 1, 0, c2, c1
            if p["kind"] == "zero":
                continue
            found.append(_cand(i, page, ci, pi, c, p, "flip"))
    return _merge_candidates(found)


def refine_with_diffs(cand: dict, images, merge_gap: int = 16) -> dict:
    """候補範囲をダンプ間差分ランで精密化する。

    候補ページ範囲と交差する diff ランの最小 offset / 最大終端で
    境界を更新し "refined_start" / "refined_end" に格納する。
    (ダンプ間の差分がブロック実体の外縁に現れることを利用する)
    """
    runs = diff_runs(images[cand["cipher"]], images[cand["plain"]],
                     merge_gap=merge_gap)
    inside = [r for r in runs if r["kind"] == "diff"
              and r["offset"] < cand["end"]
              and r["offset"] + r["length"] > cand["start"]]
    if not inside:
        cand["refined_start"] = cand["start"]
        cand["refined_end"] = cand["end"]
    else:
        cand["refined_start"] = min(r["offset"] for r in inside)
        cand["refined_end"] = max(r["offset"] + r["length"] for r in inside)
    return cand


def descriptor_suggestion(cand: dict) -> str:
    """候補を展開エンジンの記述子形式 "off1:size1:off2:size2" に整形。

    サイズは候補範囲からの推定値(展開エンジン側での調整を前提)。
    """
    start = cand.get("refined_start", cand["start"])
    end = cand.get("refined_end", cand["end"])
    size = max(1, end - start)
    return "0x%x:0x%x:0x%x:0x%x" % (start, size, start, size)


def analyze_pairs(images, names, page: int = DEFAULT_PAGE,
                   cipher_entropy: float = 7.0, entropy_gap: float = 0.5,
                   merge_gap: int = 16):
    """find_pairs + 境界精密化 + 記述子整形 + 名前解決までの一括処理。"""
    cands = find_pairs(images, page=page, cipher_entropy=cipher_entropy,
                       entropy_gap=entropy_gap)
    for c in cands:
        refine_with_diffs(c, images, merge_gap=merge_gap)
        c["cipher_name"] = names[c["cipher"]]
        c["plain_name"] = names[c["plain"]]
        c["descriptor"] = descriptor_suggestion(c)
    return cands
