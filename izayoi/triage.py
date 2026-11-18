"""ダンプのトリアージ(初動鑑定)。

「手元のダンプ群をまず何を見るべきか」に答える第一段階の分析:

  - PE ヘッダ検出 (detect_pe)
      メモリキャプチャ / オンディスクファイルの両方から
      PE32/PE32+ の基本情報(機種・イメージベース・SizeOfImage・
      セクション表・レイアウト推定)を読む。
  - REGION ヘッダ解析 (region_info)
      採取ツールが先頭に付けるテキストヘッダから採取条件を復元。
  - ページ分類の集計 (page_census)
      cipher/zero/code/strings/data のページ数を数える。
  - 読みやすい資産の所在推定 (readable_sources / readability_ranking)
      複数時点ダンプの同じページを見比べ、最も平文らしい
      (読みやすい)状態を持つダンプをページ/領域単位で選ぶ。
      「どの時点のダンプでどの領域を読めばいいか」の答えになる。

コアは標準ライブラリのみ。ページ分類は pairs の一括分類を流用する
ため、NumPy 導入環境ではここも自動的にベクトル化される。
"""
from __future__ import annotations

import os
import re
import struct

from .images import fingerprint, strip_header
from .pairs import _classify_all

DEFAULT_PAGE = 0x1000

# REGION ヘッダ(採取ツール由来のテキスト行)。
_REGION_RE = re.compile(rb"^REGION ([^\r\n]*)\r?\n")
_REGION_FIELD = re.compile(r"(addr|size)=(0x[0-9a-fA-F]+|\d+)")

# COFF Machine 値(mainstream のみ)。
_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0xAA64: "arm64",
    0x01C0: "arm",
    0x01C4: "armnt",
}

# ページ内容の「読みやすさ」ランク(小さいほど読みやすい)。
# code/strings は平文としてそのまま読める。data は低エントロピーの
# 構造データ、zero は未使用、cipher は最後の手段。
READABILITY_RANK = {"code": 0, "strings": 0, "data": 1, "zero": 2,
                    "cipher": 3}

_KIND_ORDER = ("cipher", "code", "strings", "data", "zero")


def region_info(data: bytes):
    """REGION ヘッダを解析する。

    例: b"REGION image addr=0x140000000 size=688128\\r\\n" から
    {"addr": 0x140000000, "size": 688128} を取り出す。
    ヘッダが無い場合は None を返す。
    """
    m = _REGION_RE.match(data)
    if not m:
        return None
    text = m.group(1).decode("ascii", "replace")
    out = {"text": text}
    for key, value in _REGION_FIELD.findall(text):
        out[key] = int(value, 0)
    return out


def detect_pe(data: bytes):
    """先頭 4KB の窓から PE ヘッダを検出し、基本情報を返す。

    オンディスク PE(セクション raw オフセット != RVA)と
    メモリキャプチャ(RVA==オフセット)の両方に対応する。
    ヘッダが読めない/存在しない場合は None(例外を投げない)。

    返り値: {
      "offset": MZ の位置, "bitness": "PE32+"|"PE32",
      "machine": "x86-64" 等, "machine_code": int,
      "image_base": int, "size_of_image": int|None,
      "sections": [{"name","vaddr","vsize"}, ...],
      "layout": "memory"|"file", "coverage": 0.0〜1.0|None,
      "full": bool|None,
    }
    """
    window = data[:0x1000]
    mz = window.find(b"MZ")
    if mz < 0 or mz + 0x40 > len(data):
        return None
    try:
        (lfanew,) = struct.unpack_from("<I", data, mz + 0x3C)
    except struct.error:
        return None
    if not 0 < lfanew < 0x1000 or mz + lfanew + 24 > len(data):
        return None
    pe = mz + lfanew
    if data[pe:pe + 4] != b"PE\x00\x00":
        return None
    try:
        machine, nsec, _tds, _ptr, _ncs, opt_size, _flags = \
            struct.unpack_from("<HHIIIHH", data, pe + 4)
    except struct.error:
        return None
    opt = pe + 24
    try:
        (magic,) = struct.unpack_from("<H", data, opt)
    except struct.error:
        return None
    if magic == 0x20B:
        bitness = "PE32+"
        try:
            (image_base,) = struct.unpack_from("<Q", data, opt + 24)
        except struct.error:
            return None
    elif magic == 0x10B:
        bitness = "PE32"
        try:
            (image_base,) = struct.unpack_from("<I", data, opt + 28)
        except struct.error:
            return None
    else:
        return None
    size_of_image = None
    try:
        (soi,) = struct.unpack_from("<I", data, opt + 56)
        if soi:
            size_of_image = soi
    except struct.error:
        pass

    sections = []
    memory_layout = True
    sec_off = opt + opt_size if opt_size else 0
    for i in range(nsec):
        o = sec_off + 40 * i
        if o <= 0 or o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        try:
            vsize, vaddr, rsize, raw_off = struct.unpack_from(
                "<IIII", data, o + 8)
        except struct.error:
            break
        if raw_off != vaddr:
            memory_layout = False
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize})

    coverage = None
    full = None
    if size_of_image:
        coverage = min(len(data), size_of_image) / size_of_image
        full = len(data) >= size_of_image
    return {
        "offset": mz,
        "bitness": bitness,
        "machine": _MACHINES.get(machine, "unknown(0x%04x)" % machine),
        "machine_code": machine,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "sections": sections,
        "layout": "memory" if memory_layout else "file",
        "coverage": coverage,
        "full": full,
    }


def page_census(images, page: int = DEFAULT_PAGE,
                cipher_entropy: float = 7.0):
    """各イメージのページ分類を集計する。

    返り値: [{kind: ページ数, ...}, ...] — イメージごと。
    ページ分類本体は pairs.page_class と同じ基準。
    """
    cls = _classify_all(images, page, cipher_entropy)
    out = []
    for pages in cls:
        acc: dict = {}
        for p in pages:
            acc[p["kind"]] = acc.get(p["kind"], 0) + 1
        out.append(acc)
    return out


def readable_sources(images, page: int = DEFAULT_PAGE,
                     cipher_entropy: float = 7.0):
    """ページごとに「最も読みやすい」イメージを選ぶ。

    同じページを複数時点で比較し、READABILITY_RANK が最も良く
    (同ランクならエントロピーが最も低い=より構造のある)状態を
    持つイメージを選ぶ。「この領域はどのダンプで読むべきか」
    の答えを領域単位で返す。

    返り値: [{"start", "end", "source", "kind", "entropy"}, ...]
    隣接する同条件ページは 1 本に併合済み(end は排他)。
    """
    if len(images) < 2:
        raise ValueError("2つ以上のイメージが必要です")
    cls = _classify_all(images, page, cipher_entropy)
    n = min(len(c) for c in cls)
    out = []
    for i in range(n):
        best = None  # (rank, entropy, index)
        for idx, pages in enumerate(cls):
            c = pages[i]
            key = (READABILITY_RANK[c["kind"]], c["entropy"], idx)
            if best is None or key < best:
                best = key
                chosen = c
        rank, ent, src = best
        kind = chosen["kind"]
        if (out and out[-1]["source"] == src
                and out[-1]["kind"] == kind
                and out[-1]["end"] == i * page):
            out[-1]["end"] = (i + 1) * page
        else:
            out.append({"start": i * page, "end": (i + 1) * page,
                        "source": src, "kind": kind,
                        "entropy": round(ent, 4)})
    return out


def readability_ranking(images, page: int = DEFAULT_PAGE,
                        cipher_entropy: float = 7.0):
    """イメージを読みやすさで順位付けする。

    平文(code+strings)ページ数の降順、data ページ数の降順、
    cipher ページ数の昇順、最後にイメージ順で決定論的に並べる。
    """
    stats = []
    for idx, acc in enumerate(page_census(images, page, cipher_entropy)):
        stats.append({
            "index": idx,
            "plain_pages": acc.get("code", 0) + acc.get("strings", 0),
            "data_pages": acc.get("data", 0),
            "cipher_pages": acc.get("cipher", 0),
            "zero_pages": acc.get("zero", 0),
        })
    stats.sort(key=lambda s: (-s["plain_pages"], -s["data_pages"],
                              s["cipher_pages"], s["index"]))
    return stats


def triage_images(raws, names, page: int = DEFAULT_PAGE,
                  cipher_entropy: float = 7.0):
    """生バイト列のリストから初動鑑定情報を構築する。

    raws には REGION ヘッダ付きの生データを渡す(解析後に除去する)。
    返り値: {
      "page": page,
      "images": [{"name", "size", "md5", "sha256", "entropy",
                   "region"|None, "pe"|None, "census"}, ...],
      "readable": [...] (2 イメージ以上),
      "ranking": [...] (2 イメージ以上),
    }
    """
    images = [strip_header(r) for r in raws]
    info = {"page": page, "images": []}
    for name, raw, img in zip(names, raws, images):
        info["images"].append({
            "name": name,
            **fingerprint(img),
            "region": region_info(raw),
            "pe": detect_pe(img),
        })
    census = page_census(images, page, cipher_entropy)
    for entry, acc in zip(info["images"], census):
        entry["census"] = {k: acc[k] for k in _KIND_ORDER if k in acc}
    if len(images) >= 2:
        info["readable"] = [
            {"start": r["start"], "end": r["end"], "source": names[r["source"]],
             "kind": r["kind"], "entropy": r["entropy"]}
            for r in readable_sources(images, page, cipher_entropy)]
        info["ranking"] = [
            {**s, "name": names[s["index"]]} for s in
            readability_ranking(images, page, cipher_entropy)]
    return info


def triage(paths, page: int = DEFAULT_PAGE, cipher_entropy: float = 7.0):
    """ダンプファイル群の初動鑑定を一括実行する(パス指定の表 API)。"""
    names = [os.path.basename(p) for p in paths]
    raws = []
    for p in paths:
        with open(p, "rb") as fh:
            raws.append(fh.read())
    return triage_images(raws, names, page=page, cipher_entropy=cipher_entropy)
