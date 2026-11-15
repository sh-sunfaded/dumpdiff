"""
izayoi.fastpath — 任意依存 (NumPy) による高速化レイヤ

コアは一貫して標準ライブラリのみで動作する。NumPy が導入されている
環境ではホットパスが自動的にベクトル化実装に切り替わる。
両者の結果の等価性は tests の等価性検証で担保する(NumPy が無い
環境では当該テストはスキップされる)。

高速化の狙いどころ:

  - shannon_entropy / entropy_map
      ページごとのヒストグラムを bincount で一括作り、
      エントロピーをページ軸でまとめて計算する
      (純実装の Counter + 逐次ループを排除)。
  - diff_runs
      a != b のバイトマスクからラン境界を flatnonzero/diff で
      一括抽出する(ページ単位の Python ループを排除)。
  - classify_pages
      ページごとの md5 掛り比較をやめ、フルページ範囲を 2D 化して
      一括バイト比較する(md5 衝突も原理的に排除)。
  - pairs のページ分類 (page_class 一括版)
      ヒストグラム行列から entropy / zero / strings 比率を、
      2 バイト窓の bincount から code 密度を、それぞれページ軸で
      まとめて計算する(ページ×バイトの Python ループを排除)。

ベクトル化しない箇所(ラン数に対する後処理は元々軽量):

  - diff ランの併合(merge_gap)と min_length フィルタ
  - pairs の候補併合・境界精密化・記述子整形
"""
from __future__ import annotations

try:
    import numpy as _np
    HAVE_NUMPY = True
except ImportError:  # pragma: no cover - 環境依存
    _np = None
    HAVE_NUMPY = False


def _require_numpy() -> None:
    if _np is None:
        raise RuntimeError("izayoi.fastpath requires numpy (not installed)")


# ============================================================ ヒストグラム

def _page_counts(data: bytes, page: int):
    """ページごとのバイトヒストグラム。

    返り値: (C, sizes) — C は (npages, 256) の int64 行列、
    sizes は各ページのバイト長(最終ページは端数)。
    """
    n = len(data)
    npages = (n + page - 1) // page
    C = _np.zeros((npages, 256), dtype=_np.int64)
    if npages == 0:
        return C, _np.zeros(0, dtype=_np.int64)
    arr = _np.frombuffer(data, dtype=_np.uint8)
    # ページをブロック単位で処理し、一時配列を抑制する
    BLOCK = 256  # ブロックあたりのページ数
    for r0 in range(0, npages, BLOCK):
        r1 = min(r0 + BLOCK, npages)
        lo = r0 * page
        hi = min(r1 * page, n)
        block = arr[lo:hi]
        row = (_np.arange(hi - lo, dtype=_np.int64) // page) - r0
        flat = block.astype(_np.int64) + row * 256
        bc = _np.bincount(flat, minlength=(r1 - r0) * 256)
        C[r0:r1] = bc.reshape(r1 - r0, 256)
    sizes = _np.full(npages, page, dtype=_np.int64)
    sizes[-1] = n - page * (npages - 1)
    return C, sizes


def _entropies_from_counts(C, sizes):
    """ヒストグラム行列 (npages, 256) から各ページのエントロピー。"""
    npages = C.shape[0]
    ent = _np.zeros(npages, dtype=_np.float64)
    if npages == 0:
        return ent
    nz = C > 0
    with _np.errstate(divide="ignore", invalid="ignore"):
        p = C / sizes[:, None].astype(_np.float64)
        logs = _np.zeros(p.shape, dtype=_np.float64)
        _np.log2(p, out=logs, where=nz)
        logs[~nz] = 0.0
    ent = -(p * logs).sum(axis=1)
    ent[sizes <= 0] = 0.0
    return ent


# ============================================================ entropy

def shannon_entropy(data: bytes) -> float:
    """全体エントロピーのベクトル化(単一バッファ)。"""
    _require_numpy()
    if not data:
        return 0.0
    counts = _np.bincount(_np.frombuffer(data, dtype=_np.uint8),
                          minlength=256).astype(_np.float64)
    p = counts / float(len(data))
    nz = counts > 0
    return float(-_np.sum(p[nz] * _np.log2(p[nz])))


def entropy_map(data: bytes, page: int):
    """ページ単位エントロピーの一括計算。

    返り値は純実装と同じ [(offset, entropy, chunk_size), ...]。
    """
    _require_numpy()
    C, sizes = _page_counts(data, page)
    ent = _entropies_from_counts(C, sizes)
    npages = C.shape[0]
    return [(i * page, float(ent[i]), int(sizes[i])) for i in range(npages)]


# ============================================================ diffruns

def diff_runs(a: bytes, b: bytes):
    """a vs b の不一致ラン抽出(ベクトル化)。

    併合(merge_gap)と min_length フィルタは呼び出し側
    (diffruns.diff_runs)が純実装と共通の処理で行うため、
    ここではランの列挙のみを返す。kind は diff / a-only / b-only。
    """
    _require_numpy()
    n = min(len(a), len(b))
    runs: list = []
    if n:
        x = _np.frombuffer(a, dtype=_np.uint8, count=n)
        y = _np.frombuffer(b, dtype=_np.uint8, count=n)
        idx = _np.flatnonzero(x != y)
        if idx.size:
            d = _np.diff(idx)
            brk = _np.flatnonzero(d > 1)
            starts = _np.concatenate((idx[:1], idx[brk + 1]))
            ends = _np.concatenate((idx[brk], idx[-1:])) + 1
            for s, e in zip(starts.tolist(), ends.tolist()):
                runs.append({"offset": s, "length": e - s, "kind": "diff"})
    if len(a) > len(b):
        runs.append({"offset": n, "length": len(a) - n, "kind": "a-only"})
    elif len(b) > len(a):
        runs.append({"offset": n, "length": len(b) - n, "kind": "b-only"})
    return runs


def classify_pages(images, page: int):
    """2〜3イメージのページ分類(ベクトル化)。

    md5 掛り比較の代わりにバイト比較でページ等価性を判定する
    (衝突の可能性も原理的に排除される)。検証は呼び出し側で済み。
    返り値は純実装と同じ [(offset, label), ...]。
    """
    _require_numpy()
    arrs = [_np.frombuffer(img, dtype=_np.uint8) for img in images]
    npages = min((len(x) + page - 1) // page for x in arrs)
    if npages == 0:
        return []
    full = (npages - 1) * page  # この範囲は全イメージでフルページ
    pairs = [(0, 1)] if len(images) == 2 else [(0, 1), (0, 2), (1, 2)]
    eq = {}
    for x, y in pairs:
        a2 = arrs[x][:full].reshape(-1, page)
        b2 = arrs[y][:full].reshape(-1, page)
        eq[(x, y)] = (a2 == b2).all(axis=1)
    # 最終比較ページは端数があり得るのでスライス等価で判定
    last = {}
    for x, y in pairs:
        last[(x, y)] = (images[x][full:full + page]
                        == images[y][full:full + page])
    out = []
    for i in range(npages):
        if i < npages - 1:
            e = {k: bool(v[i]) for k, v in eq.items()}
        else:
            e = last
        if len(images) == 2:
            label = "static" if e[(0, 1)] else "volatile"
        elif e[(0, 1)] and e[(0, 2)]:
            label = "static"
        elif e[(0, 2)]:
            label = "flip"
        elif e[(1, 2)]:
            label = "settled"
        else:
            label = "volatile"
        out.append((i * page, label))
    return out


# ============================================================ pairs

def _page_code_densities(data: bytes, page: int, sizes, patterns):
    """ページごとの 2 バイトパターン密度(256 バイトあたりのヒット数)。

    純実装の bytes.count と同じ結果になる:
    採用パターンはすべて 2 バイト目と 1 バイト目が異なるため、
    重複出現(オーバーラップ)は起こり得ず、非重複カウントと
    窓の全数え上げが一致する。ページ境界を跨ぐ窓は除外する
    (純実装はページスライス内で数えるため)。
    """
    n = len(data)
    npages = len(sizes)
    if npages == 0 or n < 2:
        return _np.zeros(npages, dtype=_np.float64)
    arr = _np.frombuffer(data, dtype=_np.uint8)
    w = (arr[:-1].astype(_np.uint16) << 8) | arr[1:]
    pats = _np.array([int.from_bytes(p, "big") for p in patterns],
                     dtype=_np.uint16)
    hits = _np.isin(w, pats)
    wpos = _np.arange(len(w), dtype=_np.int64)
    hits &= (wpos % page) != (page - 1)   # 境界跨ぎ窓を除外
    counts = _np.bincount(wpos[hits] // page, minlength=npages)
    return counts.astype(_np.float64) / (sizes.astype(_np.float64) / 256.0)


def page_classifications(data: bytes, page: int, cipher_entropy: float = 7.0,
                         code_density_min: float = 1.5,
                         printable_min: float = 0.55,
                         zero_min: float = 0.9, patterns=()):
    """全ページの page_class を一括計算する。

    返り値: [{"kind": ..., "entropy": ...}, ...] — ページ数ぶん。
    (純実装の pairs._classify_all と同じ形)
    """
    _require_numpy()
    C, sizes = _page_counts(data, page)
    npages = C.shape[0]
    if npages == 0:
        return []
    ent = _entropies_from_counts(C, sizes)
    sizesf = sizes.astype(_np.float64)
    zero_r = C[:, 0] / sizesf
    printable_cols = _np.array(list(range(0x20, 0x7f)) + [0x09, 0x0a, 0x0d])
    print_r = C[:, printable_cols].sum(axis=1) / sizesf
    code_d = _page_code_densities(data, page, sizes, patterns)
    cipher_b = ent >= cipher_entropy
    zero_b = zero_r >= zero_min
    code_b = code_d >= code_density_min
    strings_b = print_r >= printable_min
    ent_l = ent.tolist()
    out = []
    for i in range(npages):
        if cipher_b[i]:
            kind = "cipher"
        elif zero_b[i]:
            kind = "zero"
        elif code_b[i]:
            kind = "code"
        elif strings_b[i]:
            kind = "strings"
        else:
            kind = "data"
        out.append({"kind": kind, "entropy": ent_l[i]})
    return out


def printable_ratio(data: bytes) -> float:
    """印刷可能 ASCII 比率のベクトル化(単一バッファ)。"""
    _require_numpy()
    if not data:
        return 0.0
    arr = _np.frombuffer(data, dtype=_np.uint8)
    ok = (((arr >= 0x20) & (arr <= 0x7e))
          | (arr == 0x09) | (arr == 0x0a) | (arr == 0x0d))
    return float(ok.sum()) / len(data)
