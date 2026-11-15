"""izayoi テストスイート(合成データのみ・外部ダンプ不要)。

使い方: PYTHONPATH=. python3 tests/test_izayoi.py
"""
import hashlib
import io
import os
import random
import sys
import tempfile
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from izayoi import (classify_pages, diff_runs, entropy_map,
                      fingerprint, high_entropy_ranges, label_ranges,
                      load_image, shannon_entropy, strip_header, summarize)
from izayoi import fastpath as _fp
from izayoi.fastpath import HAVE_NUMPY
from izayoi.pairs import (analyze_pairs, code_density, find_pairs,
                            page_class, printable_ratio, refine_with_diffs,
                            descriptor_suggestion, _CODE_PATTERNS,
                            CODE_DENSITY_MIN, PRINTABLE_MIN, ZERO_MIN)
from izayoi.report import json_report, markdown_report

RESULTS = []
SKIPPED = []


class SkipTest(Exception):
    """NumPy 等の任意依存が無い環境で等価性テストをスキップする。"""


def requires_numpy():
    if not HAVE_NUMPY:
        raise SkipTest("numpy not installed")


def check(name, cond):
    RESULTS.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name)


def skip(name, reason):
    SKIPPED.append(name)
    print("SKIP  %s  (%s)" % (name, reason))


def rnd(n, seed=0):
    """決定論的な一様バイト列(高エントロピーfixture)。"""
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


def codepage(seed=3):
    """x86風パターンを高密度に含む低エントロピー領域。"""
    r = random.Random(seed)
    pats = [b"\x48\x89\x5d", b"\x48\x8b\x05", b"\x48\x83\xec",
            b"\x0f\x1f\x44", b"\x85\xc0", b"\x55\x48\x89\xe5",
            b"\x48\x8d\x4d", b"\x89\x55\xfc"]
    parts = []
    for _ in range(96):
        parts.append(r.choice(pats)
                     + bytes(r.getrandbits(8) for _ in range(r.getrandbits(4))))
    data = b"".join(parts)
    return (data + b"\x90" * 0x1000)[:0x1000]


def stringspage(seed=4):
    r = random.Random(seed)
    words = [b"CreateFileW", b"LoadLibraryW", b"GetThreadContext",
             b"WriteProcessMemory", b"NtQueryVirtualMemory"]
    parts = []
    total = 0
    while total < 0x1000:
        w = r.choice(words) + b"\x00"
        parts.append(w)
        total += len(w)
    return b"".join(parts)[:0x1000]


def test_strip_header():
    hdr = b"REGION image addr=0x140000000 size=16\r\n"
    payload = b"\x00\x01\x02MZ"
    check("test_strip_header", strip_header(hdr + payload) == payload)
    check("test_strip_header_passthrough",
          strip_header(payload) == payload)


def test_load_image_strips_header():
    hdr = b"REGION image addr=0x140000000 size=4\n"
    payload = b"MZ\x90\x00"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(hdr + payload)
        path = fh.name
    try:
        check("test_load_image_strips_header", load_image(path) == payload)
    finally:
        os.unlink(path)


def test_fingerprint():
    data = b"hello world"
    fp = fingerprint(data)
    import hashlib
    check("test_fingerprint_md5",
          fp["md5"] == hashlib.md5(data).hexdigest())
    check("test_fingerprint_size", fp["size"] == len(data))


def test_entropy_zero_and_high():
    check("test_entropy_zero", shannon_entropy(b"\x00" * 0x100) == 0.0)
    check("test_entropy_high", shannon_entropy(rnd(0x1000, 1)) > 7.0)
    check("test_entropy_empty", shannon_entropy(b"") == 0.0)


def test_entropy_map_and_ranges():
    page = 0x1000
    data = (b"\x00" * page) + rnd(page, 2) + (b"\xff" * 0x800)
    m = entropy_map(data, page)
    check("test_entropy_map_pages", len(m) == 3 and m[0][0] == 0
          and m[1][0] == page and m[2][2] == 0x800)
    ranges = high_entropy_ranges(data, 7.0, page)
    check("test_high_entropy_ranges",
          len(ranges) == 1 and ranges[0][0] == page
          and ranges[0][1] == 2 * page)
    check("test_high_entropy_ranges_none",
          high_entropy_ranges(b"\x00" * 0x2000, 7.0, page) == [])


def test_diff_runs_basic():
    a = bytearray(b"\x00" * 0x1000)
    b = bytearray(a)
    b[0x100:0x200] = b"\x11" * 0x100
    runs = diff_runs(bytes(a), bytes(b))
    check("test_diff_runs_basic",
          len(runs) == 1 and runs[0]["offset"] == 0x100
          and runs[0]["length"] == 0x100 and runs[0]["kind"] == "diff")


def test_diff_runs_merge():
    a = bytearray(b"\x00" * 0x100)
    b = bytearray(a)
    b[0x10:0x20] = b"\x11" * 0x10
    b[0x30:0x40] = b"\x22" * 0x10   # 0x10 バイトの一致区間を挟む
    runs = diff_runs(bytes(a), bytes(b), merge_gap=0x10)
    check("test_diff_runs_merge",
          len(runs) == 1 and runs[0]["offset"] == 0x10
          and runs[0]["length"] == 0x30)
    runs2 = diff_runs(bytes(a), bytes(b), merge_gap=0)
    check("test_diff_runs_no_merge", len(runs2) == 2)


def test_diff_runs_tail_and_minlen():
    a = b"\x00" * 0x100 + b"\xAA" * 0x10
    b = b"\x00" * 0x100
    runs = diff_runs(a, b)
    check("test_diff_runs_tail",
          runs[-1]["kind"] == "a-only"
          and runs[-1]["offset"] == 0x100
          and runs[-1]["length"] == 0x10)
    short = diff_runs(b"\x00\x01\x00", b"\x00\x02\x00", min_length=2)
    check("test_diff_runs_min_length", short == [])


def test_diff_runs_page_boundary():
    a = bytearray(b"\x00" * 0x2000)
    b = bytearray(a)
    b[0xff0:0x1010] = b"\x33" * 0x20   # ページ境界を跨ぐ差分
    runs = diff_runs(bytes(a), bytes(b))
    check("test_diff_runs_page_boundary",
          len(runs) == 1 and runs[0]["offset"] == 0xff0
          and runs[0]["length"] == 0x20)
    runs2 = diff_runs(bytes(a), bytes(b), merge_gap=1)
    check("test_diff_runs_page_boundary_merge", runs2 == runs)


def test_classify_pages_three():
    page = 0x1000
    static = b"\x00" * page
    flip_plain = b"\x11" * page
    flip_other = b"\x22" * page
    volatile = [rnd(page, s) for s in (10, 11, 12)]
    settled_p1 = rnd(page, 20)
    settled_p23 = rnd(page, 21)
    img1 = static + flip_plain + volatile[0] + settled_p1
    img2 = static + flip_other + volatile[1] + settled_p23
    img3 = static + flip_plain + volatile[2] + settled_p23
    items = classify_pages([img1, img2, img3], page)
    labels = [lab for _, lab in items]
    check("test_classify_pages_three",
          labels == ["static", "flip", "volatile", "settled"])


def test_classify_pages_two_and_errors():
    page = 0x1000
    same = b"\x00" * page
    img1 = same + b"\x11" * page
    img2 = same + b"\x22" * page
    items = classify_pages([img1, img2], page)
    check("test_classify_pages_two",
          [lab for _, lab in items] == ["static", "volatile"])
    try:
        classify_pages([img1])
        check("test_classify_pages_needs_two", False)
    except ValueError:
        check("test_classify_pages_needs_two", True)
    try:
        classify_pages([img1, img2, img1, img2])
        check("test_classify_pages_max_three", False)
    except ValueError:
        check("test_classify_pages_max_three", True)


def test_summarize_and_ranges():
    page = 0x1000
    items = [(0, "static"), (page, "static"), (2 * page, "flip")]
    acc = summarize(items, page)
    check("test_summarize",
          acc["static"] == (2, 2 * page) and acc["flip"] == (1, page))
    ranges = label_ranges(items, page)
    check("test_label_ranges",
          ranges["static"] == [(0, 2 * page)]
          and ranges["flip"] == [(2 * page, 3 * page)])


def test_reports():
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(page, 30)
    img2 = (b"\x00" * page) + rnd(page, 31)
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "dump1.bin")
        p2 = os.path.join(td, "dump2.bin")
        with open(p1, "wb") as fh:
            fh.write(img1)
        with open(p2, "wb") as fh:
            fh.write(img2)
        md = markdown_report([p1, p2], page=page)
        check("test_markdown_report",
              "# izayoi レポート" in md and "## イメージ" in md
              and "## ページ分類" in md and "flip" not in md)
        js = json_report([p1, p2], page=page)
        import json as _json
        d = _json.loads(js)
        check("test_json_report",
              d["images"][0]["size"] == len(img1)
              and "classification" in d)


def test_pairs_scores():
    code = codepage()
    plain_txt = stringspage()
    check("test_code_density_high", code_density(code) >= 1.5)
    check("test_code_density_low", code_density(rnd(0x1000, 5)) < 1.5)
    check("test_printable_ratio",
          printable_ratio(plain_txt) > 0.55
          and 0.2 < printable_ratio(rnd(0x1000, 6)) < 0.5)
    check("test_page_class_cipher",
          page_class(rnd(0x1000, 7))["kind"] == "cipher")
    check("test_page_class_zero",
          page_class(b"\x00" * 0x1000)["kind"] == "zero")
    check("test_page_class_code", page_class(code)["kind"] == "code")
    check("test_page_class_strings",
          page_class(plain_txt)["kind"] == "strings")


def test_find_pairs_two():
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(page, 50)
    img2 = (b"\x00" * page) + codepage()
    cands = find_pairs([img1, img2])
    check("test_find_pairs_two",
          len(cands) == 1 and cands[0]["start"] == page
          and cands[0]["cipher"] == 0 and cands[0]["plain"] == 1
          and cands[0]["plain_kind"] == "code"
          and cands[0]["basis"] == "score")
    check("test_find_pairs_none",
          find_pairs([img1, (b"\x00" * page) + rnd(page, 51)]) == [])


def test_find_pairs_merge():
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(page, 52) + rnd(page, 53)
    img2 = (b"\x00" * page) + codepage(1) + codepage(2)
    cands = find_pairs([img1, img2])
    check("test_find_pairs_merge",
          len(cands) == 1 and cands[0]["start"] == page
          and cands[0]["end"] == 3 * page and cands[0]["pages"] == 2)


def test_find_pairs_three_flip():
    page = 0x1000
    cipher_state = rnd(page, 60)
    img1 = (b"\x00" * page) + cipher_state + (b"\x00" * page)
    img2 = (b"\x00" * page) + codepage(3) + (b"\x00" * page)
    img3 = (b"\x00" * page) + cipher_state + (b"\x00" * page)
    cands = find_pairs([img1, img2, img3])
    check("test_find_pairs_three_flip",
          len(cands) == 1 and cands[0]["basis"] == "flip"
          and cands[0]["cipher"] == 0 and cands[0]["plain"] == 1
          and cands[0]["plain_kind"] == "code")
    # 平文側が zero の flip は対象外
    img2z = (b"\x00" * page) + (b"\x00" * page) + (b"\x00" * page)
    check("test_find_pairs_flip_zero_skipped",
          find_pairs([img1, img2z, img3]) == [])


def test_refine_and_descriptor():
    img1 = b"\x00" * 0x2000
    img2 = (b"\x00" * 0x1234 + b"\x11" * 0x2cc
            + b"\x00" * (0x2000 - 0x1500))
    cand = {"start": 0x1000, "end": 0x2000, "cipher": 0, "plain": 1}
    refine_with_diffs(cand, [img1, img2])
    check("test_refine_with_diffs",
          cand["refined_start"] == 0x1234
          and cand["refined_end"] == 0x1500)
    check("test_descriptor_suggestion",
          descriptor_suggestion(cand)
          == "0x1234:0x2cc:0x1234:0x2cc")
    cand2 = {"start": 0x1000, "end": 0x2000, "cipher": 0, "plain": 1}
    refine_with_diffs(cand2, [img1, img1])
    check("test_refine_no_diff_keeps_range",
          cand2["refined_start"] == 0x1000
          and cand2["refined_end"] == 0x2000)


def test_analyze_pairs_and_report():
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(page, 70)
    img2 = (b"\x00" * page) + codepage(4)
    cands = analyze_pairs([img1, img2], ["dump1.bin", "v1d.bin"])
    check("test_analyze_pairs",
          len(cands) == 1 and cands[0]["cipher_name"] == "dump1.bin"
          and cands[0]["plain_name"] == "v1d.bin"
          and cands[0]["descriptor"].startswith("0x1000:"))
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "dump1.bin")
        p2 = os.path.join(td, "v1d.bin")
        with open(p1, "wb") as fh:
            fh.write(img1)
        with open(p2, "wb") as fh:
            fh.write(img2)
        md = markdown_report([p1, p2], page=page)
        check("test_markdown_report_pairs",
              "## 暗文↔平文対候補" in md and "desc (推定)" in md)
        import json as _json
        d = _json.loads(json_report([p1, p2], page=page))
        check("test_json_report_pairs",
              len(d["pairs"]) == 1
              and d["pairs"][0]["plain_kind"] == "code")


def test_pairs_cli_smoke():
    from izayoi import cli
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(page, 80)
    img2 = (b"\x00" * page) + codepage(5)
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "dump1.bin")
        p2 = os.path.join(td, "v1d.bin")
        with open(p1, "wb") as fh:
            fh.write(img1)
        with open(p2, "wb") as fh:
            fh.write(img2)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["pairs", p1, p2])
        out = buf.getvalue()
        check("test_cli_pairs_smoke",
              rc == 0 and "1 候補" in out and "desc (推定)" in out)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["pairs", p1, p2, "--json"])
        import json as _json
        d = _json.loads(buf.getvalue())
        check("test_cli_pairs_json", rc == 0 and len(d) == 1
              and d[0]["descriptor"])


def test_cli_smoke():
    from izayoi import cli
    page = 0x1000
    img1 = (b"\x00" * page) + rnd(0x100, 40)
    img2 = (b"\x00" * page) + rnd(0x100, 41)
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "a.bin")
        p2 = os.path.join(td, "b.bin")
        with open(p1, "wb") as fh:
            fh.write(img1)
        with open(p2, "wb") as fh:
            fh.write(img2)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["diff", p1, p2, "--merge-gap", "16"])
        check("test_cli_diff_smoke", rc == 0 and "ラン" in buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["compare", p1, p2, "--ranges"])
        check("test_cli_compare_smoke", rc == 0 and "static" in buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["report", p1, p2, "--out",
                           os.path.join(td, "r.md")])
        check("test_cli_report_smoke",
              rc == 0 and os.path.exists(os.path.join(td, "r.md")))


# ============================================================ fastpath(NumPy)
# NumPy が導入されている環境では、これらの等価性テストが
# ベクトル化実装(fastpath)と純実装の結果一致を検証する。
# NumPy が無い環境ではスキップされ、コアは純実装で動く。


def _pure_entropy(data):
    """純実装エントロピー(原本の Counter 版)。"""
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _pure_entropy_map(data, page):
    return [(o, _pure_entropy(data[o:o + page]), min(page, len(data) - o))
            for o in range(0, len(data), page)]


def _pure_diff_runs(a, b):
    """純実装のラン列挙(併合前)。0x1000 チャンク走査でもランを
    チャンク境界で分割しない仕様の参照実装。"""
    runs = []
    n = min(len(a), len(b))
    off = 0
    start = None
    while off < n:
        end = min(off + 0x1000, n)
        if a[off:end] != b[off:end]:
            for i in range(off, end):
                if a[i] != b[i]:
                    if start is None:
                        start = i
                elif start is not None:
                    runs.append({"offset": start, "length": i - start,
                                 "kind": "diff"})
                    start = None
        elif start is not None:
            runs.append({"offset": start, "length": off - start,
                         "kind": "diff"})
            start = None
        off = end
    if start is not None:
        runs.append({"offset": start, "length": n - start, "kind": "diff"})
    if len(a) > len(b):
        runs.append({"offset": n, "length": len(a) - n, "kind": "a-only"})
    elif len(b) > len(a):
        runs.append({"offset": n, "length": len(b) - n, "kind": "b-only"})
    return runs


def _pure_classify_pages(images, page):
    """純実装のページ分類(原本の md5 版)。"""
    hashes = [[hashlib.md5(img[o:o + page]).digest()
               for o in range(0, len(img), page)] for img in images]
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


def _pure_printable(data):
    if not data:
        return 0.0
    n = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    return n / len(data)


def _pure_page_class(chunk, cipher_entropy=7.0):
    """純実装 page_class(原本の定義)。"""
    ent = _pure_entropy(chunk)
    if ent >= cipher_entropy:
        kind = "cipher"
    elif chunk.count(0) / len(chunk) >= ZERO_MIN:
        kind = "zero"
    elif sum(chunk.count(p) for p in _CODE_PATTERNS) / (len(chunk) / 256.0) \
            >= CODE_DENSITY_MIN:
        kind = "code"
    elif _pure_printable(chunk) >= PRINTABLE_MIN:
        kind = "strings"
    else:
        kind = "data"
    return {"kind": kind, "entropy": ent}


def test_fastpath_entropy_equivalence():
    requires_numpy()
    ok = True
    for size, seed in ((0, 0), (1, 1), (7, 2), (0x1000, 3),
                       (0x1000 * 3 + 123, 4), (0x2731, 5)):
        data = rnd(size, seed) if size else b""
        fe = _fp.shannon_entropy(data)
        pe = _pure_entropy(data)
        ok = ok and abs(fe - pe) < 1e-9
        fm = _fp.entropy_map(data, 0x1000)
        pm = _pure_entropy_map(data, 0x1000)
        ok = ok and len(fm) == len(pm)
        for (o1, e1, s1), (o2, e2, s2) in zip(fm, pm):
            ok = ok and o1 == o2 and s1 == s2 and abs(e1 - e2) < 1e-9
    check("test_fastpath_entropy_equivalence", ok)


def test_fastpath_diff_runs_equivalence():
    requires_numpy()
    ok = True
    cases = [
        (b"", b""),
        (b"abc", b"abc"),
        (b"aaabbbccc", b"aaaXXXccc"),          # 中央1ラン
        (b"\x00" * 10, b"\x00" * 10 + b"tail"),  # b-only
        (b"head" + b"\x00" * 8, b"\x00" * 8),   # a-only
        (rnd(0x2000, 10), rnd(0x2000, 11)),    # ページ跨ぎ
        (rnd(0x1234, 12), rnd(0x2345, 13)),    # 長さ不一致+端数
    ]
    for a, b in cases:
        ok = ok and _fp.diff_runs(a, b) == _pure_diff_runs(a, b)
    # 高密度差分(多数の小ラン)での境界抽出
    r = random.Random(99)
    a = bytes(r.getrandbits(8) for _ in range(0x3000))
    b = bytearray(a)
    for i in range(0, 0x3000, 3):
        b[i] ^= 0xFF
    ok = ok and _fp.diff_runs(bytes(b[:0x2000]), a[:0x2000]) \
        == _pure_diff_runs(bytes(b[:0x2000]), a[:0x2000])
    check("test_fastpath_diff_runs_equivalence", ok)


def test_fastpath_classify_pages_equivalence():
    requires_numpy()
    ok = True
    base = rnd(0x3000, 20)
    # 時点2=flip/settled が混在する3時点を作る
    v2 = bytearray(base)
    v3 = bytearray(base)
    v2[0x1000:0x2000] = rnd(0x1000, 21)
    v3[0x1000:0x2000] = v2[0x1000:0x2000]
    v3[0x2000:0x2400] = rnd(0x400, 22)
    v2 = bytes(v2)
    v3 = v3[:0x2800]                      # 長さ不一致も含める
    for imgs in ([base, v2, v3], [base, v2], [base[:0x1234], v2[:0x2500]]):
        for page in (0x1000, 0x400):
            ok = ok and _fp.classify_pages(imgs, page) \
                == _pure_classify_pages(imgs, page)
    check("test_fastpath_classify_pages_equivalence", ok)


def test_fastpath_page_classifications_equivalence():
    requires_numpy()
    ok = True
    # 各分類種を混在させたイメージ(zero/code/strings/cipher/data)
    page = 0x1000
    img = (b"\x00" * page + codepage(5) + stringspage(6)
           + rnd(page, 23)
           + bytes(range(0x40, 0x80)) * 32)   # data(低エントロピー・非コード)
    img = img[:page * 5]
    fast = _fp.page_classifications(
        img, page, cipher_entropy=7.0, code_density_min=CODE_DENSITY_MIN,
        printable_min=PRINTABLE_MIN, zero_min=ZERO_MIN,
        patterns=_CODE_PATTERNS)
    pure = [_pure_page_class(img[o:o + page]) for o in range(0, len(img), page)]
    ok = ok and len(fast) == len(pure)
    for f, p in zip(fast, pure):
        ok = ok and f["kind"] == p["kind"] and abs(f["entropy"] - p["entropy"]) < 1e-9
    # ページ境界を跨ぐパターンがカウントされないこと(窓除外の検証)
    page = 0x10
    img = b"\x90" * (page * 2)
    img = (img[:page - 1] + b"\x48\x89" + img[page + 1:])   # 境界に跨ぐ
    dens = _fp._page_code_densities(img, page, [page, page],
                                   _CODE_PATTERNS)
    ok = ok and float(dens.max()) == 0.0
    # 純実装と同じく「ページ内に完全に含まれる窓」のみ数える
    img2 = img[:page - 2] + b"\x48\x89" + img[page:]        # page0 内に収まる
    dens2 = _fp._page_code_densities(img2, page, [page, page],
                                     _CODE_PATTERNS)
    pure_d = (img2[:page].count(b"\x48\x89")) / (page / 256.0)
    ok = ok and abs(float(dens2[0]) - pure_d) < 1e-9
    check("test_fastpath_page_classifications_equivalence", ok)


def test_fastpath_printable_ratio_equivalence():
    requires_numpy()
    ok = True
    for size, seed in ((0, 0), (1, 1), (0x1000, 30), (0x2731, 31)):
        data = rnd(size, seed) if size else b""
        ok = ok and _fp.printable_ratio(data) == _pure_printable(data)
        # 境界値(0x20/0x7e/0x7f/0x09/0x0a/0x0d)を含むデータ
    edge = bytes([0x09, 0x0a, 0x0d, 0x20, 0x7e, 0x7f, 0x1f, 0x00, 0x41])
    ok = ok and _fp.printable_ratio(edge) == _pure_printable(edge)
    ok = ok and printable_ratio(edge) == _pure_printable(edge)
    check("test_fastpath_printable_ratio_equivalence", ok)


def test_fastpath_dispatch_flag():
    """HAVE_NUMPY フラグとディスパッチの一貫性(NumPy 無し環境のフォールバック)。"""
    if HAVE_NUMPY:
        # NumPy がある環境では全公開APIが fastpath 経由でも動く(他テストが担保)
        check("test_fastpath_dispatch_flag", True)
        return
    # NumPy が無い環境: fastpath は RuntimeError、コアは純実装で動作
    ok = True
    for fn, args in ((_fp.shannon_entropy, (b"abc",)),
                     (_fp.entropy_map, (b"abc", 0x1000)),
                     (_fp.diff_runs, (b"a", b"b")),
                     (_fp.classify_pages, ([b"a", b"b"], 0x1000)),
                     (_fp.page_classifications, (b"abc", 0x1000)),
                     (_fp.printable_ratio, (b"abc",))):
        try:
            fn(*args)
            ok = False
        except RuntimeError:
            pass
    ok = ok and shannon_entropy(b"aaaa") == 0.0
    ok = ok and diff_runs(b"abc", b"abd") == [
        {"offset": 2, "length": 1, "kind": "diff"}]
    check("test_fastpath_dispatch_flag", ok)


def main():
    test_strip_header()
    test_load_image_strips_header()
    test_fingerprint()
    test_entropy_zero_and_high()
    test_entropy_map_and_ranges()
    test_diff_runs_basic()
    test_diff_runs_merge()
    test_diff_runs_tail_and_minlen()
    test_diff_runs_page_boundary()
    test_classify_pages_three()
    test_classify_pages_two_and_errors()
    test_summarize_and_ranges()
    test_reports()
    test_pairs_scores()
    test_find_pairs_two()
    test_find_pairs_merge()
    test_find_pairs_three_flip()
    test_refine_and_descriptor()
    test_analyze_pairs_and_report()
    test_pairs_cli_smoke()
    test_cli_smoke()

    for name, fn in (
            ("test_fastpath_entropy_equivalence",
             test_fastpath_entropy_equivalence),
            ("test_fastpath_diff_runs_equivalence",
             test_fastpath_diff_runs_equivalence),
            ("test_fastpath_classify_pages_equivalence",
             test_fastpath_classify_pages_equivalence),
            ("test_fastpath_page_classifications_equivalence",
             test_fastpath_page_classifications_equivalence),
            ("test_fastpath_printable_ratio_equivalence",
             test_fastpath_printable_ratio_equivalence),
            ("test_fastpath_dispatch_flag", test_fastpath_dispatch_flag)):
        try:
            fn()
        except SkipTest as exc:
            skip(name, str(exc))

    failed = [n for n, ok in RESULTS if not ok]
    print("\n%d/%d passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    if SKIPPED:
        print("%d skipped (NumPy 等の任意依存が未導入)" % len(SKIPPED))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
