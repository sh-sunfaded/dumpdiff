"""izayoi コマンドライン。

使い方: python -m izayoi.cli <cmd> ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .diffruns import classify_pages, diff_runs, label_ranges, summarize
from .entropy import high_entropy_ranges
from .images import load_image
from .pairs import analyze_pairs
from .report import json_report, markdown_report


def _int(s: str) -> int:
    return int(s, 0)


def _cmd_entropy(args) -> int:
    data = load_image(args.image)
    ranges = high_entropy_ranges(data, args.threshold, args.page)
    if not ranges:
        print("高エントロピー領域なし (threshold=%.2f)" % args.threshold)
        return 0
    print("%d 領域 (threshold=%.2f, page=0x%x):"
          % (len(ranges), args.threshold, args.page))
    for start, end, mx in ranges:
        print("  0x%08x-0x%08x  %6d bytes  max=%.2f"
              % (start, end, end - start, mx))
    return 0


def _cmd_diff(args) -> int:
    a, b = load_image(args.a), load_image(args.b)
    runs = diff_runs(a, b, merge_gap=args.merge_gap, min_length=args.min_length)
    if not runs:
        print("差分なし")
        return 0
    total = sum(r["length"] for r in runs)
    print("%d ラン / %d bytes (merge_gap=%d, min_length=%d):"
          % (len(runs), total, args.merge_gap, args.min_length))
    for r in runs[:args.limit]:
        print("  0x%08x  %8d  %s" % (r["offset"], r["length"], r["kind"]))
    if len(runs) > args.limit:
        print("  ... ほか %d ラン" % (len(runs) - args.limit))
    return 0


def _cmd_compare(args) -> int:
    images = [load_image(p) for p in args.images]
    items = classify_pages(images, args.page)
    acc = summarize(items, args.page)
    print("ページ分類 (page=0x%x):" % args.page)
    for label, (npages, nbytes) in acc.items():
        print("  %-8s %5d ページ / %8d bytes" % (label, npages, nbytes))
    if args.ranges:
        print("領域一覧:")
        for label, ranges in label_ranges(items, args.page).items():
            for s, e in ranges:
                print("  %-8s 0x%08x-0x%08x (%d bytes)"
                      % (label, s, e, e - s))
    return 0


def _cmd_pairs(args) -> int:
    names = [os.path.basename(p) for p in args.images]
    images = [load_image(p) for p in args.images]
    cands = analyze_pairs(
        images, names, page=args.page, cipher_entropy=args.cipher_entropy,
        entropy_gap=args.entropy_gap, merge_gap=args.merge_gap)
    if args.json:
        print(json.dumps(cands, indent=2, ensure_ascii=False))
        return 0
    if not cands:
        print("暗文↔平文対候補なし")
        return 0
    print("%d 候補:" % len(cands))
    for c in cands[:args.limit]:
        print("0x%08x-0x%08x (%d pages, basis=%s)"
              % (c["start"], c["end"], c["pages"], c["basis"]))
        print("  cipher=%s (ent %.2f)  plain=%s (ent %.2f, %s)"
              % (c["cipher_name"], c["cipher_entropy"],
                 c["plain_name"], c["plain_entropy"], c["plain_kind"]))
        print("  refined: 0x%08x-0x%08x"
              % (c["refined_start"], c["refined_end"]))
        print("  desc (推定): %s" % c["descriptor"])
    if len(cands) > args.limit:
        print("  ... ほか %d 候補" % (len(cands) - args.limit))
    return 0


def _cmd_report(args) -> int:
    if args.json:
        out = json_report(
            args.images, page=args.page, merge_gap=args.merge_gap,
            threshold=args.threshold, top=args.top)
    else:
        out = markdown_report(
            args.images, page=args.page, merge_gap=args.merge_gap,
            threshold=args.threshold, top=args.top)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("%s に書き出しました (%d bytes)" % (args.out, len(out)))
    else:
        print(out)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="izayoi",
        description="複数時点メモリダンプ比較ツールキット")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("entropy", help="ページ単位エントロピーと高エントロピー領域")
    sp.add_argument("image")
    sp.add_argument("--page", type=_int, default=0x1000)
    sp.add_argument("--threshold", type=float, default=7.0)
    sp.set_defaults(func=_cmd_entropy)

    sp = sub.add_parser("diff", help="2ダンプ間の差分ラン列挙")
    sp.add_argument("a")
    sp.add_argument("b")
    sp.add_argument("--merge-gap", type=_int, default=0)
    sp.add_argument("--min-length", type=_int, default=1)
    sp.add_argument("--limit", type=_int, default=50)
    sp.set_defaults(func=_cmd_diff)

    sp = sub.add_parser("compare", help="2〜3ダンプのページ分類")
    sp.add_argument("images", nargs="+")
    sp.add_argument("--page", type=_int, default=0x1000)
    sp.add_argument("--ranges", action="store_true",
                    help="ラベルごとの連続領域も表示")
    sp.set_defaults(func=_cmd_compare)

    sp = sub.add_parser("pairs", help="暗文↔平文ページ対の推定(記述子形式で出力)")
    sp.add_argument("images", nargs="+")
    sp.add_argument("--page", type=_int, default=0x1000)
    sp.add_argument("--cipher-entropy", type=float, default=7.0)
    sp.add_argument("--entropy-gap", type=float, default=0.5)
    sp.add_argument("--merge-gap", type=_int, default=16)
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--limit", type=_int, default=20)
    sp.set_defaults(func=_cmd_pairs)

    sp = sub.add_parser("report", help="Markdown/JSON レポート生成")
    sp.add_argument("images", nargs="+")
    sp.add_argument("--out", default=None)
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--page", type=_int, default=0x1000)
    sp.add_argument("--merge-gap", type=_int, default=16)
    sp.add_argument("--threshold", type=float, default=7.0)
    sp.add_argument("--top", type=_int, default=10)
    sp.set_defaults(func=_cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
