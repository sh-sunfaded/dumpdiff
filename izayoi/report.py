"""レポート生成(Markdown / JSON)。"""
from __future__ import annotations

import json
import os

from .diffruns import classify_pages, diff_runs, label_ranges, summarize
from .entropy import high_entropy_ranges
from .images import fingerprint, load_image
from .pairs import analyze_pairs

DEFAULT_PAGE = 0x1000


def _fmt_ranges(ranges, limit=None):
    lines = []
    for start, end, *rest in (ranges[:limit] if limit else ranges):
        tail = "  max=%.2f" % rest[0] if rest else ""
        lines.append("- `0x%08x`-`0x%08x` (%d bytes)%s"
                     % (start, end, end - start, tail))
    return lines


def collect(paths, page=DEFAULT_PAGE, merge_gap=16, threshold=7.0, top=10):
    """全解析結果を dict として収集する(JSON 出力の実体)。"""
    names = [os.path.basename(p) for p in paths]
    images = [load_image(p) for p in paths]

    info = {
        "images": [{"name": n, **fingerprint(img)}
                   for n, img in zip(names, images)],
        "page": page,
        "high_entropy": {},
        "diff_runs": {},
        "classification": None,
    }
    for n, img in zip(names, images):
        info["high_entropy"][n] = [
            {"start": s, "end": e, "max_entropy": round(m, 4)}
            for s, e, m in high_entropy_ranges(img, threshold, page)]

    for i in range(len(images)):
        for j in range(i + 1, len(images)):
            key = "%s vs %s" % (names[i], names[j])
            runs = diff_runs(images[i], images[j], merge_gap=merge_gap)
            total = sum(r["length"] for r in runs)
            info["diff_runs"][key] = {
                "merge_gap": merge_gap,
                "run_count": len(runs),
                "total_bytes": total,
                "top": [
                    {"offset": r["offset"], "length": r["length"],
                     "kind": r["kind"]}
                    for r in runs[:top]],
            }

    if len(images) >= 2:
        items = classify_pages(images, page)
        info["classification"] = {
            "summary": {k: list(v) for k, v in summarize(items, page).items()},
            "ranges": {k: [list(r) for r in v]
                       for k, v in label_ranges(items, page).items()},
        }

    if 2 <= len(images) <= 3:
        cands = analyze_pairs(images, names, page=page)
        info["pairs"] = [
            {"start": c["start"], "end": c["end"], "pages": c["pages"],
             "basis": c["basis"],
             "cipher": c["cipher_name"], "cipher_entropy": c["cipher_entropy"],
             "plain": c["plain_name"], "plain_entropy": c["plain_entropy"],
             "plain_kind": c["plain_kind"],
             "refined_start": c["refined_start"],
             "refined_end": c["refined_end"],
             "descriptor": c["descriptor"]}
            for c in cands]
    return info


def json_report(paths, **kw):
    return json.dumps(collect(paths, **kw), indent=2, ensure_ascii=False)


def markdown_report(paths, page=DEFAULT_PAGE, merge_gap=16,
                    threshold=7.0, top=10):
    """解析結果を1本のMarkdownレポートにする。"""
    info = collect(paths, page=page, merge_gap=merge_gap,
                   threshold=threshold, top=top)
    lines = ["# izayoi レポート", ""]

    lines += ["## イメージ", "",
              "| 名前 | サイズ | md5 | 全体エントロピー |",
              "| --- | --- | --- | --- |"]
    for im in info["images"]:
        lines.append("| `%s` | %d | `%s` | %.3f |"
                      % (im["name"], im["size"], im["md5"], im["entropy"]))
    lines.append("")

    lines += ["## 高エントロピー領域 (>= %.2f)" % threshold, ""]
    for name, ranges in info["high_entropy"].items():
        lines.append("`%s`: %d 領域" % (name, len(ranges)))
        for r in ranges[:top]:
            lines.append("- `0x%08x`-`0x%08x` (%d bytes) max=%.2f"
                         % (r["start"], r["end"], r["end"] - r["start"],
                            r["max_entropy"]))
    lines.append("")

    lines += ["## 差分ラン", ""]
    for key, d in info["diff_runs"].items():
        lines.append("`%s`: %d ラン / %d bytes (merge_gap=%d)"
                     % (key, d["run_count"], d["total_bytes"],
                        d["merge_gap"]))
        for r in d["top"]:
            lines.append("- `0x%08x` len=%d kind=%s"
                         % (r["offset"], r["length"], r["kind"]))
    lines.append("")

    if info["classification"]:
        lines += ["## ページ分類", ""]
        for label, (npages, nbytes) in info["classification"]["summary"].items():
            lines.append("- **%s**: %d ページ / %d bytes"
                         % (label, npages, nbytes))
        lines.append("")
        for label, ranges in info["classification"]["ranges"].items():
            lines.append("`%s`:" % label)
            for s, e in ranges[:top]:
                lines.append("- `0x%08x`-`0x%08x` (%d bytes)"
                             % (s, e, e - s))
            lines.append("")

    for key in ("pairs",):
        if info.get(key):
            lines += ["## 暗文↔平文対候補", ""]
            for c in info[key]:
                lines.append(
                    "- `0x%08x`-`0x%08x` (%d pages, %s): "
                    "cipher=`%s` (ent %.2f) / plain=`%s` (ent %.2f, %s)"
                    % (c["start"], c["end"], c["pages"], c["basis"],
                       c["cipher"], c["cipher_entropy"],
                       c["plain"], c["plain_entropy"], c["plain_kind"]))
                lines.append("  - refined: `0x%08x`-`0x%08x`"
                             % (c["refined_start"], c["refined_end"]))
                lines.append("  - desc (推定): `%s`" % c["descriptor"])
            lines.append("")

    return "\n".join(lines)
