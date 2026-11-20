"""izayoi — 複数時点メモリダンプ比較ツールキット。

ページ単位のエントロピー分析、ダンプ間の差分ラン列挙、
複数時点ダンプのページ分類(static/flip/settled/volatile)、
暗文↔平文ページ対の推定、ダンプのトリアージ
(PEヘッダ検出・読みやすい資産の所在推定)を提供する。
標準ライブラリのみで動作し、NumPy が導入されていれば
ホットパスが自動的にベクトル化実装に切り替わる(fastpath)。
"""
from .diffruns import classify_pages, diff_runs, label_ranges, summarize
from .entropy import entropy_map, high_entropy_ranges, shannon_entropy
from .images import fingerprint, load_image, strip_header
from .pairs import (analyze_pairs, code_density, descriptor_suggestion,
                    find_pairs, page_class, printable_ratio,
                    refine_with_diffs, zero_ratio)
from .triage import (detect_pe, page_census, readability_ranking,
                     readable_sources, region_info, triage, triage_images)

__version__ = "0.5.2"

__all__ = [
    "analyze_pairs", "classify_pages", "code_density", "detect_pe",
    "descriptor_suggestion", "diff_runs", "entropy_map", "fingerprint",
    "find_pairs", "high_entropy_ranges", "label_ranges", "load_image",
    "page_class", "page_census", "printable_ratio", "readability_ranking",
    "readable_sources", "refine_with_diffs", "region_info", "shannon_entropy",
    "strip_header", "summarize", "triage", "triage_images", "zero_ratio",
    "__version__",
]
