"""dumpdiff — 複数時点メモリダンプ比較ツールキット。

ページ単位のエントロピー分析、ダンプ間の差分ラン列挙、
複数時点ダンプのページ分類(static/flip/settled/volatile)を提供する。
"""
from .diffruns import classify_pages, diff_runs, label_ranges, summarize
from .entropy import entropy_map, high_entropy_ranges, shannon_entropy
from .images import fingerprint, load_image, strip_header

__version__ = "0.1.0"

__all__ = [
    "classify_pages", "diff_runs", "entropy_map", "fingerprint",
    "high_entropy_ranges", "label_ranges", "load_image", "shannon_entropy",
    "strip_header", "summarize", "__version__",
]
