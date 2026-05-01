from __future__ import annotations

from pathlib import Path
import sys

from .base import (
    ApplyOutcome,
    CurrencyRecord,
    EcosystemAdapter,
    GraphEdge,
    ManifestInfo,
    Package,
    UsageRecord,
    UsageResult,
)
from .npm_adapter import NpmAdapter
from .python_adapter import PythonAdapter

REGISTRY: dict[str, EcosystemAdapter] = {
    "python": PythonAdapter(),
    "npm": NpmAdapter(),
}


def detect_adapter(source: Path) -> EcosystemAdapter | None:
    """Return the best-matching adapter for *source*."""
    source = Path(source)
    matches: list[tuple[int, int, EcosystemAdapter]] = []
    for index, adapter in enumerate(REGISTRY.values()):
        manifest = adapter.find_manifest(source)
        if manifest is None:
            continue
        try:
            depth = len(manifest.path.relative_to(source).parts)
        except ValueError:
            depth = len(manifest.path.parts)
        matches.append((depth, index, adapter))
    if not matches:
        return None
    matches.sort(key=lambda item: (item[0], item[1]))
    best_depth = matches[0][0]
    best_matches = [item for item in matches if item[0] == best_depth]
    if len(best_matches) > 1:
        adapters = ", ".join(item[2].name for item in best_matches)
        print(
            f"Warning: multiple ecosystems detected at {source} ({adapters}); "
            "defaulting to python by registry order. Use --ecosystem to override.",
            file=sys.stderr,
        )
    return matches[0][2]


__all__ = [
    "ApplyOutcome",
    "CurrencyRecord",
    "EcosystemAdapter",
    "GraphEdge",
    "ManifestInfo",
    "NpmAdapter",
    "Package",
    "PythonAdapter",
    "REGISTRY",
    "UsageRecord",
    "UsageResult",
    "detect_adapter",
]
