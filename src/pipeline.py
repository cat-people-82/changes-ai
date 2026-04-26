"""Typed pipeline stage boundaries for the Phase 2 execution model."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

StageName = Literal[
    "discovery",
    "graph",
    "currency",
    "cves",
    "usage",
    "impact",
    "remediation",
    "report",
]


@dataclass
class StageResult:
    """Result envelope for one pipeline stage."""

    stage: StageName
    artifact: Any
    started_at: int
    completed_at: int
    status: str = "completed"
    error: str | None = None


@dataclass
class PipelineRun:
    """In-memory representation of one orchestrated run."""

    run_id: int | None = None
    stages: list[StageResult] = field(default_factory=list)

    def artifact(self, stage: StageName) -> Any | None:
        for result in reversed(self.stages):
            if result.stage == stage and result.status == "completed":
                return result.artifact
        return None


class PipelineOrchestrator:
    """Minimal stage runner used as the boundary for future cached stages."""

    def __init__(self, run_id: int | None = None) -> None:
        self.run = PipelineRun(run_id=run_id)

    def run_stage(self, stage: StageName, fn: Callable[[], Any]) -> StageResult:
        started = int(time.time())
        try:
            artifact = fn()
        except Exception as exc:
            completed = int(time.time())
            result = StageResult(
                stage=stage,
                artifact=None,
                started_at=started,
                completed_at=completed,
                status="failed",
                error=str(exc),
            )
            self.run.stages.append(result)
            raise

        completed = int(time.time())
        result = StageResult(
            stage=stage,
            artifact=artifact,
            started_at=started,
            completed_at=completed,
        )
        self.run.stages.append(result)
        return result
