from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .db import kpi_events_collection


async def _insert_event(event: Dict[str, Any]) -> None:
    try:
        await kpi_events_collection.insert_one(event)
    except Exception:
        # KPI events should never block the main flow
        pass


def emit_kpi_event(
    *,
    event_type: str,
    user_id: Optional[str],
    dataset_version: Optional[str] = None,
    level: Optional[str] = None,
    module_id: Optional[str] = None,
    question_index: Optional[int] = None,
    correct: Optional[bool] = None,
    latency_ms: Optional[int] = None,
    flags: Optional[List[str]] = None,
) -> None:
    payload: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "timestamp_dt": datetime.now(timezone.utc),
        "event_type": event_type,
        "user_id": user_id,
        "dataset_version": dataset_version,
        "level": level,
        "module_id": module_id,
        "question_index": question_index,
        "correct": correct,
        "latency_ms": latency_ms,
        "flags": flags or [],
    }
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_insert_event(payload))
