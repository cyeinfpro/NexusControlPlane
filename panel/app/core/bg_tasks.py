from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Awaitable, Set

logger = logging.getLogger(__name__)

_BACKGROUND_TASKS: Set[asyncio.Task[Any]] = set()
_BACKGROUND_TASKS_LOCK = threading.Lock()


def spawn_background_task(coro: Awaitable[Any], *, label: str = "background") -> asyncio.Task[Any]:
    """Create and retain a background task until completion."""
    task = asyncio.create_task(coro)
    with _BACKGROUND_TASKS_LOCK:
        _BACKGROUND_TASKS.add(task)

    def _done(t: asyncio.Task[Any]) -> None:
        with _BACKGROUND_TASKS_LOCK:
            _BACKGROUND_TASKS.discard(t)
        try:
            t.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("%s task crashed", str(label or "background"))

    task.add_done_callback(_done)
    return task
