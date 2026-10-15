import asyncio
from collections import defaultdict
from typing import Any


class EventHub:
    def __init__(self) -> None:
        self._queues: dict[int, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)

    async def publish(self, scan_id: int, event: dict[str, Any]) -> None:
        for queue in list(self._queues[scan_id]):
            await queue.put(event)

    def subscribe(self, scan_id: int) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._queues[scan_id].add(queue)
        return queue

    def unsubscribe(self, scan_id: int, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._queues[scan_id].discard(queue)


event_hub = EventHub()

