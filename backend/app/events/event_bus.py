import asyncio
from typing import Callable, Dict, List, Set
from app.events.events import ScanEventMessage, EventType

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {} # scan_id -> Set of websocket/listener queues
        self._global_subscribers: Set[asyncio.Queue] = set()
        self._callbacks: Dict[EventType, List[Callable]] = {}

    def subscribe_scan(self, scan_id: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = set()
        self._subscribers[scan_id].add(queue)
        return queue

    def unsubscribe_scan(self, scan_id: str, queue: asyncio.Queue):
        if scan_id in self._subscribers and queue in self._subscribers[scan_id]:
            self._subscribers[scan_id].remove(queue)
            if not self._subscribers[scan_id]:
                del self._subscribers[scan_id]

    def subscribe_global(self) -> asyncio.Queue:
        queue = asyncio.Queue()
        self._global_subscribers.add(queue)
        return queue

    def unsubscribe_global(self, queue: asyncio.Queue):
        if queue in self._global_subscribers:
            self._global_subscribers.remove(queue)

    def register_callback(self, event_type: EventType, callback: Callable):
        if event_type not in self._callbacks:
            self._callbacks[event_type] = []
        self._callbacks[event_type].append(callback)

    async def publish(self, event: ScanEventMessage):
        # Dispatch to scan-specific queues
        if event.scan_id in self._subscribers:
            for queue in list(self._subscribers[event.scan_id]):
                try:
                    await queue.put(event)
                except Exception:
                    pass

        # Dispatch to global queues
        for queue in list(self._global_subscribers):
            try:
                await queue.put(event)
            except Exception:
                pass

        # Run registered callbacks
        if event.event_type in self._callbacks:
            for cb in self._callbacks[event.event_type]:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        asyncio.create_task(cb(event))
                    else:
                        cb(event)
                except Exception as e:
                    print(f"Error in event callback: {e}")

event_bus = EventBus()
