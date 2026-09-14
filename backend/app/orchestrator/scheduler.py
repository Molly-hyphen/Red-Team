from app.config import settings

class ScanScheduler:
    def __init__(self):
        self.max_concurrency = settings.MAX_AGENT_CONCURRENCY

    def can_spawn_agent(self, current_active: int) -> bool:
        return current_active < self.max_concurrency

scheduler = ScanScheduler()
