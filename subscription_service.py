import asyncio
import aiohttp
import json
import fcntl
import os
import logging
import signal
import hashlib
import time
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Set, Tuple
from contextlib import contextmanager


@dataclass
class Config:
    """Central configuration for the subscription service."""
    LOG_FILE: str = "vulnerabilities.jsonl"
    STATE_FILE: str = "shared_state.json"
    PAGE_SIZE: int = 250
    CONCURRENT_PAGES: int = 2
    RATE_LIMIT_RPM: int = 20
    RATE_LIMIT_BURST: int = 1
    FLUSH_BATCH_SIZE: int = 500


config = Config()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SubscriptionService")


class Interval(Enum):
    """Supported polling intervals."""
    MINUTE = 60
    HOUR = 3600
    DAY = 86400


@contextmanager
def file_lock(filepath: str, mode: str = 'r+'):
    """Cross-process file locking using fcntl."""
    if not os.path.exists(filepath):
        with open(filepath, 'w') as f:
            f.write('{}' if filepath.endswith('.json') else '')

    f = open(filepath, mode)
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield f
    finally:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


class TokenBucketRateLimiter:
    """Token bucket rate limiter for controlling API request rates."""

    def __init__(self, rpm: int, burst: int):
        self.rate = rpm / 60.0
        self.capacity = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a token is available."""
        async with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_update = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)


class StateStore:
    """Manages distributed state and job coordination across workers."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def try_acquire_job(self, api_name: str, worker_id: str, interval: int) -> Tuple[bool, Optional[str]]:
        """Attempt to claim an API polling job. Returns (acquired, cursor)."""
        now = datetime.now(timezone.utc).timestamp()

        with file_lock(self.filepath, 'r+') as f:
            try:
                state = json.loads(f.read().strip() or '{}')
            except json.JSONDecodeError:
                state = {}

            api_state = state.get(api_name, {})
            last_poll = api_state.get('last_poll', 0)
            claimed_by = api_state.get('claimed_by')
            claimed_at = api_state.get('claimed_at', 0)

            is_due = (now - last_poll) >= interval
            is_stale = claimed_by and (now - claimed_at) > 600

            if is_due and (not claimed_by or is_stale):
                api_state.update({
                    'claimed_by': worker_id,
                    'claimed_at': now
                })
                state[api_name] = api_state
                self._save(f, state)
                return True, api_state.get('cursor')

            return False, None

    def release_job(self, api_name: str, next_cursor: str):
        """Release job claim and update cursor for next poll."""
        with file_lock(self.filepath, 'r+') as f:
            state = json.loads(f.read().strip() or '{}')
            state[api_name].update({
                'claimed_by': None,
                'claimed_at': None,
                'last_poll': datetime.now(timezone.utc).timestamp(),
                'cursor': next_cursor
            })
            self._save(f, state)

    def _save(self, f, state):
        f.seek(0)
        f.truncate()
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())


class LogStore:
    """Append-only log with in-memory deduplication."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.seen_ids: Set[str] = set()
        self.buffer: List[dict] = []
        self._load_existing_ids()

    def _load_existing_ids(self):
        """Load existing item IDs from log file into memory."""
        if not os.path.exists(self.filepath):
            return

        count = 0
        try:
            with open(self.filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'id' in data:
                                self.seen_ids.add(data['id'])
                                count += 1
                        except:
                            pass
        except Exception as e:
            logger.error(f"Error loading IDs: {e}")
        logger.info(f"Loaded {count} existing IDs into memory")

    def add(self, items: List[dict]) -> int:
        """Add items to buffer, filtering duplicates. Returns count of new items."""
        added = 0
        for item in items:
            if 'id' not in item:
                item['id'] = hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()

            if item['id'] not in self.seen_ids:
                self.seen_ids.add(item['id'])
                item['_ingested_at'] = datetime.now(timezone.utc).isoformat()
                self.buffer.append(item)
                added += 1

        if len(self.buffer) >= config.FLUSH_BATCH_SIZE:
            self.flush()
        return added

    def flush(self):
        """Flush buffer to disk with file locking."""
        if not self.buffer:
            return

        with file_lock(self.filepath, 'a') as f:
            for item in self.buffer:
                f.write(json.dumps(item) + '\n')
            f.flush()
            os.fsync(f.fileno())

        self.buffer.clear()


class APIClient:
    """HTTP client for API interactions with retries, rate limiting, and pagination."""

    def __init__(self, session: aiohttp.ClientSession, rate_limiter: TokenBucketRateLimiter):
        self.session = session
        self.limiter = rate_limiter

    async def fetch_page(self, url: str, offset: int, cursor: Optional[str]) -> dict:
        """Fetch a single page with automatic retries."""
        params = {'limit': config.PAGE_SIZE, 'offset': offset}
        if cursor:
            params['updatedSince'] = cursor

        for attempt in range(3):
            try:
                await self.limiter.acquire()

                async with self.session.get(url, params=params, timeout=30) as resp:
                    if resp.status == 429:
                        wait = int(resp.headers.get('Retry-After', 2 ** attempt))
                        logger.warning(f"Rate limited. Waiting {wait}s")
                        await asyncio.sleep(wait)
                        continue

                    resp.raise_for_status()
                    return await resp.json()
            except Exception as e:
                logger.error(f"Fetch failed (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

        return {'items': [], 'total': 0}

    async def fetch_stream(self, url: str, cursor: Optional[str]):
        """Stream paginated data, yielding batches as they arrive."""
        first_page = await self.fetch_page(url, 0, cursor)
        items = first_page.get('items', [])
        total = first_page.get('total', 0)

        if items:
            yield items

        if total <= config.PAGE_SIZE:
            return

        logger.info(f"Streaming {total} items...")

        offsets = list(range(config.PAGE_SIZE, total, config.PAGE_SIZE))

        for i in range(0, len(offsets), config.CONCURRENT_PAGES):
            batch = offsets[i:i + config.CONCURRENT_PAGES]
            tasks = [self.fetch_page(url, off, cursor) for off in batch]

            results = await asyncio.gather(*tasks)
            for res in results:
                batch_items = res.get('items', [])
                if batch_items:
                    yield batch_items


class SubscriptionService:
    """Main service orchestrating API polling, deduplication, and persistence."""

    def __init__(self):
        self.worker_id = f"worker-{os.getpid()}"
        self.state_store = StateStore(config.STATE_FILE)
        self.log_store = LogStore(config.LOG_FILE)
        self.rate_limiter = TokenBucketRateLimiter(rpm=config.RATE_LIMIT_RPM, burst=config.RATE_LIMIT_BURST)
        self.subscriptions = {}
        self.running = True

    def register_api(self, name: str, url: str, interval: Interval, value: int = 1):
        """Register an API endpoint for polling."""
        self.subscriptions[name] = (url, interval.value * value)

    async def run(self):
        """Main polling loop."""
        logger.info(f"Starting {self.worker_id}")

        async with aiohttp.ClientSession() as session:
            client = APIClient(session, self.rate_limiter)

            while self.running:
                did_work = False

                for name, (url, interval) in self.subscriptions.items():
                    acquired, cursor = self.state_store.try_acquire_job(name, self.worker_id, interval)

                    if acquired:
                        did_work = True
                        logger.info(f"Job acquired: {name}")

                        try:
                            total_ingested = 0
                            async for batch in client.fetch_stream(url, cursor):
                                added = self.log_store.add(batch)
                                self.log_store.flush()
                                total_ingested += added

                            next_cursor = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                            self.state_store.release_job(name, next_cursor)

                            logger.info(f"Job completed: {name}. Ingested: {total_ingested}")
                        except Exception as e:
                            logger.error(f"Job failed: {name}. Error: {e}")

                if not did_work:
                    await asyncio.sleep(1)

    def stop(self):
        """Signal the service to stop."""
        self.running = False


async def main():
    """Entry point with graceful shutdown handling."""
    service = SubscriptionService()

    service.register_api("qualys", "https://api.cogent.security/sandbox/qualys/vulnerabilities", Interval.HOUR, 4)
    service.register_api("rapid7", "https://api.cogent.security/sandbox/rapid7/vulnerabilities", Interval.HOUR, 4)
    service.register_api("tenable", "https://api.cogent.security/sandbox/tenable/vulnerabilities", Interval.HOUR, 4)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def handle_sig():
        logger.info("Shutdown signal received")
        service.stop()
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, handle_sig)
    loop.add_signal_handler(signal.SIGTERM, handle_sig)

    task = asyncio.create_task(service.run())
    await stop_event.wait()
    await task


if __name__ == "__main__":
    asyncio.run(main())
