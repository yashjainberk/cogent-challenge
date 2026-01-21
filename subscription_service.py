import asyncio
import aiohttp
import json
import fcntl
import os
import logging
import signal
import hashlib
import time
import multiprocessing
import redis
import pickle
from multiprocessing import Process
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Set, Tuple, Dict
from contextlib import contextmanager
from collections import OrderedDict


@dataclass
class Config:
    """Central configuration for the subscription service."""
    LOG_FILE: str = "vulnerabilities.jsonl"
    STATE_FILE: str = "shared_state.json"
    PAGE_SIZE: int = 250
    CONCURRENT_PAGES: int = 2
    RATE_LIMIT_RPM: int = 20  # Per-service limit, shared across all workers via Redis
    RATE_LIMIT_BURST: int = 1
    FLUSH_BATCH_SIZE: int = 500
    NUM_WORKERS: int = 3
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379


config = Config()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SubscriptionService")


@dataclass
class Batch:
    """
    A batch of items from a single job fetch.
    
    The flusher uses is_final to know when to update the cursor in shared_state.
    """
    job_name: str
    items: List[dict]
    cursor: str  # The cursor to set after this batch is flushed
    is_final: bool = False  # True if this is the last batch for this job


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


class RedisQueue:
    """A distributed queue backed by Redis."""
    def __init__(self, redis_client: redis.Redis, name: str = "flush_queue"):
        self.redis = redis_client
        self.name = name

    def put(self, obj):
        """Put an object into the queue (RPUSH)."""
        # We use pickle to handle complex objects like Batch
        self.redis.rpush(self.name, pickle.dumps(obj))

    def get(self, timeout=None):
        """Get an object from the queue (BLPOP)."""
        # timeout in BLPOP is in seconds
        res = self.redis.blpop(self.name, timeout=int(timeout or 0))
        if res:
            return pickle.loads(res[1])
        return None

    def clear(self):
        """Clear the queue."""
        self.redis.delete(self.name)


class RedisRateLimiter:
    """
    Redis-based token bucket rate limiter shared across all workers.
    
    Uses Redis to maintain token state, ensuring the rate limit is
    respected globally across all workers polling the same service.
    """

    def __init__(self, redis_client: redis.Redis, service_name: str, rpm: int, burst: int):
        self.redis = redis_client
        self.key = f"ratelimit:{service_name}"
        self.rate = rpm / 60.0  # tokens per second
        self.capacity = burst
        self.lock = asyncio.Lock()

    async def acquire(self):
        """
        Wait until a token is available (shared across all workers).
        
        Uses Redis to atomically check and update token count.
        """
        while True:
            # Run Redis operations in thread pool to avoid blocking
            acquired = await asyncio.get_event_loop().run_in_executor(
                None, self._try_acquire
            )
            if acquired:
                return
            
            # Wait before retrying
            wait_time = 1.0 / self.rate if self.rate > 0 else 1.0
            await asyncio.sleep(wait_time)

    def _try_acquire(self) -> bool:
        """
        Atomically try to acquire a token from Redis.
        
        Uses a Lua script to ensure atomic read-modify-write.
        """
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        -- Get current state
        local state = redis.call('HMGET', key, 'tokens', 'last_update')
        local tokens = tonumber(state[1]) or capacity
        local last_update = tonumber(state[2]) or now
        
        -- Refill tokens based on elapsed time
        local elapsed = now - last_update
        tokens = math.min(capacity, tokens + elapsed * rate)
        
        -- Try to consume a token
        if tokens >= 1 then
            tokens = tokens - 1
            redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
            redis.call('EXPIRE', key, 120)  -- TTL to clean up stale keys
            return 1
        else
            -- Update last_update even if no token consumed (for accurate refill)
            redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
            redis.call('EXPIRE', key, 120)
            return 0
        end
        """
        
        now = time.time()
        result = self.redis.eval(lua_script, 1, self.key, self.capacity, self.rate, now)
        return result == 1


class RateLimiterFactory:
    """Creates per-service rate limiters backed by Redis."""
    
    def __init__(self, redis_client: redis.Redis, rpm: int, burst: int):
        self.redis = redis_client
        self.rpm = rpm
        self.burst = burst
        self._limiters: Dict[str, RedisRateLimiter] = {}
    
    def get(self, service_name: str) -> RedisRateLimiter:
        """Get or create a rate limiter for a specific service."""
        if service_name not in self._limiters:
            self._limiters[service_name] = RedisRateLimiter(
                self.redis, service_name, self.rpm, self.burst
            )
        return self._limiters[service_name]


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

    def checkpoint_cursor(self, api_name: str, cursor: str):
        """Update cursor in shared state without releasing the job claim."""
        with file_lock(self.filepath, 'r+') as f:
            try:
                state = json.loads(f.read().strip() or '{}')
            except json.JSONDecodeError:
                state = {}

            if api_name in state:
                state[api_name]['cursor'] = cursor
                self._save(f, state)

    def _save(self, f, state):
        f.seek(0)
        f.truncate()
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())


class Flusher:
    """
    Single writer process that owns deduplication, disk writes, and job completion.
    
    The flusher is the single source of truth for:
    - Deduplication (in-memory seen_ids set)
    - Disk writes (append-only log with fsync)
    - Job state (updates shared_state.json after data is persisted)
    
    This ensures crash safety: cursor only advances AFTER data is on disk.
    """

    def __init__(self, data_queue: 'RedisQueue', filepath: str, state_filepath: str):
        self.data_queue = data_queue
        self.filepath = filepath
        self.state_store = StateStore(state_filepath)
        # Use Redis for 100% accurate, distributed deduplication
        self.redis = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=True)
        self.buffer: List[dict] = []
        self.pending_batches: List[Batch] = []  # Batches waiting to be flushed
        self.running = True
        self._sync_ids_to_redis()

    def _sync_ids_to_redis(self):
        """Sync existing item IDs from log file to Redis on startup."""
        if not os.path.exists(self.filepath):
            return

        count = 0
        try:
            with open(self.filepath, 'r') as f:
                batch = []
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            # Create fingerprint from content to allow updates
                            fingerprint = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
                            batch.append(fingerprint)
                            
                            if len(batch) >= 1000:
                                self.redis.sadd("seen_fingerprints", *batch)
                                count += len(batch)
                                batch = []
                        except:
                            pass
                if batch:
                    self.redis.sadd("seen_fingerprints", *batch)
                    count += len(batch)
        except Exception as e:
            logger.error(f"Error syncing IDs to Redis: {e}")
        logger.info(f"Flusher synced {count} existing fingerprints to Redis")

    def is_duplicate(self, item: dict) -> bool:
        """
        Check if an item is an exact duplicate using a content hash.
        
        Returns True if the content has been seen before.
        Returns False for new items OR updated items (different content).
        """
        # Exclude our internal metadata before hashing
        clean_item = {k: v for k, v in item.items() if k not in ('id', '_ingested_at')}
        fingerprint = hashlib.md5(json.dumps(clean_item, sort_keys=True).encode()).hexdigest()
        
        # SADD returns 1 if added (new), 0 if already exists (duplicate)
        is_new = self.redis.sadd("seen_fingerprints", fingerprint)
        return is_new == 0

    def _flush_buffer(self):
        """
        Write buffer to disk, then update job state.
        
        Critical ordering:
        1. Write data to disk
        2. fsync to ensure durability
        3. Update cursor in shared_state.json
        
        If crash occurs before step 3, data may be re-fetched (at-least-once).
        """
        if not self.buffer:
            return

        # Step 1: Write data to disk
        with open(self.filepath, 'a') as f:
            for item in self.buffer:
                f.write(json.dumps(item) + '\n')
            f.flush()
            os.fsync(f.fileno())

        logger.info(f"Flushed {len(self.buffer)} items to disk")
        self.buffer.clear()

        # Step 2: Update cursors (Checkpointing & Job Completion)
        # Track the latest cursor for each job in this flush cycle
        job_updates: Dict[str, Tuple[str, bool]] = {}
        for batch in self.pending_batches:
            job_updates[batch.job_name] = (batch.cursor, batch.is_final)

        for job_name, (cursor, is_final) in job_updates.items():
            if is_final:
                self.state_store.release_job(job_name, cursor)
                logger.info(f"Job {job_name} completed, cursor updated to {cursor}")
            else:
                self.state_store.checkpoint_cursor(job_name, cursor)
                logger.info(f"Job {job_name} checkpointed at cursor {cursor}")

        self.pending_batches.clear()

    def run(self):
        """
        Main flusher loop.
        
        Receives Batch objects from workers, deduplicates items,
        flushes to disk, and updates job cursors.
        """
        logger.info("Flusher process started")

        while self.running:
            try:
                # Block for up to 1 second waiting for batches
                batch = self.data_queue.get(timeout=1.0)

                # Poison pill to stop the flusher
                if batch is None:
                    logger.info("Flusher received shutdown signal")
                    self._flush_buffer()
                    break

                # Process batch items
                for item in batch.items:
                    # Treat exact content duplicates as duplicates, 
                    # but allow items with the same ID but changed content (updates)
                    if not self.is_duplicate(item):
                        if 'id' not in item:
                            # Fallback ID if missing
                            item['id'] = hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()
                        
                        item['_ingested_at'] = datetime.now(timezone.utc).isoformat()
                        self.buffer.append(item)

                # Track this batch for acknowledgment
                self.pending_batches.append(batch)

                # Flush when buffer is full
                if len(self.buffer) >= config.FLUSH_BATCH_SIZE:
                    self._flush_buffer()

            except Exception:
                # Queue.get() timeout - flush any pending items
                if self.buffer:
                    self._flush_buffer()

        logger.info("Flusher process stopped")

    def stop(self):
        self.running = False


def run_flusher(filepath: str, state_filepath: str):
    """Entry point for the flusher process."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Initialize Redis connection inside the process
    redis_client = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=False)
    data_queue = RedisQueue(redis_client)
    flusher = Flusher(data_queue, filepath, state_filepath)
    flusher.run()


class APIClient:
    """HTTP client for API interactions with retries, rate limiting, and pagination."""

    def __init__(self, session: aiohttp.ClientSession, rate_limiter_factory: RateLimiterFactory):
        self.session = session
        self.limiter_factory = rate_limiter_factory

    async def fetch_page(self, url: str, offset: int, cursor: Optional[str], service_name: str) -> dict:
        """Fetch a single page with automatic retries."""
        params = {'limit': config.PAGE_SIZE, 'offset': offset}
        if cursor:
            params['updatedSince'] = cursor

        # Get per-service rate limiter
        limiter = self.limiter_factory.get(service_name)

        for attempt in range(3):
            try:
                await limiter.acquire()

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

    async def fetch_stream(self, url: str, cursor: Optional[str], service_name: str):
        """
        Stream pages as they arrive (async generator).
        
        Yields (items, total, is_last) tuples for each page.
        This allows the worker to send batches to the flusher immediately
        rather than waiting for all pages to be fetched.
        """
        first_page = await self.fetch_page(url, 0, cursor, service_name)
        items = first_page.get('items', [])
        total = first_page.get('total', 0)

        if total <= config.PAGE_SIZE:
            # Single page - yield it as the last one
            if items:
                yield items, total, True
            return

        # Multiple pages - yield first page
        if items:
            yield items, total, False

        logger.info(f"Streaming {total} items...")

        offsets = list(range(config.PAGE_SIZE, total, config.PAGE_SIZE))
        total_offsets = len(offsets)

        for i in range(0, total_offsets, config.CONCURRENT_PAGES):
            batch_offsets = offsets[i:i + config.CONCURRENT_PAGES]
            tasks = [self.fetch_page(url, off, cursor, service_name) for off in batch_offsets]

            results = await asyncio.gather(*tasks)
            
            for j, res in enumerate(results):
                batch_items = res.get('items', [])
                # Check if this is the last batch
                is_last = (i + j + 1) >= total_offsets
                if batch_items:
                    yield batch_items, total, is_last


class Worker:
    """
    API polling worker that fetches data and sends batches to the flusher.
    
    Workers are stateless fetchers - they don't track job completion.
    The flusher owns the job lifecycle and updates shared_state.json
    after data is persisted to disk.
    """

    def __init__(self, worker_id: str, subscriptions: dict):
        self.worker_id = worker_id
        self.subscriptions = subscriptions
        self.state_store = StateStore(config.STATE_FILE)
        # Redis-based rate limiting shared across all workers
        self.redis_client = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=True)
        # Separate client for binary queue operations
        self.redis_binary = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=False)
        self.data_queue = RedisQueue(self.redis_binary)
        self.rate_limiter_factory = RateLimiterFactory(
            self.redis_client, 
            rpm=config.RATE_LIMIT_RPM, 
            burst=config.RATE_LIMIT_BURST
        )
        self.running = True

    async def run(self):
        """Main polling loop."""
        logger.info(f"Worker {self.worker_id} started")

        async with aiohttp.ClientSession() as session:
            client = APIClient(session, self.rate_limiter_factory)

            while self.running:
                did_work = False

                for name, (url, interval) in self.subscriptions.items():
                    acquired, cursor = self.state_store.try_acquire_job(name, self.worker_id, interval)

                    if acquired:
                        did_work = True
                        logger.info(f"[{self.worker_id}] Job acquired: {name}")

                        try:
                            next_cursor = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                            total_items = 0
                            batch_count = 0
                            has_data = False

                            # Stream pages and send to flusher immediately as they arrive
                            async for items, total, is_last in client.fetch_stream(url, cursor, name):
                                has_data = True
                                batch = Batch(
                                    job_name=name,
                                    items=items,
                                    cursor=next_cursor,
                                    is_final=is_last
                                )
                                self.data_queue.put(batch)
                                total_items += len(items)
                                batch_count += 1
                                logger.info(f"[{self.worker_id}] Sent batch {batch_count} ({len(items)} items) to flusher")

                            if not has_data:
                                # No data, release job immediately (flusher won't see this job)
                                self.state_store.release_job(name, next_cursor)
                                logger.info(f"[{self.worker_id}] Job completed: {name}. No new data.")
                                continue

                            # Flusher will update shared_state.json after persisting data
                            logger.info(f"[{self.worker_id}] Sent all {total_items} items in {batch_count} batches to flusher")

                        except Exception as e:
                            logger.error(f"[{self.worker_id}] Job failed: {name}. Error: {e}")

                if not did_work:
                    await asyncio.sleep(1)

        logger.info(f"Worker {self.worker_id} stopped")

    def stop(self):
        self.running = False


def run_worker(worker_id: str, subscriptions: dict):
    """Entry point for a worker process."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    worker = Worker(worker_id, subscriptions)

    def handle_sig(signum, frame):
        logger.info(f"Worker {worker_id} received shutdown signal")
        worker.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    asyncio.run(worker.run())


class SubscriptionService:
    """
    Main service orchestrating workers and the flusher.
    
    Architecture:
    - N worker processes fetch from APIs and send Batch objects to data_queue
    - 1 flusher process deduplicates, writes to disk, and updates job cursors
    
    The flusher owns the job lifecycle - it updates shared_state.json AFTER
    data is persisted to disk, ensuring at-least-once delivery.
    """

    def __init__(self):
        self.subscriptions = {}
        self.flusher_process: Process = None
        self.worker_processes: List[Process] = []
        # Shared Redis connection for queue cleanup
        self.redis = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT)
        self.data_queue = RedisQueue(self.redis)

    def register_api(self, name: str, url: str, interval: Interval, value: int = 1):
        """Register an API endpoint for polling."""
        self.subscriptions[name] = (url, interval.value * value)

    def start(self):
        """Start the flusher and worker processes."""
        # Clear shared queue from previous runs
        self.data_queue.clear()

        # Start flusher process (single writer, owns job state)
        self.flusher_process = Process(
            target=run_flusher,
            args=(config.LOG_FILE, config.STATE_FILE),
            name="flusher"
        )
        self.flusher_process.start()
        logger.info(f"Started flusher process (PID: {self.flusher_process.pid})")

        # Start worker processes
        for i in range(config.NUM_WORKERS):
            worker_id = f"worker-{i}"
            p = Process(
                target=run_worker,
                args=(worker_id, self.subscriptions),
                name=worker_id
            )
            p.start()
            self.worker_processes.append(p)
            logger.info(f"Started {worker_id} (PID: {p.pid})")

    def stop(self):
        """Gracefully stop all processes."""
        logger.info("Stopping all workers...")

        # Stop workers first
        for p in self.worker_processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)

        # Send poison pill to flusher to trigger final flush
        if self.data_queue:
            self.data_queue.put(None)

        # Wait for flusher to finish
        if self.flusher_process and self.flusher_process.is_alive():
            self.flusher_process.join(timeout=10)

        logger.info("All processes stopped")

    def wait(self):
        """Wait for all processes to complete."""
        try:
            while True:
                for p in self.worker_processes:
                    if not p.is_alive():
                        logger.warning(f"Worker {p.name} died unexpectedly")

                if not self.flusher_process.is_alive():
                    logger.error("Flusher died unexpectedly!")
                    break

                time.sleep(1)
        except KeyboardInterrupt:
            pass


def main():
    """Entry point with graceful shutdown handling."""
    service = SubscriptionService()

    service.register_api("qualys", "https://api.cogent.security/sandbox/qualys/vulnerabilities", Interval.HOUR, 4)
    service.register_api("rapid7", "https://api.cogent.security/sandbox/rapid7/vulnerabilities", Interval.HOUR, 4)
    service.register_api("tenable", "https://api.cogent.security/sandbox/tenable/vulnerabilities", Interval.HOUR, 4)

    def handle_shutdown(signum, frame):
        logger.info("Shutdown signal received")
        service.stop()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    service.start()
    service.wait()


if __name__ == "__main__":
    main()
