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
import uuid
from multiprocessing import Process, Queue
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Set, Tuple, Dict
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
    NUM_WORKERS: int = 3


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
    
    The batch_id allows the flusher to acknowledge when this specific
    batch has been persisted to disk.
    """
    batch_id: str
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


class Flusher:
    """
    Single writer process that owns deduplication and disk writes.
    
    Sends acknowledgments back to workers after data is persisted,
    ensuring at-least-once delivery semantics.
    """

    def __init__(self, data_queue: Queue, ack_queue: Queue, filepath: str, state_filepath: str):
        self.data_queue = data_queue
        self.ack_queue = ack_queue
        self.filepath = filepath
        self.state_store = StateStore(state_filepath)
        self.seen_ids: Set[str] = set()
        self.buffer: List[dict] = []
        self.pending_batches: List[Batch] = []  # Batches waiting to be flushed
        self.running = True
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
        logger.info(f"Flusher loaded {count} existing IDs into memory")

    def _flush_buffer(self):
        """
        Write buffer to disk, then update state and send acks.
        
        This is the critical section: data is written to disk BEFORE
        we update the cursor in shared_state.json and send acks.
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

        # Step 2: Update cursors and send acks for completed batches
        # Group final batches by job name to update cursor once per job
        final_batches_by_job: Dict[str, Batch] = {}
        for batch in self.pending_batches:
            if batch.is_final:
                final_batches_by_job[batch.job_name] = batch

        # Update state for each completed job
        for job_name, batch in final_batches_by_job.items():
            self.state_store.release_job(job_name, batch.cursor)
            logger.info(f"Released job {job_name} with cursor {batch.cursor}")

        # Send acks for all pending batches
        for batch in self.pending_batches:
            self.ack_queue.put(batch.batch_id)

        self.pending_batches.clear()

    def run(self):
        """
        Main flusher loop.
        
        Receives Batch objects from workers, deduplicates items,
        flushes to disk, then sends acknowledgments.
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
                    item_id = item.get('id')
                    if not item_id:
                        item_id = hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()
                        item['id'] = item_id

                    if item_id not in self.seen_ids:
                        self.seen_ids.add(item_id)
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


def run_flusher(data_queue: Queue, ack_queue: Queue, filepath: str, state_filepath: str):
    """Entry point for the flusher process."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    flusher = Flusher(data_queue, ack_queue, filepath, state_filepath)
    flusher.run()


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

    async def fetch_all(self, url: str, cursor: Optional[str]) -> List[List[dict]]:
        """Fetch all pages and return as list of batches."""
        batches = []
        
        first_page = await self.fetch_page(url, 0, cursor)
        items = first_page.get('items', [])
        total = first_page.get('total', 0)

        if items:
            batches.append(items)

        if total <= config.PAGE_SIZE:
            return batches

        logger.info(f"Fetching {total} items...")

        offsets = list(range(config.PAGE_SIZE, total, config.PAGE_SIZE))

        for i in range(0, len(offsets), config.CONCURRENT_PAGES):
            batch_offsets = offsets[i:i + config.CONCURRENT_PAGES]
            tasks = [self.fetch_page(url, off, cursor) for off in batch_offsets]

            results = await asyncio.gather(*tasks)
            for res in results:
                batch_items = res.get('items', [])
                if batch_items:
                    batches.append(batch_items)

        return batches


class Worker:
    """
    API polling worker that fetches data and sends batches to the flusher.
    
    Waits for acknowledgment from flusher before considering job complete.
    This ensures data is persisted before the cursor advances.
    """

    def __init__(self, worker_id: str, data_queue: Queue, ack_queue: Queue, subscriptions: dict):
        self.worker_id = worker_id
        self.data_queue = data_queue
        self.ack_queue = ack_queue
        self.subscriptions = subscriptions
        self.state_store = StateStore(config.STATE_FILE)
        self.rate_limiter = TokenBucketRateLimiter(rpm=config.RATE_LIMIT_RPM, burst=config.RATE_LIMIT_BURST)
        self.running = True
        self.pending_acks: Dict[str, bool] = {}  # batch_id -> received

    def _check_acks(self):
        """Non-blocking check for acknowledgments from flusher."""
        while True:
            try:
                batch_id = self.ack_queue.get_nowait()
                self.pending_acks[batch_id] = True
            except:
                break

    async def _wait_for_acks(self, batch_ids: List[str], timeout: float = 60.0):
        """Wait for all batch_ids to be acknowledged."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            self._check_acks()
            if all(self.pending_acks.get(bid, False) for bid in batch_ids):
                # Clean up
                for bid in batch_ids:
                    self.pending_acks.pop(bid, None)
                return True
            await asyncio.sleep(0.1)
        return False

    async def run(self):
        """Main polling loop."""
        logger.info(f"Worker {self.worker_id} started")

        async with aiohttp.ClientSession() as session:
            client = APIClient(session, self.rate_limiter)

            while self.running:
                did_work = False

                for name, (url, interval) in self.subscriptions.items():
                    acquired, cursor = self.state_store.try_acquire_job(name, self.worker_id, interval)

                    if acquired:
                        did_work = True
                        logger.info(f"[{self.worker_id}] Job acquired: {name}")

                        try:
                            # Fetch all data first
                            batches = await client.fetch_all(url, cursor)
                            
                            if not batches:
                                # No data, release job immediately
                                next_cursor = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                                self.state_store.release_job(name, next_cursor)
                                logger.info(f"[{self.worker_id}] Job completed: {name}. No new data.")
                                continue

                            # Create batch objects and send to flusher
                            next_cursor = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                            batch_ids = []
                            
                            for i, items in enumerate(batches):
                                is_final = (i == len(batches) - 1)
                                batch = Batch(
                                    batch_id=str(uuid.uuid4()),
                                    job_name=name,
                                    items=items,
                                    cursor=next_cursor,
                                    is_final=is_final
                                )
                                batch_ids.append(batch.batch_id)
                                self.data_queue.put(batch)

                            total_items = sum(len(b) for b in batches)
                            logger.info(f"[{self.worker_id}] Sent {total_items} items in {len(batches)} batches, waiting for ack...")

                            # Wait for ALL batches to be acknowledged (data persisted)
                            acked = await self._wait_for_acks(batch_ids)
                            
                            if acked:
                                logger.info(f"[{self.worker_id}] Job completed: {name}. All data persisted.")
                            else:
                                logger.error(f"[{self.worker_id}] Job {name} timed out waiting for acks!")

                        except Exception as e:
                            logger.error(f"[{self.worker_id}] Job failed: {name}. Error: {e}")

                if not did_work:
                    await asyncio.sleep(1)

        logger.info(f"Worker {self.worker_id} stopped")

    def stop(self):
        self.running = False


def run_worker(worker_id: str, data_queue: Queue, ack_queue: Queue, subscriptions: dict):
    """Entry point for a worker process."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [%(process)d] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    worker = Worker(worker_id, data_queue, ack_queue, subscriptions)

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
    - 1 flusher process deduplicates, writes to disk, updates state, sends acks
    - Workers wait for acks before considering jobs complete
    
    This ensures at-least-once delivery: data is ALWAYS on disk before
    the cursor advances.
    """

    def __init__(self):
        self.subscriptions = {}
        self.data_queue: Queue = None
        self.ack_queue: Queue = None
        self.flusher_process: Process = None
        self.worker_processes: List[Process] = []

    def register_api(self, name: str, url: str, interval: Interval, value: int = 1):
        """Register an API endpoint for polling."""
        self.subscriptions[name] = (url, interval.value * value)

    def start(self):
        """Start the flusher and worker processes."""
        # Create shared queues
        self.data_queue = multiprocessing.Queue()
        self.ack_queue = multiprocessing.Queue()

        # Start flusher process (single writer)
        self.flusher_process = Process(
            target=run_flusher,
            args=(self.data_queue, self.ack_queue, config.LOG_FILE, config.STATE_FILE),
            name="flusher"
        )
        self.flusher_process.start()
        logger.info(f"Started flusher process (PID: {self.flusher_process.pid})")

        # Start worker processes
        for i in range(config.NUM_WORKERS):
            worker_id = f"worker-{i}"
            p = Process(
                target=run_worker,
                args=(worker_id, self.data_queue, self.ack_queue, self.subscriptions),
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
