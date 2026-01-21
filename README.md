# Vulnerability Subscription Service

A horizontally scalable polling service for ingesting vulnerability data from multiple third-party APIs (Qualys, Rapid7, Tenable) into an append-only log.

## Features

-   **Scalable Distributed Architecture**: Workers and flushers communicate via a shared Redis Queue, allowing for multi-machine scaling.
-   **Distributed Job Coordination**: File-based locking (fcntl) ensures APIs are polled reliably without overlap.
-   **Redis-Based Rate Limiting**: Per-service token-bucket rate limits shared across all workers (global 20 RPM per service).
-   **100% Accurate Deduplication**: Redis-backed content fingerprinting prevents duplicates even for updated items and across restarts.
-   **Checkpointing & Crash Safety**: Intermediate cursors are saved to `shared_state.json` after every disk flush, allowing long-running jobs to resume without data loss.
-   **Data Durability**: 
    -   Append-only JSON Lines log with `fsync` on every batch flush.
    -   Atomic state updates ensure cursor only advances after data is physically on disk.

## Prerequisites

-   Python 3.11+
-   Redis server (used for Queue, Deduplication, and Rate Limiting)

### Start Redis

```bash
docker run -d --name redis-stack -p 6379:6379 -p 8001:8001 redis/redis-stack:latest
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the service (spawns 3 workers + 1 flusher by default):

```bash
python subscription_service.py
```

Run the test suite:

```bash
pytest test_subscription_service.py
```

## Architecture

The system uses a distributed producer-consumer model coordinated by Redis.

```text
┌──────────────┐
│   Worker 0   │──┐
│ (qualys)     │  │      ┌──────────────────┐
└──────────────┘  │      │   Redis Queue    │      ┌─────────────┐
┌──────────────┐  │      │ (RPUSH / BLPOP)  │      │   Flusher   │──▶ vulnerabilities.jsonl
│   Worker 1   │──┼─────▶│  [Shared Job]    │─────▶│ (Single)    │──▶ shared_state.json (Checkpoint)
│ (rapid7)     │  │      └──────────────────┘      └─────────────┘
└──────────────┘  │               ▲                       │
┌──────────────┐  │               │                       │
│   Worker 2   │──┘               │                       │
│ (tenable)    │                  │                       │
└──────────────┘                  ▼                       ▼
       │                 ┌──────────────────┐    ┌──────────────────┐
       └────────────────▶│      Redis       │◀───┤   Redis Set      │
                         │ (Rate Limiting)  │    │ (Deduplication)  │
                         └──────────────────┘    └──────────────────┘
```

## Configuration

Edit the `Config` class in `subscription_service.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RATE_LIMIT_RPM` | 20 | Requests per minute per service |
| `NUM_WORKERS` | 3 | Number of worker processes |
| `FLUSH_BATCH_SIZE` | 500 | Items buffered before flushing to disk |
| `REDIS_HOST` | localhost | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `LOG_FILE` | vulnerabilities.jsonl | Path to the append-only data log |
| `STATE_FILE` | shared_state.json | Path to the job cursor state file |

## Testing

The project includes a comprehensive test suite covering:
-   **API Client**: Pagination, retries, and streaming logic.
-   **Deduplication**: Content-based hashing and Redis integration.
-   **Rate Limiting**: Distributed token bucket verification.
-   **Durability**: Checkpointing, crash recovery, and atomic state updates.
