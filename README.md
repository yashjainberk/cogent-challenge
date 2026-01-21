# Vulnerability Subscription Service

A horizontally scalable polling service for ingesting vulnerability data from multiple third-party APIs (Qualys, Rapid7, Tenable) into an append-only log.

## Features

-   **Scalable Architecture**: Multiple worker processes fetch from APIs in parallel, with a single flusher process handling deduplication and disk writes.
-   **Distributed Coordination**: File-based job locking ensures each API is polled by only one worker at a time.
-   **Redis-Based Rate Limiting**: Per-service rate limits shared across all workers to respect API quotas (20 RPM per service).
-   **Streaming Ingestion**: Pages are sent to the flusher immediately as they arrive, rather than waiting for all pages to be fetched.
-   **Acknowledgment-Based Persistence**: Workers wait for the flusher to confirm data is written to disk before updating cursors, ensuring crash safety.
-   **Data Integrity**:
    -   In-memory O(1) deduplication in the flusher process.
    -   Append-only JSON Lines log with fsync for durability.
    -   Crash-recovery support (resumes from last successful cursor).

## Prerequisites

-   Python 3.11+
-   Redis server running locally

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

## Architecture

```
┌──────────────┐
│   Worker 0   │──┐
│ (qualys)     │  │
└──────────────┘  │
┌──────────────┐  │     ┌────────────────┐      ┌─────────────┐
│   Worker 1   │──┼────▶│  Shared Queue  │─────▶│   Flusher   │───▶ vulnerabilities.jsonl
│ (rapid7)     │  │     │ (mp.Queue)     │      │ (seen_ids)  │
└──────────────┘  │     └────────────────┘      └─────────────┘
┌──────────────┐  │
│   Worker 2   │──┘
│ (tenable)    │
└──────────────┘
       │
       ▼
   Redis (shared rate limiting per service)
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
