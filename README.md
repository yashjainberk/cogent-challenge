# Vulnerability Subscription Service

A horizontally scalable polling service for ingesting vulnerability data from multiple third-party APIs (Qualys, Rapid7, Tenable) into an append-only log.

## Features

-   **Scalable Architecture**: Run multiple worker processes in parallel to increase throughput.
-   **Distributed Coordination**: Uses file-based locking to ensure jobs are distributed safely without race conditions.
-   **Robust Ingestion**:
    -   Concurrent page fetching with streaming.
    -   Token bucket rate limiting to respect API quotas.
    -   Automatic retries with exponential backoff.
-   **Data Integrity**:
    -   In-memory O(1) deduplication.
    -   Append-only JSON Lines log with atomic writes.
    -   Crash-recovery support (resumes from last successful cursor).

## Usage

Run a single worker:

```bash
python subscription_service.py
```

Run multiple workers in parallel (for higher throughput):

```bash
python subscription_service.py &
python subscription_service.py &
python subscription_service.py &
```
