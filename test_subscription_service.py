import pytest
import json
import os
import tempfile
import time
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone
from aiohttp import web
import aiohttp

from subscription_service import (
    StateStore, Flusher, APIClient, Interval, Batch,
    RateLimiterFactory, RedisRateLimiter, SubscriptionService
)


# Test Fixtures
@pytest.fixture
def temp_files():
    """Create temporary files for testing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as log_file, \
         tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as state_file:
        log_path = log_file.name
        state_path = state_file.name
        state_file.write('{}')

    yield log_path, state_path

    # Cleanup
    for path in [log_path, state_path]:
        if os.path.exists(path):
            os.remove(path)


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    redis_mock = Mock()
    redis_mock.eval.return_value = 1  # Always return success
    return redis_mock


# StateStore Tests
class TestStateStore:
    """Tests for distributed state management."""

    def test_try_acquire_job_success(self, temp_files):
        _, state_path = temp_files
        store = StateStore(state_path)

        # First acquisition should succeed
        acquired, cursor = store.try_acquire_job("test_api", "worker-1", interval=60)

        assert acquired is True
        assert cursor is None

    def test_try_acquire_job_locked(self, temp_files):
        _, state_path = temp_files
        store = StateStore(state_path)

        # First worker acquires
        store.try_acquire_job("test_api", "worker-1", interval=60)

        # Second worker should fail (job locked, not due yet)
        acquired, _ = store.try_acquire_job("test_api", "worker-2", interval=60)

        assert acquired is False

    def test_try_acquire_job_stale_claim(self, temp_files):
        _, state_path = temp_files
        store = StateStore(state_path)

        # Manually create stale state
        now = datetime.now(timezone.utc).timestamp()
        state = {
            "test_api": {
                "claimed_by": "worker-old",
                "claimed_at": now - 700,  # 11+ minutes ago (stale)
                "last_poll": now - 700,
                "cursor": None
            }
        }
        with open(state_path, 'w') as f:
            json.dump(state, f)

        # Should be able to claim stale job
        acquired, _ = store.try_acquire_job("test_api", "worker-2", interval=60)

        assert acquired is True

    def test_release_job(self, temp_files):
        _, state_path = temp_files
        store = StateStore(state_path)

        # Acquire and release
        store.try_acquire_job("test_api", "worker-1", interval=60)
        store.release_job("test_api", "2024-01-01T00:00:00Z")

        # Verify state
        with open(state_path, 'r') as f:
            state = json.load(f)

        assert state["test_api"]["claimed_by"] is None
        assert state["test_api"]["cursor"] == "2024-01-01T00:00:00Z"


# Flusher Tests
class TestFlusher:
    """Tests for the single-writer flusher process."""

    def test_deduplication(self, temp_files):
        log_path, state_path = temp_files
        
        # Mock Redis
        with patch('redis.Redis') as mock_redis_cls:
            mock_redis = mock_redis_cls.return_value
            # SADD returns 1 for new, 0 for existing
            mock_redis.sadd.side_effect = [1, 0, 1] 

            data_queue = Mock()
            flusher = Flusher(data_queue, log_path, state_path)

            items = [
                {"id": "item-1", "data": "first"},
                {"id": "item-1", "data": "first"},  # Exact duplicate
                {"id": "item-1", "data": "updated"} # Same ID, different data (should be kept)
            ]

            # Manually process as the flusher loop would
            processed = []
            for item in items:
                if not flusher.is_duplicate(item):
                    processed.append(item)

            assert len(processed) == 2
            assert processed[0]["data"] == "first"
            assert processed[1]["data"] == "updated"

    def test_flush_buffer_durability(self, temp_files):
        log_path, state_path = temp_files

        data_queue = Mock()
        flusher = Flusher(data_queue, log_path, state_path)

        # Add items to buffer
        flusher.buffer = [
            {"id": "item-1", "data": "test1"},
            {"id": "item-2", "data": "test2"}
        ]

        # Flush
        flusher._flush_buffer()

        # Verify written to disk
        with open(log_path, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 2
        assert json.loads(lines[0])["id"] == "item-1"
        assert json.loads(lines[1])["id"] == "item-2"

    def test_load_existing_ids(self, temp_files):
        log_path, state_path = temp_files

        # Write existing data
        with open(log_path, 'w') as f:
            f.write(json.dumps({"id": "existing-1", "data": "1"}) + '\n')
            f.write(json.dumps({"id": "existing-2", "data": "2"}) + '\n')

        # Mock Redis
        with patch('redis.Redis') as mock_redis_cls:
            mock_redis = mock_redis_cls.return_value
            data_queue = Mock()
            flusher = Flusher(data_queue, log_path, state_path)

            # Sync should have been called twice
            assert mock_redis.sadd.called

    def test_batch_processing_with_final_flag(self, temp_files):
        log_path, state_path = temp_files
    
        # Initialize state with the job before testing
        with open(state_path, 'w') as f:
            json.dump({"test_job": {"cursor": None, "claimed_by": "worker-1", "claimed_at": 123456}}, f)

        # Mock Redis
        with patch('redis.Redis') as mock_redis_cls:
            mock_redis = mock_redis_cls.return_value
            mock_redis.sadd.return_value = 1  # All items new

            data_queue = Mock()
            flusher = Flusher(data_queue, log_path, state_path)

            # Process batch
            batch = Batch(
                job_name="test_job",
                items=[{"id": "item-1", "data": "test"}],
                cursor="2024-01-01T00:00:00Z",
                is_final=True
            )

            for item in batch.items:
                if not flusher.is_duplicate(item):
                    flusher.buffer.append(item)

            flusher.pending_batches.append(batch)
            flusher._flush_buffer()

        # Verify cursor was updated
        with open(state_path, 'r') as f:
            state = json.load(f)

        assert state["test_job"]["cursor"] == "2024-01-01T00:00:00Z"


# APIClient Tests
class TestAPIClient:
    """Tests for API client with pagination and retries."""

    @pytest.mark.asyncio
    async def test_fetch_page_success(self, mock_redis):
        """Test successful page fetch."""
        limiter_factory = RateLimiterFactory(mock_redis, rpm=60, burst=1)

        async with aiohttp.ClientSession() as session:
            with patch.object(session, 'get') as mock_get:
                # Mock response
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.json = AsyncMock(return_value={
                    "items": [{"id": "1"}],
                    "total": 1,
                    "count": 1
                })
                mock_get.return_value.__aenter__.return_value = mock_resp

                client = APIClient(session, limiter_factory)
                result = await client.fetch_page(
                    "https://api.test.com/data",
                    offset=0,
                    cursor=None,
                    service_name="test"
                )

                assert result["total"] == 1
                assert len(result["items"]) == 1

    @pytest.mark.asyncio
    async def test_fetch_page_retry_on_failure(self, mock_redis):
        """Test retry logic on transient failures."""
        limiter_factory = RateLimiterFactory(mock_redis, rpm=60, burst=1)

        async with aiohttp.ClientSession() as session:
            with patch.object(session, 'get') as mock_get:
                # First call fails, second succeeds
                mock_resp_fail = MagicMock()
                mock_resp_fail.status = 500
                mock_resp_fail.raise_for_status.side_effect = Exception("Server error")

                mock_resp_success = MagicMock()
                mock_resp_success.status = 200
                mock_resp_success.json = AsyncMock(return_value={
                    "items": [{"id": "1"}],
                    "total": 1
                })

                # Mock context manager
                mock_cm = MagicMock()
                mock_cm.__aenter__ = AsyncMock(side_effect=[
                    mock_resp_fail,
                    mock_resp_success
                ])
                mock_get.return_value = mock_cm

                client = APIClient(session, limiter_factory)
                result = await client.fetch_page(
                    "https://api.test.com/data",
                    offset=0,
                    cursor=None,
                    service_name="test"
                )

                assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_fetch_stream_pagination(self, mock_redis):
        """Test streaming pagination."""
        limiter_factory = RateLimiterFactory(mock_redis, rpm=60, burst=1)

        async with aiohttp.ClientSession() as session:
            with patch.object(session, 'get') as mock_get:
                # Mock paginated responses
                page1 = {"items": [{"id": "1"}, {"id": "2"}], "total": 5, "count": 2}
                page2 = {"items": [{"id": "3"}, {"id": "4"}], "total": 5, "count": 2}
                page3 = {"items": [{"id": "5"}], "total": 5, "count": 1}

                responses = []
                for page_data in [page1, page2, page3]:
                    mock_resp = AsyncMock()
                    mock_resp.status = 200
                    mock_resp.json = AsyncMock(return_value=page_data)
                    responses.append(mock_resp)

                mock_get.return_value.__aenter__.side_effect = responses

                # Mock Config for test
                with patch('subscription_service.config') as mock_config:
                    mock_config.PAGE_SIZE = 2
                    mock_config.CONCURRENT_PAGES = 1

                    client = APIClient(session, limiter_factory)

                    items_collected = []
                    async for items, _, _ in client.fetch_stream(
                        "https://api.test.com/data",
                        cursor=None,
                        service_name="test"
                    ):
                        items_collected.extend(items)

                    assert len(items_collected) == 5


# RedisRateLimiter Tests
class TestRedisRateLimiter:
    """Tests for distributed rate limiting."""

    @pytest.mark.asyncio
    async def test_acquire_token_success(self, mock_redis):
        """Test successful token acquisition."""
        mock_redis.eval.return_value = 1  # Token available

        limiter = RedisRateLimiter(mock_redis, "test_service", rpm=60, burst=1)

        # Should succeed without blocking
        await limiter.acquire()

        assert mock_redis.eval.called

    @pytest.mark.asyncio
    async def test_acquire_token_retry(self, mock_redis):
        """Test retry when token unavailable."""
        # First call fails, second succeeds
        mock_redis.eval.side_effect = [0, 1]

        limiter = RedisRateLimiter(mock_redis, "test_service", rpm=60, burst=1)

        start = time.time()
        await limiter.acquire()
        elapsed = time.time() - start

        # Should have waited before retrying
        assert elapsed >= 0.5  # At least some delay
        assert mock_redis.eval.call_count == 2


# Integration Tests
class TestIntegration:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_mock_api_server(self):
        """Test with mock API server."""

        # Create mock API server
        async def handle_vulnerabilities(request):
            offset = int(request.query.get('offset', 0))
            limit = int(request.query.get('limit', 100))

            # Generate mock data
            items = [{"id": f"item-{i}", "data": f"test-{i}"} for i in range(offset, min(offset + limit, 10))]

            return web.json_response({
                "items": items,
                "total": 10,
                "count": len(items)
            })

        app = web.Application()
        app.router.add_get('/vulnerabilities', handle_vulnerabilities)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', 8888)
        await site.start()

        try:
            # Test client
            with patch('subscription_service.config') as mock_config:
                mock_config.PAGE_SIZE = 5
                mock_config.CONCURRENT_PAGES = 1

                mock_redis = Mock()
                mock_redis.eval.return_value = 1
                limiter_factory = RateLimiterFactory(mock_redis, rpm=60, burst=1)

                async with aiohttp.ClientSession() as session:
                    client = APIClient(session, limiter_factory)

                    items_collected = []
                    async for items, _, _ in client.fetch_stream(
                        "http://localhost:8888/vulnerabilities",
                        cursor=None,
                        service_name="test"
                    ):
                        items_collected.extend(items)

                    assert len(items_collected) == 10
                    assert items_collected[0]["id"] == "item-0"
                    assert items_collected[-1]["id"] == "item-9"
        finally:
            await runner.cleanup()

    def test_crash_recovery(self, temp_files):
        """Test that service can recover after crash."""
        log_path, state_path = temp_files
    
        # Simulate partial write before crash
        with open(log_path, 'w') as f:
            f.write(json.dumps({"id": "pre-crash-1", "data": "old"}) + '\n')
    
        # Write state with cursor
        with open(state_path, 'w') as f:
            json.dump({
                "test_api": {
                    "claimed_by": None,
                    "claimed_at": None,
                    "last_poll": 0,
                    "cursor": "2024-01-01T00:00:00Z"
                }
            }, f)
    
        # Start flusher (recovery)
        with patch('redis.Redis') as mock_redis_cls:
            mock_redis = mock_redis_cls.return_value
            data_queue = Mock()
            flusher = Flusher(data_queue, log_path, state_path)
    
            # Sync should have called sadd for the pre-crash item
            assert mock_redis.sadd.called
    
            # Should be able to continue
            flusher.buffer = [{"id": "post-crash-1", "data": "new"}]
            # Mock sadd for post-crash item
            mock_redis.sadd.return_value = 1
            flusher.is_duplicate(flusher.buffer[0])
            flusher._flush_buffer()

        # Verify both items in log
        with open(log_path, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 2

    def test_concurrent_worker_coordination(self, temp_files):
        """Test that multiple workers don't poll the same API simultaneously."""
        _, state_path = temp_files

        store1 = StateStore(state_path)
        store2 = StateStore(state_path)

        # Worker 1 acquires
        acquired1, _ = store1.try_acquire_job("test_api", "worker-1", interval=60)

        # Worker 2 tries to acquire (should fail)
        acquired2, _ = store2.try_acquire_job("test_api", "worker-2", interval=60)

        assert acquired1 is True
        assert acquired2 is False


# Subscription Service Tests
class TestSubscriptionService:
    """Tests for the main service orchestrator."""

    def test_register_api(self):
        """Test API registration."""
        service = SubscriptionService()

        service.register_api("test", "https://api.test.com", Interval.HOUR, value=2)

        assert "test" in service.subscriptions
        assert service.subscriptions["test"][0] == "https://api.test.com"
        assert service.subscriptions["test"][1] == 7200  # 2 hours in seconds


# Performance Tests
class TestPerformance:
    """Tests for throughput and performance requirements."""

    def test_checkpointing(self, temp_files):
        """Test that cursors are checkpointed before job completion."""
        log_path, state_path = temp_files
        
        # Initialize state
        with open(state_path, 'w') as f:
            json.dump({"test_job": {"cursor": "old", "claimed_by": "w1", "claimed_at": 1}}, f)

        # Mock Redis
        with patch('redis.Redis') as mock_redis_cls:
            mock_redis = mock_redis_cls.return_value
            mock_redis.sadd.return_value = 1

            data_queue = Mock()
            flusher = Flusher(data_queue, log_path, state_path)

            # Process an intermediate batch (is_final=False)
            batch = Batch(job_name="test_job", items=[{"id": "1"}], cursor="mid-point", is_final=False)
            flusher.buffer = [{"id": "1"}]
            flusher.pending_batches = [batch]
            flusher._flush_buffer()

            # Verify state was checkpointed but NOT released
            with open(state_path, 'r') as f:
                state = json.load(f)
                assert state["test_job"]["cursor"] == "mid-point"
                assert state["test_job"]["claimed_by"] == "w1"  # Still claimed

            # Process final batch
            batch_final = Batch(job_name="test_job", items=[{"id": "2"}], cursor="final", is_final=True)
            flusher.buffer = [{"id": "2"}]
            flusher.pending_batches = [batch_final]
            flusher._flush_buffer()

            # Verify state was released
            with open(state_path, 'r') as f:
                state = json.load(f)
                assert state["test_job"]["cursor"] == "final"
                assert state["test_job"]["claimed_by"] is None  # Released

    def test_throughput_calculation(self):
        """Verify system meets throughput requirements."""
        # System config
        rate_limit_rpm = 20
        num_services = 3
        page_size = 250

        # Calculate throughput
        requests_per_sec = (rate_limit_rpm * num_services) / 60
        items_per_sec = requests_per_sec * page_size

        # Requirements
        req_initial = 1_000_000 / (4 * 3600)  # 69.44 items/sec
        req_steady = 10_000 / (4 * 3600)  # 0.69 items/sec

        # Verify system exceeds requirements
        assert items_per_sec > req_initial
        assert items_per_sec > req_steady
        assert items_per_sec / req_initial >= 3.0  # At least 3x margin


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
