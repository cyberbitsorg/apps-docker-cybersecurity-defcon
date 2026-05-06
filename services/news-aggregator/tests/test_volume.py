import pytest
from unittest.mock import AsyncMock
from cache.volume import record_volume, get_volume_baseline

VOLUME_KEY = "defcon:volume_history"


@pytest.fixture
def redis():
    r = AsyncMock()
    r.lrange = AsyncMock(return_value=[])
    return r


@pytest.mark.asyncio
async def test_record_volume_pushes_count(redis):
    await record_volume(redis, 7)
    redis.rpush.assert_called_once_with(VOLUME_KEY, 7)


@pytest.mark.asyncio
async def test_record_volume_trims_to_168_entries(redis):
    await record_volume(redis, 7)
    redis.ltrim.assert_called_once_with(VOLUME_KEY, -168, -1)


@pytest.mark.asyncio
async def test_get_volume_baseline_cold_start_returns_none(redis):
    redis.lrange.return_value = [b"5", b"7"]  # only 2 entries — below threshold
    result = await get_volume_baseline(redis)
    assert result is None


@pytest.mark.asyncio
async def test_get_volume_baseline_exactly_three_entries(redis):
    redis.lrange.return_value = [b"9", b"12", b"9"]
    result = await get_volume_baseline(redis)
    assert result == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_get_volume_baseline_averages_correctly(redis):
    redis.lrange.return_value = [b"5", b"15", b"10", b"10", b"10"]
    result = await get_volume_baseline(redis)
    assert result == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_get_volume_baseline_queries_full_list(redis):
    redis.lrange.return_value = [b"10", b"10", b"10"]
    await get_volume_baseline(redis)
    redis.lrange.assert_called_once_with(VOLUME_KEY, 0, -1)
