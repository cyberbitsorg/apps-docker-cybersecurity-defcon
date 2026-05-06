_VOLUME_KEY = "defcon:volume_history"
_WINDOW_SIZE = 168   # 7 days × 24 cycles at 60-min fetch interval
_COLD_START_MIN = 3  # entries needed before baseline is meaningful


async def record_volume(redis, new_count: int) -> None:
    """Push new_count to the rolling window and trim to the last 168 entries."""
    await redis.rpush(_VOLUME_KEY, new_count)
    await redis.ltrim(_VOLUME_KEY, -_WINDOW_SIZE, -1)


async def get_volume_baseline(redis) -> float | None:
    """
    Return the arithmetic mean of stored fetch counts, or None during cold start.
    Returns None when fewer than 3 entries exist — caller should use neutral 12.5.
    """
    entries = await redis.lrange(_VOLUME_KEY, 0, -1)
    if len(entries) < _COLD_START_MIN:
        return None
    # Decode bytes → float (Redis returns bytes when decode_responses=False)
    values = [float(e.decode() if isinstance(e, bytes) else e) for e in entries]
    return sum(values) / len(values)
