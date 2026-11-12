"""Read-ahead overlaps requests without reordering commits or leaking tasks."""

import asyncio
from collections.abc import AsyncGenerator

import pytest

from extra_codeowners.ordered_prefetch import ordered_prefetch


# Verifies XCO-019.
@pytest.mark.asyncio
async def test_reads_overlap_but_results_and_errors_stay_in_source_order() -> None:
    started: set[int] = set()
    together = asyncio.Event()
    committed: list[tuple[int, int]] = []

    async def read(item: int) -> AsyncGenerator[int, None]:
        started.add(item)
        if len(started) == 3:
            together.set()
        await asyncio.wait_for(together.wait(), 5)
        yield item * 10
        if item == 2:
            raise ValueError("second repository failed after its first PR")
        yield item * 10 + 1

    with pytest.raises(ValueError, match="second repository"):
        async with ordered_prefetch([1, 2, 3], read, slots=3) as repositories:
            async for item, results in repositories:
                async for result in results:
                    committed.append((item, result))  # noqa: PERF401 - retain the prefix before failure
    assert started == {1, 2, 3}
    assert committed == [(1, 10), (1, 11), (2, 20)]


# Verifies XCO-019.
@pytest.mark.asyncio
async def test_early_exit_drains_readers_and_bounds_tasks_and_buffering() -> None:
    started: set[int] = set()
    closed: set[int] = set()
    produced: dict[int, int] = {}

    async def read(item: int) -> AsyncGenerator[int, None]:
        started.add(item)
        try:
            for number in range(100):
                produced[item] = number + 1
                yield number
        finally:
            closed.add(item)

    async with ordered_prefetch(range(100), read, slots=4) as repositories:
        async for _, results in repositories:
            async for _ in results:
                await asyncio.sleep(0)
                break
            break
    assert started == closed == {0, 1, 2, 3}
    assert all(count <= 3 for count in produced.values())


@pytest.mark.asyncio
async def test_unexpected_reader_cancellation_does_not_leave_consumer_waiting() -> None:
    async def read(item: int) -> AsyncGenerator[int, None]:
        yield item
        raise asyncio.CancelledError

    with pytest.raises(RuntimeError, match="cancelled unexpectedly"):
        async with ordered_prefetch([1], read, slots=1) as repositories:
            async for _, results in repositories:
                async for _ in results:
                    pass


@pytest.mark.asyncio
async def test_outer_cancellation_closes_readers() -> None:
    started = asyncio.Event()
    closed = asyncio.Event()

    async def read(item: int) -> AsyncGenerator[int, None]:
        try:
            started.set()
            await asyncio.Event().wait()
            yield item
        finally:
            closed.set()

    async def consume() -> None:
        async with ordered_prefetch([1], read, slots=1) as repositories:
            async for _, results in repositories:
                async for _ in results:
                    pass

    task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    assert closed.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("slots", [0, 5])
async def test_invalid_slot_count_is_rejected(slots: int) -> None:
    async def read(item: int) -> AsyncGenerator[int, None]:
        yield item

    with pytest.raises(ValueError, match="one and four"):
        async with ordered_prefetch([1], read, slots=slots):
            pass
