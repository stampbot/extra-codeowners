"""Bound read-ahead while one consumer commits results in source order."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Iterable
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass


@dataclass(frozen=True)
class _Value[Result]:
    value: Result


@dataclass(frozen=True)
class _Failure:
    error: Exception


@dataclass(frozen=True)
class _End:
    pass


@asynccontextmanager
async def ordered_prefetch[Item, Result](
    items: Iterable[Item],
    read: Callable[[Item], AsyncGenerator[Result, None]],
    *,
    slots: int,
) -> AsyncIterator[AsyncIterator[tuple[Item, AsyncIterator[Result]]]]:
    """Prefetch bounded streams, cancelling and draining unused reads on exit.

    Each producer can buffer one result. Consume each returned stream fully
    before requesting the next item; leave the context to stop early. Readers
    must be read-only: later items can be fetched before earlier ones commit.
    """
    if not 1 <= slots <= 4:
        raise ValueError("ordered prefetch requires between one and four slots")
    source = iter(items)
    pending: deque[
        tuple[Item, asyncio.Task[None], asyncio.Queue[_Value[Result] | _Failure | _End]]
    ] = deque()

    async def produce(item: Item, queue: asyncio.Queue[_Value[Result] | _Failure | _End]) -> None:
        try:
            async with aclosing(read(item)) as stream:
                async for result in stream:
                    await queue.put(_Value(result))
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise
            await queue.put(_Failure(RuntimeError("discovery reader cancelled unexpectedly")))
        except Exception as error:
            await queue.put(_Failure(error))
        else:
            await queue.put(_End())

    def fill() -> None:
        while len(pending) < slots:
            try:
                item = next(source)
            except StopIteration:
                break
            queue: asyncio.Queue[_Value[Result] | _Failure | _End] = asyncio.Queue(maxsize=1)
            task = asyncio.create_task(produce(item, queue), name="reconciliation-prefetch")
            pending.append((item, task, queue))

    async def receive(
        queue: asyncio.Queue[_Value[Result] | _Failure | _End],
    ) -> AsyncIterator[Result]:
        while True:
            result = await queue.get()
            if isinstance(result, _End):
                return
            if isinstance(result, _Failure):
                raise result.error
            yield result.value

    async def consume() -> AsyncGenerator[tuple[Item, AsyncIterator[Result]], None]:
        fill()
        while pending:
            item, task, queue = pending[0]
            yield item, receive(queue)
            await task
            pending.popleft()
            fill()

    consumer = consume()
    try:
        yield consumer
    finally:
        await consumer.aclose()
        for _, task, _ in pending:
            task.cancel()
        await asyncio.gather(*(task for _, task, _ in pending), return_exceptions=True)
