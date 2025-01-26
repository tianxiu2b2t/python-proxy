import asyncio
from collections import deque


class Queue[T]:
    def __init__(
        self
    ):
        self._objs: deque[T] = deque()
        self._waiters: deque[asyncio.Future] = deque()

    def offer(
        self,
        obj: T
    ):
        self._objs.append(obj)
        self._wake_up()

    
    async def poll(
        self,
    ):
        if not self._objs:
            fut = asyncio.get_running_loop().create_future()
            self._waiters.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self._waiters:
                    self._waiters.remove(fut)
        return self._objs.popleft()

    async def peek(
        self,
    ):
        if not self._objs:
            fut = asyncio.Future()
            self._waiters.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self._waiters:
                    self._waiters.remove(fut)
        return self._objs[0]

    def _wake_up(
        self,
    ):
        while self._waiters and self._objs:
            fut = self._waiters.popleft()
            fut.set_result(True)
