import asyncio
from apscheduler.executors.pool import ThreadPoolExecutor
from datetime import datetime
import time
from typing import Callable, Optional
from apscheduler.schedulers.background import (
    BackgroundScheduler as SyncBackground
)
from apscheduler.schedulers.asyncio import (
    AsyncIOScheduler as AsyncBackground
)
from apscheduler.job import Job
from logger import logger
from weakref import WeakValueDictionary


tasks: WeakValueDictionary[int, Job] = WeakValueDictionary()
_async_id: int = 0
_sync_id: int = 0
MAX_INSTANCES = 9999
MAX_WORKERS = 256
gconfig = {
    "coalesce": True,
    "misfire_grace_time": None
}
background = SyncBackground(
    job_defaults=gconfig,
    executors={
        "default": ThreadPoolExecutor(max_workers=MAX_WORKERS),
    }
)
async_background: AsyncBackground


async def init():
    global async_background
    async_background = AsyncBackground(
        event_loop=asyncio.get_event_loop(),
        job_defaults=gconfig,
    )

    background.start()
    async_background.start()

    logger.success('Background scheduler initialized')


async def unload():
    global async_background
    background.shutdown()
    async_background.shutdown()
    logger.success('Background scheduler unloaded')


def run_later(func: Callable, delay: float, args = (), kwargs = {}) -> int:
    global _sync_id, _async_id
    if asyncio.iscoroutinefunction(func):
        cur_id = -(_async_id := _async_id + 1)
        tasks[cur_id] = async_background.add_job(
            func=func, args=args, kwargs=kwargs, trigger='date', run_date=datetime.fromtimestamp(time.time() + delay), max_instances=MAX_INSTANCES
        )
    else:
        cur_id = (_sync_id := _sync_id + 1)
        tasks[cur_id] = background.add_job(
            func=func, args=args, kwargs=kwargs, trigger='date', run_date=datetime.fromtimestamp(time.time() + delay), max_instances=MAX_INSTANCES
        )
    return cur_id

def run_repeat_later(func: Callable, delay: float, interval: float, args = (), kwargs = {}) -> int:
    global _sync_id, _async_id
    delay = max(delay, 1)
    if asyncio.iscoroutinefunction(func):
        cur_id = -(_async_id := _async_id + 1)
        tasks[cur_id] = async_background.add_job(
            func=func, args=args, kwargs=kwargs, trigger='interval', seconds=interval, start_date=datetime.fromtimestamp(time.time() + delay), max_instances=MAX_INSTANCES
        )
    else:
        cur_id = (_sync_id := _sync_id + 1)
        tasks[cur_id] = background.add_job(
            func=func, args=args, kwargs=kwargs, trigger='interval', seconds=interval, start_date=datetime.fromtimestamp(time.time() + delay), max_instances=MAX_INSTANCES
        )
    return cur_id

def run_repeat(func: Callable, interval: float, args = (), kwargs = {}) -> int:
    return run_repeat_later(func, 0, interval, args, kwargs)

def cancel(task_id: Optional[int] = None):
    if task_id is None:
        return
    if task_id in tasks:
        try:
            tasks.pop(task_id).remove()
        except:
            logger.debug(f'Task {task_id} was cancelled')
            return
        logger.debug(f'Task {task_id} canceled')
    
