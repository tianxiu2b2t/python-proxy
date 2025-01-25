import asyncio
from typing import Any
from logger import logger
import proxy
import scheduler
import service

def init():
    asyncio.run(main())

async def run_func(
    module: Any,
    name: str
):
    try:
        await getattr(module, name)()
    except Exception as e:
        logger.debug_traceback(f"Error in {name}: {e}")


async def main():
    # load modules
    for module in (
        scheduler,
        proxy,
        service
    ):
        await run_func(module, "init")

    try:
        await asyncio.get_event_loop().create_future()
    except asyncio.CancelledError:
        pass

    # unload modules
    for module in (
        scheduler,
        proxy,
    ):
        await run_func(module, "unload")