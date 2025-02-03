import abc
import asyncio
from collections import defaultdict, deque
import datetime
import time

from bson import ObjectId
import config
from logger import logger
import scheduler
import units
import database
from utils import Queue

class AccessLog:
    def __init__(
        self,
        type: str,
        host: str,
        rtt: int,
        method: str,
        path: str,
        status: int,
        address: str,
        user_agent: str,
        http_version: str
    ):
        self.type = type
        self.host = host
        self.rtt = rtt
        self.method = method
        self.path = path
        self.status = status
        self.address = address
        self.user_agent = user_agent
        self.http_version = http_version
        self.id = ObjectId()
        self.utc_time = datetime.datetime.now(datetime.timezone.utc)

class Statistics:
    def __init__(
        self,
    ):
        self.total_queries: defaultdict[int, int] = defaultdict(int)
        self.queries: defaultdict[str, defaultdict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._logger_queue: Queue[AccessLog] = Queue()
        self._db_access_logger: deque[AccessLog] = deque()
        self._start_runtime = time.monotonic_ns()
        self._logger_task = None
        self._logger_db_task = None
        self._stop = False

    @property
    def get_runtime(self):
        return (time.monotonic_ns() - self._start_runtime) / 1e9
    
    @property
    def get_runtime_int(self):
        return int(self.get_runtime)
    
    def add_qps(self, host: str):
        self.total_queries[self.get_runtime_int] += 1
        self.queries[host][self.get_runtime_int] += 1

    def print_access_log(
        self,
        type: str,
        host: str,
        rtt: int,
        method: str,
        path: str,
        status: int,
        address: str,
        user_agent: str,
        http_version: str
    ):
        self._logger_queue.offer(
            AccessLog(
                type=type,
                host=host,
                rtt=rtt,
                method=method,
                path=path,
                status=status,
                address=address,
                user_agent=user_agent,
                http_version=http_version
            )
        )

    def gc(self):
        self.gc_total_queries()
        self.gc_queries()

    def gc_total_queries(self):
        old_keys = list(filter(lambda x: x < self.get_runtime_int - 600, list(self.total_queries.keys())))
        for key in old_keys:
            del self.total_queries[key]

    def gc_queries(self):
        for host, host_dict in self.queries.items():
            old_keys = list(filter(lambda x: x < self.get_runtime_int - 600, list(host_dict.keys())))
            for key in old_keys:
                del host_dict[key]
                
    async def _task_print_access_log(self):
        while not self._stop:
            obj = await self._logger_queue.poll()
            if obj is None:
                break
            logger.info(config.templates.ACCESS_LOG.safe_substitute(
                type=obj.type,
                host=obj.host,
                rtt=units.format_count_time(obj.rtt, 4).rjust(14),
                method=obj.method.ljust(9),
                path=obj.path,
                status=str(obj.status).rjust(3),
                address=obj.address.rjust(20),
                user_agent=obj.user_agent,
                http_version=obj.http_version.ljust(8),
            ))
            self._db_access_logger.append(obj)

    async def _task_save_access_log(self):
        collection = database.db.get_collection("access_log")
        while not self._stop:
            await asyncio.sleep(1)
            if len(self._db_access_logger) == 0:
                continue
            objs = self._db_access_logger.copy()
            try:
                await collection.insert_many([{
                    "_id": obj.id,
                    "type": obj.type,
                    "host": obj.host,
                    "rtt": obj.rtt,
                    "method": obj.method,
                    "path": obj.path,
                    "status": obj.status,
                    "address": obj.address,
                    "user_agent": obj.user_agent,
                    "http_version": obj.http_version,
                    "utc_time": obj.utc_time
                } for obj in objs])
                for obj in objs:
                    self._db_access_logger.remove(obj)
            except:
                logger.traceback("Error while saving access log to database")
    
    def start(self):
        self._logger_task = asyncio.get_running_loop().create_task(self._task_print_access_log())
        self._db_logger_task = asyncio.get_running_loop().create_task(self._task_save_access_log())
        scheduler.run_repeat_later(self.gc, 5, 60)

    async def stop(self):
        self._stop = True
        self._logger_queue.offer(None) # type: ignore
        if self._logger_task is not None:
            await self._logger_task
        if self._db_logger_task is not None:
            await self._db_logger_task


statistics = Statistics()