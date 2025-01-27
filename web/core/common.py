import asyncio
from collections import defaultdict, deque
import time
from typing import Any

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
        # pgsql
        async with database.pool.acquire(
            timeout=5
        ) as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS access_log (
                    id CHAR(24) PRIMARY KEY,
                    type VARCHAR(32),
                    host VARCHAR(255),
                    rtt INT,
                    method VARCHAR(10),
                    path TEXT,
                    status INT,
                    address VARCHAR(255),
                    user_agent TEXT,
                    http_version VARCHAR(10)
                );
            ''')
            # create index
            for idx in (
                'host',
                'rtt',
                'method',
                'path',
                'status',
                'address',
                'user_agent',
                'http_version'
            ):
                await conn.execute(f'''
                    CREATE INDEX IF NOT EXISTS idx_access_log_{idx} ON access_log ({idx});
                ''')
            
        while not self._stop:
            await asyncio.sleep(1)
            if len(self._db_access_logger) == 0:
                continue
            objs = self._db_access_logger.copy()
            for obj in objs:
                self._db_access_logger.remove(obj)
            conn: database.asyncpg.Connection
            async with database.pool.acquire(
                timeout=5
            ) as conn:
                await conn.executemany('''

                    INSERT INTO access_log (
                        id, 
                        type, 
                        host, 
                        rtt,
                        method,
                        path,
                        status,
                        address,
                        user_agent,
                        http_version
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
                    )
                ''', [
                    (
                        str(obj.id),
                        obj.type,
                        obj.host,
                        obj.rtt,
                        obj.method,
                        obj.path,
                        obj.status,
                        obj.address,
                        obj.user_agent,
                        obj.http_version
                    )
                    for obj in objs
                ])
    
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