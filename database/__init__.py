import asyncpg
import config
import redis.asyncio as aredis

pool: asyncpg.Pool = None # type: ignore
redis = aredis.Redis(
    host=config.env.get("REDIS_HOST") or "127.0.0.1",
    port=int(config.env.get("REDIS_PORT") or 6379)
)

prefix = config.env.get("DB") or "proxy"
redis_prefix = f"{prefix}:"

async def init():
    global pool
    pool = await asyncpg.create_pool(
        user=config.env.get("POSTGRES_USER"),
        password=config.env.get("POSTGRES_PASSWORD"),
        database=prefix,
        host=config.env.get("POSTGRES_HOST"),
        port=config.env.get("POSTGRES_PORT")
    )

async def unload():
    global pool
    await pool.close()