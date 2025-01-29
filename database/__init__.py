import config
import motor.motor_asyncio as amotor
import urllib.parse as urlparse

db = amotor.AsyncIOMotorClient(
    f"mongodb://{urlparse.quote(config.env.get('MONGO_USER') or '')}:{urlparse.quote(config.env.get('MONGO_PASSWORD') or '')}@localhost:27017"
).get_database(config.env.get("DB") or "Proxy")