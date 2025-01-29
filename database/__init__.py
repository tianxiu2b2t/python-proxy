import config
import motor.motor_asyncio as amotor
import urllib.parse as urlparse

db = amotor.AsyncIOMotorClient(
    f"mongodb://{urlparse.quote(config.env.get('MONGO_USER') or '')}:{urlparse.quote(config.env.get('MONGO_PASSWORD') or '')}@{config.env.get('MONGO_HOST') or 'localhost'}:{config.env.get('MONGO_PORT') or '27017'}"
).get_database(config.env.get("DB") or "Proxy")