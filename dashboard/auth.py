import hashlib
import random
import string
import time
import database
from utils import JWT
import web
from web.utils import Header
from bson import ObjectId

db = database.db
router = web.Router("/api/auth")
global_secret = b''


UNAUTHORIZATED = web.Response(
    status=401,
    content="Unauthorized"
)

@router.get("/")
async def _(
    request: web.Request
):
    authorization = JWT(
        request.headers.get_one("Authorization") or ""
    )
    user_id = None
    authorization.secret = global_secret
    try:
        user_id = ObjectId(authorization.decode())
    except:
        return UNAUTHORIZATED
    r = await db.get_collection("auth_users").find_one({"_id": user_id})
    if r is None:
        return UNAUTHORIZATED
    return web.Response(
        status=200,
        content={
            "username": r["username"]
        }
    )

@router.post("/login")
async def _(
    request: web.Request
):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    auth_users = db.get_collection("auth_users")
    r = await auth_users.find_one({"username": username, "password": hashlib.sha256(password.encode()).hexdigest()})
    if r is None:
        return UNAUTHORIZATED
    return web.Response(
        status=200,
        headers=Header({
            "Authorization": JWT(
                str(r["_id"]),
                global_secret,
                int(time.time() + 60 * 60)
            ).encode()
        })
    )


async def init_variables():
    global global_secret
    # initialize global secret

    auth_config_collection = db.get_collection("auth_config")
    r = await auth_config_collection.find_one({"key": "secret"})
    if r is None:
        global_secret = random.getrandbits(256).to_bytes(32, 'big')
        await auth_config_collection.insert_one({
            "key": "secret",
            "value": global_secret
        })
    else:
        global_secret = r["value"]


async def init():
    await init_variables()

    # user

    auth_users = db.get_collection("auth_users")
    if await auth_users.count_documents({}) == 0:
        pwd = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=8))
        await auth_users.insert_one({
            "username": "admin",
            "password": hashlib.sha256(pwd.encode()).hexdigest(),
        })
        print("admin password:", pwd)