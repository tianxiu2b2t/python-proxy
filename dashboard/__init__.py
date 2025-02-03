from pathlib import Path
from . import auth
from utils import JWT
import web
from database import db

ASSETS = Path(__file__).parent / "assets"
DB_PREFIX = "dashboard_"

app = web.create_application(
    "*",
    8008
)

    

app.mount("/assets/js", ASSETS / "js")
app.mount("/assets/css", ASSETS / "css")
app.mount("/assets/fonts", ASSETS / "fonts")
app.mount("/assets/img", ASSETS / "img")
app.mount("/", ASSETS / "index.html")

@app.get("/")
def _():
    return ASSETS / "index.html"

@app.get("/{tag}/{item}")
def _(tag, item):
    return ASSETS / "index.html"

app.add_router(auth.router)

async def init():
    """Initialize the dashboard."""
    await web.start_server(
        8008,
        None,
        True
    )

    await auth.init()