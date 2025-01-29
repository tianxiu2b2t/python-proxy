from pathlib import Path
import web
from database import db

ASSETS = Path(__file__).parent / "assets"
DB_PREFIX = "dashboard_"

app = web.create_application(
    "*",
    8008
)

auth = web.Router("/auth")
@auth.get("/")
async def _():
    ...

app.mount("/assets/js", ASSETS / "js")
app.mount("/assets/css", ASSETS / "css")
app.mount("/assets/fonts", ASSETS / "fonts")
app.mount("/assets/img", ASSETS / "img")
app.mount("/", ASSETS / "index.html")

async def init():
    """Initialize the dashboard."""
    await web.start_server(
        8008,
        None,
        True
    )