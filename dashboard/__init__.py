from pathlib import Path
import web

ASSETS = Path(__file__).parent / "assets"

app = web.create_application(
    "*",
    8008
)

app.mount("/", ASSETS / "index.html")

async def init():
    """Initialize the dashboard."""
    await web.start_server(
        8008,
        None,
        True
    )