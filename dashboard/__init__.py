import web

app = web.create_application(
    "*",
    8008
)

@app.get("/")
async def index():
    return web.statistics.queries

async def init():
    """Initialize the dashboard."""
    await web.start_server(
        8008,
        None,
        True
    )