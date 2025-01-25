from . import acme_zerossl
from . import dns

async def init():
    await acme_zerossl.init()
