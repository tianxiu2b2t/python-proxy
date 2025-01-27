import asyncio
from typing import Optional

from logger import logger
from .app import Application, Request, process_application
from .proxy import ProxyForward, process_backend_proxy
from ..utils import Client, ForwardConfig, Header
from ..protocols import is_http1, is_http2, Protocol

import urllib.parse as urlparse

proxies: dict[str, 'ProxyForward'] = {}
applications: dict[str, 'Application'] = {}
port_applications: dict[int, 'Application'] = {}


def create_proxy(
    host: str,
    url: str,
    force_https: bool = False
):
    if host in proxies:
        raise ValueError(f"proxy {host} already exists")
    proxies[host] = ProxyForward(
        url,
        force_https
    )

def create_application(
    host: str,
    port: Optional[int] = None,
    force_https: bool = False
):
    if host in applications:
        return applications[host]
    applications[host] = Application(
        force_https
    )
    if host == "*":
        assert port is not None
        port_applications[port] = applications[host]
    return applications[host]

async def process(
    client: Client,
    cfg: ForwardConfig = ForwardConfig()
):
    try:
        buffer = await client.read(8192)
        client.feed_reader_data(buffer)
        host = cfg.sni
        if is_http1(buffer) and host is None:
            header = Header({
                k: v for k, v in (
                    line.decode("utf-8").split(": ", 1) for line in buffer.split(b"\r\n\r\n", 1)[0].split(b"\r\n", 1)[1].split(b"\r\n")
                )
            })
            host = header.get_one("Host") or ""
        if host is None:
            return

        hostname = urlparse.urlparse(f"http://{host}").hostname
        if hostname is None:
            return
        protocol = None
        if is_http1(buffer):
            protocol = Protocol.HTTP1
        elif is_http2(buffer):
            protocol = Protocol.HTTP2
        if protocol is None:
            return

        if cfg.pub_port in port_applications:
            await process_application(client, protocol, hostname, port_applications[cfg.pub_port])
        elif hostname in applications:
            await process_application(client, protocol, hostname, applications[hostname])
        elif hostname in proxies:
            await process_backend_proxy(client, protocol, hostname, proxies[hostname])
        else:
            logger.debug("Unavailable host:", hostname)
    except (
        ConnectionAbortedError,
        ConnectionResetError,
        asyncio.exceptions.CancelledError
    ):
        ...
    except:
        logger.traceback()

