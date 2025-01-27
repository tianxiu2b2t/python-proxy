import asyncio
from dataclasses import dataclass
import ssl
import time
from typing import Optional

from logger import logger
from .common import statistics
from ..protocols import Protocol
from ..utils import Client, ClientStream, Header, get_status_code_name

import urllib.parse as urlparse

MAX_BUFFER = 1024 * 1024 * 4

class ProxyForward:
    def __init__(
        self,
        url: str
    ):
        result = urlparse.urlparse(url)
        self.url = url
        self.host = result.hostname
        self.port = result.port or (
            443 if result.scheme == "https" else 80
        )
        self.scheme = result.scheme

    @property
    def is_ssl(self):
        return self.scheme == "https"

    def __repr__(self):
        return f"ProxyForward({self.host}:{self.port}, url={self.scheme}://{self.host}:{self.port})"



async def process_backend_proxy(
    client: Client,
    protocol: Protocol,
    hostname: str,
    proxy: ProxyForward
):
    if protocol == Protocol.HTTP1:
        await process_http1_backend_proxy(client, hostname, proxy)
    #elif protocol == Protocol.HTTP2:
    #    await process_http2_backend_proxy(client, protocol, hostname, proxy)


@dataclass
class HTTPStatus:
    accepted: bool = False
    req_host: str = ""
    req_http_version: str = ""
    req_method: str = ""
    req_raw_path: str = ""
    req_user_agent: str = ""
    req_peername: str = ""
    req_time: int = 0

    resp_time: int = 0

    proxy_url: str = ""

    keepalive: Optional[asyncio.Future] = None


async def _forward_req(
    client: ClientStream,
    conn: Client,
    status: HTTPStatus
):
    while not client.is_closing and (buffer := await client.readuntil(b"\r\n\r\n")):
        buffer = buffer[:-4]
        pre_byte_header, byte_header = buffer.split(b"\r\n", 1)
        byte_method, byte_path, byte_version = pre_byte_header.split(b" ")
        method, path, http_version = (
            byte_method.decode("utf-8"),
            byte_path.decode("utf-8"),
            byte_version.decode("utf-8"),
        )
        headers = Header()
        for line in byte_header.split(b"\r\n"):
            if not line:
                break
            k, v = line.split(b": ", 1)
            headers.add(k.decode("utf-8"), v.decode("utf-8"))

        status.req_http_version = http_version
        status.req_method = method
        status.req_raw_path = path
        status.req_user_agent = (headers.get_one("User-Agent") or "")
        status.req_host = (headers.get_one("Host") or "")

        # add proxy header
        headers["X-Forwarded-For"] = status.req_peername
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = status.req_host
        headers["X-Real-IP"] = status.req_peername
        
        # start forward
        statistics.add_qps("proxy:" + status.proxy_url)

        req_header = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            if isinstance(v, list):
                for val in v:
                    req_header += f"{k}: {val}\r\n"
                continue
            req_header += f"{k}: {v}\r\n"
        req_header += "\r\n"

        status.req_time = time.perf_counter_ns()

        if status.keepalive is not None:
            status.keepalive.cancel()

        conn.write(req_header.encode("utf-8"))

        content_length = int(headers.get_one("Content-Length", None) or 0)
        websocket = (headers.get_one("Upgrade") or "").lower() == "websocket"

        while content_length > 0 and not client.is_closing and (data := await client.read(min(content_length, MAX_BUFFER))):
            if not data:
                break
            conn.write(data)
            content_length -= len(data)
            await conn.drain()

        if not websocket:
            continue
        while not client.is_closing and (data := await client.read(MAX_BUFFER)):
            if not data:
                break
            conn.write(data)
            await conn.drain()


async def _forward_resp(
    client: ClientStream,
    conn: Client,
    status: HTTPStatus
):
    while not client.is_closing and (buffer := await conn.readuntil(b"\r\n\r\n")):
        buffer = buffer[:-4]

        status.resp_time = time.perf_counter_ns()


        pre_byte_header, byte_header = buffer.split(b"\r\n", 1)
        http_version, byte_status_code, byte_status_name = pre_byte_header.split(b" ", 2)
        status_code, status_name = (
            byte_status_code.decode("utf-8"),
            byte_status_name.decode("utf-8"),
        )
    
        statistics.print_access_log(
            "Proxy",
            status.req_host,
            status.resp_time - status.req_time,
            status.req_method,
            status.req_raw_path,
            int(status_code),
            status.req_peername,
            status.req_user_agent,
            status.req_http_version
        )


        headers = Header()
        for line in byte_header.split(b"\r\n"):
            if not line:
                break
            k, v = line.split(b": ", 1)
            headers.add(k.decode("utf-8"), v.decode("utf-8"))

        status.accepted = True

        # start forward

        resp_header = f"{status.req_http_version} {status_code} {status_name}\r\n"
        for k, v in headers.items():
            if isinstance(v, list):
                for val in v:
                    resp_header += f"{k}: {val}\r\n"
                continue
            resp_header += f"{k}: {v}\r\n"
        resp_header += "\r\n"
        client.write(resp_header.encode("utf-8"))

        transfer = "Transfer-Encoding" in headers and (headers.get_one("Transfer-Encoding") or "").lower() == "chunked"
        content_length = int(headers.get_one("Content-Length", None) or 0)
        if transfer:
            while not conn.is_closing and (data := await conn.readuntil(b"\r\n")):
                size = int(data[:-2], 16)
                data = await conn.readuntil(b"\r\n")
                client.write(f"{size:x}\r\n".encode("utf-8") + data)
                await client.drain()
                if size == 0:
                    break
        elif content_length > 0:
            while content_length > 0 and not conn.is_closing and (data := await conn.read(min(content_length, MAX_BUFFER))):
                if not data:
                    break
                client.write(data)
                content_length -= len(data)

        # if websocket
        websocket = (headers.get_one("Connection") or "").lower() == "upgrade" and (headers.get_one("Upgrade") or "").lower() == "websocket"
        event_stream = "text/event-stream" in (headers.get_one("Content-Type") or "").lower()

        if websocket or event_stream:
            while not conn.is_closing:
                data = await conn.read(MAX_BUFFER)
                if not data:
                    break
                client.write(data)
                await client.drain()
        
        if "Keep-Alive" in headers and "timeout=" in headers["Keep-Alive"]:
            status.keepalive = asyncio.Future()
            try:
                await asyncio.wait_for(status.keepalive, int((headers.get_one("Keep-Alive") or "").split("timeout=")[1]))
            except asyncio.exceptions.TimeoutError:
                await conn.close()
                return
            


async def forward_http1(
    client: ClientStream,
    conn: Client,
    status: HTTPStatus
):
    try:
        await asyncio.gather(*(
            _forward_req(client, conn, status),
            _forward_resp(client, conn, status)
        ))
    except (
        asyncio.exceptions.IncompleteReadError,
        asyncio.exceptions.LimitOverrunError,
        ConnectionAbortedError,
        ConnectionResetError,
        TimeoutError,
        asyncio.exceptions.CancelledError,
        ConnectionRefusedError,
        ConnectionError
    ):
        ...
    except:
        raise


async def process_http1_backend_proxy(
    client: Client,
    hostname: str,
    proxy: ProxyForward
):
    status = HTTPStatus()
    stream = ClientStream()
    stream.set_client(client)
    status.req_peername = client.peername[0]
    status.proxy_url = proxy.url
    try:
        context = None
        if proxy.is_ssl:
            context = ssl._create_default_https_context()
        conn = Client(*await asyncio.wait_for(asyncio.open_connection(proxy.host, proxy.port, ssl=context), 5))
        await forward_http1(stream, conn, status)
    except Exception as e:
        logger.traceback()
        if not status.accepted:
            statistics.add_qps("proxy:" + proxy.url)
            client.write(CONNECT_TIMEOUT_RESPONSE.to_bytes())


class HTTPResponse:
    def __init__(
        self,
        status_code: int = 200,
        headers: Header = Header(),
        body: str = ""
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body

        self.headers.setdefault("Connection", "close")
        self.headers.setdefault("Content-Type", "text/html; charset=UTF-8")

    def to_bytes(self):
        content = self.body.encode("utf-8")
        self.headers["Content-Length"] = str(len(content))
        byte_header = f"HTTP/1.1 {self.status_code} {get_status_code_name(self.status_code)}\r\n"
        for k, v in self.headers.items():
            byte_header += f"{k}: {v}\r\n"
        byte_header += "\r\n"
        return byte_header.encode("utf-8") + content
    

CONNECT_TIMEOUT_RESPONSE = HTTPResponse(
    status_code=504,
    body="Gateway Timeout"
)
BAD_GATEWAY_RESPONSE = HTTPResponse(
    status_code=502,
    body="Bad Gateway"
)
REQUEST_TIMEOUT_RESPONSE = HTTPResponse(
    status_code=409,
    body="Request Timeout"
)

