import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
import enum
import ssl
import time
from typing import Callable, Optional

import units

from logger import logger
import urllib.parse as urlparse

BUFFER = 1024 * 1024 * 4

forward_address: dict[tuple[str, int], tuple[str, int]] = {}
forward_address_count: defaultdict[tuple[str, int], int] = defaultdict(int)
forward_address_info: dict[tuple[str, int], 'ForwardAddressInfo'] = {}
proxy_url: dict[str, urlparse.ParseResult] = {}

class ForwardAddressInfo:
    def __init__(
        self,
        sni: Optional[str] = None
    ):
        self.sni = sni

    def __repr__(self) -> str:
        return f"ForwardAddressInfo(sni={self.sni})"

class ForwardAddress:
    def __init__(
        self,
        origin: tuple[str, int],
        target: tuple[str, int],
        sni: Optional[str] = None
    ):
        self.origin = origin
        self.target = target
        self.sni = sni
    
    def __enter__(self):
        forward_address_count[self.origin] += 1
        forward_address[self.target] = self.origin
        forward_address_info[self.origin] = ForwardAddressInfo(self.sni)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        forward_address_count[self.origin] -= 1
        if forward_address_count[self.origin] == 0 and self.target in forward_address:
            del forward_address[self.target]
            if self.origin in forward_address_info:
                del forward_address_info[self.origin]
        return self

class Client:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: Optional[tuple[str, int]] = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._addr = addr
        self._buffers: deque[bytes] = deque()

    @property
    def address(self) -> tuple[str, int]:
        return self._addr or self._writer.get_extra_info("peername")
    
    def feed_data(self, data: bytes) -> None:
        self._buffers.appendleft(data)

    async def read(self, n: int) -> bytes:
        if self._buffers:
            buffer = self._buffers.popleft()
            if len(buffer) > n:
                self._buffers.appendleft(buffer[n:])
                return buffer[:n]
            else:
                return buffer
        return await self._reader.read(n)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()

    @property
    def is_closing(self):
        return self._writer.is_closing()

def find_origin_ip(target: tuple[str, int]):
    if target not in forward_address:
        return target
    return find_origin_ip(forward_address[target])

def get_origin_info(target: tuple[str, int]):
    if target not in forward_address_info:
        return None
    return forward_address_info[target]

class Protocol(enum.Enum):
    HTTP1 = "http/1"
    HTTP2 = "http/2"

protocols: dict[Protocol, Callable[[bytes], bool]] = {
    Protocol.HTTP1: lambda x: x.split(b"\r\n", 1)[0].split(b" ")[-1].startswith(b"HTTP/1."),
    Protocol.HTTP2: lambda x: x.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
}

def get_protocol(data: bytes):
    for protocol in Protocol:
        if protocol not in protocols:
            continue
        try:
            if protocols[protocol](data):
                return protocol
        except:
            ...
    return None

class Header(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _get_key(self, key: str):
        for k in self:
            if k.lower() == key.lower():
                return k
        return key

    def __getitem__(self, key: str):
        return super().__getitem__(self._get_key(key))

    def __setitem__(self, key: str, value):
        super().__setitem__(self._get_key(key), value)

    def __delitem__(self, key: str):
        super().__delitem__(self._get_key(key))

    def get(self, key: str, default=None):
        return super().get(self._get_key(key), default)
    def setdefault(self, key: str, default=None):
        return super().setdefault(self._get_key(key), default)

async def _forward(from_conn: Client, to_conn: Client):
    while not from_conn.is_closing and (buffer := await from_conn.read(16384)):
        await to_conn.write(buffer)

class HTTPConfig:
    ip: str
    port: int
    host: str
    version: str
    scheme: str = "http"
    current_req_path: str
    current_req_method: str
    current_req_timestamp: int
    current_user_agent: str
    current_host: str
    keepalive: Optional[asyncio.Future] = None

async def _process_http1_req(
    client: Client,
    conn: Client,
    config: HTTPConfig
):
    while not client.is_closing and (buffer := await client.read(16384)):
        if config.keepalive is not None and not config.keepalive.done():
            config.keepalive.set_result(True)
        byte_header, byte_body = buffer.split(b"\r\n\r\n", 1)
        client.feed_data(byte_body)
        pre_byte_header, byte_header = byte_header.split(b"\r\n", 1)
        method, url, version = pre_byte_header.decode("utf-8").split(" ")
        headers = Header({
            k: v for k, v in (
                line.split(": ", 1) for line in byte_header.decode("utf-8").split("\r\n")
            )
        })
        config.version = version
        config.current_req_path = url
        config.current_req_method = method
        config.current_user_agent = headers.get("User-Agent", "")
        config.current_host = headers.get("Host", "")
        req_header = f"{method} {url} HTTP/1.1\r\n".encode()
        if "Referer" in headers:
            headers["Referer"] = f"{config.scheme}://{config.host}/{config.current_req_path}"
        if "Origin" in headers:
            headers["Origin"] = f"{config.scheme}://{config.host}"
        headers["X-Forwarded-For"] = client.address[0]
        headers["X-Real-IP"] = client.address[0]
        for k, v in headers.items():
            req_header += f"{k}: {v}\r\n".encode()
        await conn.write(req_header + b"\r\n")
        config.current_req_timestamp = time.perf_counter_ns()
        content_length = int(headers.get("Content-Length", 0))
        read_length = 0
        data = await client.read(min(BUFFER, content_length))
        read_length += len(data)
        await conn.write(data)
        while read_length < content_length:
            data = await client.read(min(BUFFER, content_length - read_length))
            read_length += len(data)
            await conn.write(data)
        if "Connection" in headers and headers["Connection"].lower() == "upgrade":
            while not client.is_closing and (buffer := await client.read(16384)):
                await conn.write(buffer)
        continue

async def _process_http1_resp(
    client: Client,
    conn: Client,
    config: HTTPConfig
):
    while not conn.is_closing and (buffer := await conn.read(16384)):
        end_resp = time.perf_counter_ns()
        byte_header, byte_body = buffer.split(b"\r\n\r\n", 1)
        conn.feed_data(byte_body)
        pre_byte_header, byte_header = byte_header.split(b"\r\n", 1)
        version, status, reason = pre_byte_header.decode("utf-8").split(" ", 2)
        headers = Header({
            k: v for k, v in (
                line.split(": ", 1) for line in byte_header.decode("utf-8").split("\r\n")
            )
        })
        status = int(status)
        resp_header = f"{config.version} {status} {reason}\r\n".encode()
        for k, v in headers.items():
            resp_header += f"{k}: {v}\r\n".encode()
        await client.write(resp_header + b"\r\n")
        read_length = 0
        if "Transfer-Encoding" in headers and headers["Transfer-Encoding"] == "chunked":
            while not client.is_closing and (data := await conn.read(16384)):
                await client.write(data)
                read_length += len(data)
                if data.endswith(b"0\r\n\r\n"):
                    break
        else:
            content_length = int(headers.get("Content-Length", 0))
            data = await conn.read(min(BUFFER, content_length))
            read_length += len(data)
            await client.write(data)
            while read_length < content_length:
                data = await conn.read(min(BUFFER, content_length - read_length))
                read_length += len(data)
                await client.write(data)
        print_req_resp(
            config.current_req_method,
            status,
            config.current_user_agent,
            client.address[0],
            config.current_host,
            config.current_req_path,
            read_length,
            end_resp - config.current_req_timestamp
        )
        if status == 101 and "Upgrade" in headers and headers["Upgrade"].lower() == "websocket":
            while not client.is_closing and (data := await conn.read(16384)):
                await client.write(data)
        if "Content-Type" in headers:
            content_type = headers["Content-Type"]  
            if content_type.startswith("text/event-stream"):
                while not client.is_closing and (data := await conn.read(16384)):
                    await client.write(data)
        if "Connection" in headers and headers["Connection"] == "close":
            break
        if "Keep-Alive" in headers:
            config.keepalive = asyncio.get_event_loop().create_future()
            try:
                keepalives = {
                    k.lower(): v for k, v in (
                        line.split("=", 1)
                        for line in headers["Keep-Alive"].split(", ")
                    )
                }
                if "timeout" not in keepalives:
                    continue
                await asyncio.wait_for(config.keepalive, int(keepalives["timeout"]))
            except (asyncio.TimeoutError, asyncio.CancelledError):
                raise
            except:
                ...

async def process_http1(client: Client, sni: Optional[str] = None):
    buffer = await client.read(4096)
    if b"\r\n\r\n" not in buffer:
        return
    
    byte_header, byte_body = buffer.split(b"\r\n\r\n", 1)
    pre_byte_header, byte_header = byte_header.split(b"\r\n", 1)
    headers = Header({
        k: v for k, v in (
            line.split(": ", 1) for line in byte_header.decode("utf-8").split("\r\n")
        )
    })
    client.feed_data(buffer)
    config = HTTPConfig()
    config.host = urlparse.urlparse(f'http://{sni or headers.get("Host", "localhost")}').hostname or ""
    if config.host not in proxy_url:
        return
    proxy = proxy_url[config.host]
    config.scheme = proxy.scheme or "http"
    config.port = get_parse_url_port(proxy)
    config.ip = proxy.hostname or "127.0.0.1"
    context = None
    if proxy.scheme == "https":
        context = ssl.create_default_context()
        context.load_default_certs()
        context.set_default_verify_paths()

    try:
        conn = Client(*await asyncio.wait_for(asyncio.open_connection(host=config.ip, port=config.port, ssl=context), 5))
        try:
            await asyncio.gather(
                _process_http1_req( client, conn, config),
                _process_http1_resp(client, conn, config)
            )
        except (
            asyncio.TimeoutError,
            ConnectionAbortedError,
            ConnectionResetError,
            ConnectionRefusedError,
            ssl.SSLZeroReturnError,
            ssl.SSLError,
            asyncio.CancelledError
        ):
            return
        except:
            logger.traceback()
        finally:
            await conn.close()
    except:
        logger.traceback()

async def process(client: Client, sni: Optional[str] = None):
    buffer = await client.read(4096)
    protocol = get_protocol(buffer)
    client.feed_data(buffer)
    if protocol is None:
        return
    if protocol == Protocol.HTTP1:
        await process_http1(client, sni)
    if protocol == Protocol.HTTP2:
        print("HTTP2")
    try:
        await client.close()
    except:
        ...


def print_req_resp(
    method: str,
    status: int,
    user_agent: str,
    address: str,
    host: str,
    path: str,
    size: int,
    time: int
):
    logger.info(f"{host} | {units.format_count_time(time, 4).rjust(12)} | {units.format_bytes(size).rjust(12)} | {address.rjust(16)} | {method.ljust(9)} {str(status)} | {path} - {user_agent}")

def get_parse_url_port(url: urlparse.ParseResult):
    if url.port:
        return url.port
    if url.scheme == "https":
        return 443
    if url.scheme == "http":
        return 80
    return 80

def add_proxy(host: str, url: str):
    proxy_url[host] = urlparse.urlparse(url)
