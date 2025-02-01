import asyncio
from collections import deque
from dataclasses import dataclass
import ssl
import time
from typing import Optional

import anyio

from logger import logger
from .http2 import HTTP2GoAwayStream, HTTP2RstStream, HTTP2Stream, HTTP2FrameStream
from .common import statistics
from ..protocols import Protocol
from ..utils import Client, ClientStream, Header, get_status_code_name

import urllib.parse as urlparse

MAX_BUFFER = 1024 * 1024 * 4

class ProxyForward:
    def __init__(
        self,
        url: str,
        force_https: bool = False
    ):
        result = urlparse.urlparse(url)
        self.url = url
        self.host = result.hostname or "localhost"
        self.port = result.port or (
            443 if result.scheme == "https" else 80
        )
        self.scheme = result.scheme
        self.force_https = force_https

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
    elif protocol == Protocol.HTTP2:
        await process_http2_backend_proxy(client, hostname, proxy)
    #elif protocol == Protocol.HTTP2:
    #    await process_http2_backend_proxy(client, protocol, hostname, proxy)


async def open_connection( 
    ip: str,
    port: int,
    tls: bool = False,
):
    context = None
    if tls:
        context = ssl._create_default_https_context()
    return Client(*await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context), 5))

async def process_http2_backend_proxy(
    client: Client,
    host: str,
    proxy: ProxyForward
):
    await client.read(24)
    http2_stream = HTTP2Stream(client)
    connections: dict[int, asyncio.Task] = {}
    status_dict: dict[int, HTTPStatus] = {}
    async for stream in http2_stream:
        if isinstance(stream, HTTP2GoAwayStream):
            break
        stream_id = stream.stream_id
        if isinstance(stream, HTTP2FrameStream) and stream_id not in connections:
            status = HTTPStatus()
            status_dict[stream_id] = status
            status.proxy_url = proxy.url
            status.req_peername = client.peername[0]
            status.req_host = stream.host
            status.req_http_version = "HTTP/2"
            status.req_method = stream.method
            status.req_raw_path = stream.path
            status.req_user_agent = stream.headers.get_one("user-agent") or ""
            connections[stream_id] = asyncio.get_running_loop().create_task(
                _forward_http2_to_http1(
                    stream,
                    await open_connection(
                        proxy.host,
                        proxy.port,
                        proxy.is_ssl
                    ),
                    status_dict[stream_id]
                )
            )
            connections[stream_id].add_done_callback(lambda task: (connections.pop(stream_id, None), status_dict.pop(stream_id, None)))
            continue
        if isinstance(stream, HTTP2RstStream) and stream_id in connections:
            connections[stream_id].cancel()
    for task in connections.values():
        task.cancel()
    status_dict.clear()
            
async def _forward_http2_to_http1(
    stream: HTTP2FrameStream,
    conn: Client,
    status: 'HTTPStatus'
):
    try:
        await asyncio.gather(*(
            _forward_http2_req_to_http1(stream, conn, status),
            _forward_http1_resp_to_http2(stream, conn, status)
        ))
    except Exception as e:
        logger.traceback(f"Error while forwarding: {e}")
    finally:
        try:
            await conn.close()
        except:
            ...

async def _forward_http2_req_to_http1(
    stream: HTTP2FrameStream,
    conn: Client,
    status: 'HTTPStatus'
):
    status.req_time = time.perf_counter_ns()
    byte_header = f'{stream.method} {stream.path} HTTP/1.1\r\n'
    for k, v in stream.headers.items():
        for val in v:
            byte_header += f'{k}: {val}\r\n'
    byte_header += "\r\n"
    conn.write(byte_header.encode())
    await conn.drain()
    while (buffer := await stream.reader.read(MAX_BUFFER)):
        conn.write(buffer)
        await conn.drain()
        if stream.reader.at_eof():
            break

async def _forward_http1_resp_to_http2(
    stream: HTTP2FrameStream,
    conn: Client,
    status: 'HTTPStatus'
):
    while not conn.is_closing and (buffer := await conn.readuntil(b'\r\n\r\n')):
        status.resp_time = time.perf_counter_ns()
        status.accepted = True
        buffer = buffer[:-4]
        pre_byte_header, byte_header = buffer.split(b"\r\n", 1)
        http_version, status_code, status_text = pre_byte_header.decode().split(" ", 2)
        headers: Header = Header()
        for line in byte_header.split(b"\r\n"):
            if not line:
                break
            k, v = line.split(b": ", 1)
            headers.add(k.decode(), v.decode())
        await stream.send_response_header(
            status_code=int(status_code),
            headers=headers
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

        transfer = "Transfer-Encoding" in headers and (headers.get_one("Transfer-Encoding") or "").lower() == "chunked"
        content_length = int(headers.get_one("Content-Length", None) or 0)

        event_stream = "text/event-stream" in (headers.get_one("Content-Type") or "").lower()

        if event_stream:
            while not conn.is_closing and (data := await conn.read(MAX_BUFFER)):
                if not data:
                    break
                await stream.send_data(data)
                await stream.drain()

        if not event_stream and transfer:
            while not conn.is_closing and (data := await conn.readuntil(b"\r\n")):
                data_size = int(data[:-2], 16)
                size = 0
                while size < data_size and not conn.is_closing and (data := await conn.read(min(data_size - size, MAX_BUFFER))):
                    await stream.send_data(data)
                    size += len(data)
                # read 2 bytes \r\n
                await conn.read(2)
                if data_size == 0:
                    break
        elif content_length > 0:
            while content_length > 0 and not conn.is_closing and (data := await conn.read(min(content_length, MAX_BUFFER))):
                if not data:
                    break
                await stream.send_data(data)
                content_length -= len(data)
        if event_stream:
            while not conn.is_closing and (data := await conn.read(MAX_BUFFER)):
                if not data:
                    break
                await stream.send_data(data)

        await stream.send_data(b"")
        break
        


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
                data_size = int(data[:-2], 16)
                client.write(data)
                size = 0
                while size < data_size and not conn.is_closing and (data := await conn.read(min(data_size - size, MAX_BUFFER))):
                    client.write(data)
                    size += len(data)
                # read 2 bytes \r\n
                await conn.read(2)
                client.write(b"\r\n")
                await client.drain()
                if data_size == 0:
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
    stream = ClientStream(client)
    status.req_peername = client.peername[0]
    status.proxy_url = proxy.url

    if proxy.force_https and not client.is_tls:
        status.req_time = time.perf_counter_ns()
        buffer = await client.readuntil(b"\r\n\r\n")
        buffer = buffer[:-4]
        pre_byte_header, byte_headers = buffer.split(b"\r\n", 1)
        method, path, http_version = pre_byte_header.decode("utf-8").split(" ")
        headers = Header()
        for line in byte_headers.decode("utf-8").split("\r\n"):
            k, v = line.split(": ", 1)
            headers.add(k, v)

        status.req_http_version = http_version
        status.req_method = method
        status.req_raw_path = path
        status.req_user_agent = (headers.get_one("User-Agent") or "")
        status.req_host = (headers.get_one("Host") or "")


        await send_response(
            client,
            status,
            HTTPResponse(
                301,
                Header({
                    "Location": f"https://{status.req_host}{path}"
                })
            )
        )
        return


    try:
        conn = await open_connection(
            proxy.host,
            proxy.port,
            proxy.is_ssl
        )
    

        await forward_http1(stream, conn, status)
    except Exception as e:
        logger.traceback()
        if not status.accepted:
            await send_response(client, status, BAD_GATEWAY_RESPONSE)

async def send_response(
    client: Client,
    status: HTTPStatus,
    response: 'HTTPResponse'
):
    statistics.add_qps("proxy-gateway:" + status.proxy_url)
    status.resp_time = time.perf_counter_ns()
    statistics.print_access_log(
        "Proxy-Gateway",
        status.req_host,
        status.resp_time - status.req_time,
        status.req_method,
        status.req_raw_path,
        response.status_code,
        status.req_peername,
        status.req_user_agent,
        status.req_http_version
    )
    client.write(response.to_bytes())

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
            if isinstance(v, list):
                for val in v:
                    byte_header += f"{k}: {val}\r\n"
                continue
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

