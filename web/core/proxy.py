import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
import ssl
import time
from typing import Optional

import hpack

from logger import logger
from .http2 import HTTP2Error, HTTP2Frame, HTTP2FrameType, HTTP2Connection, HTTP2FrameFlags
from .common import statistics
from ..protocols import Protocol
from ..utils import Client, ClientStream, Header, get_status_code_name

import urllib.parse as urlparse

MAX_BUFFER = 1024 * 1024 * 4

class ProxyForward:
    def __init__(
        self,
        url: str,
        force_https: bool = False,
        http2: bool = False
    ):
        result = urlparse.urlparse(url)
        self.url = url
        self.host = result.hostname or "localhost"
        self.port = result.port or (
            443 if result.scheme == "https" else 80
        )
        self.scheme = result.scheme
        self.force_https = force_https
        self.http2 = http2

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

class HTTP1Stream:
    def __init__(
        self,
        stream_id: int,
        conn: Client,
        connection: 'HTTP2WrapperConnection'
    ):
        self.stream_id = stream_id
        self.conn = conn
        self.connection = connection
        self.headers: asyncio.Future[Header] = asyncio.Future()
        self.req_data: asyncio.StreamReader = asyncio.StreamReader()
        self.status = HTTPStatus()
        self.task = asyncio.create_task(self._loop())

        self.status.req_host = self.connection.hostname
        self.status.req_peername = self.connection.client.peername[0]
        self.status.req_http_version = "HTTP/2"

    async def _loop(self):
        try:
            await asyncio.gather(
                self._recv(),
                self._send()
            )
        except:
            ...

    async def close(self):
        try:
            await asyncio.wait_for(self.conn.close(), 5)
        except:
            ...
        self.task.cancel()

    async def _recv(self):
        status = self.status
        while not self.conn.is_closing and (buffer := await self.conn.readuntil(b"\r\n\r\n")):
            status.resp_time = time.perf_counter_ns()

            # send settings ack

            #await self.connection.send_ack_settings()

            pre_byte_header, byte_header = buffer[:-4].split(b"\r\n", 1)
            status_code = pre_byte_header.split(b" ", 2)[1].decode()
            headers = Header()
            for line in byte_header.split(b"\r\n"):
                k, v = line.split(b": ", 1)
                headers.add(k.decode().lower(), v.decode())

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

            # send resp headers
            header_list = [
                (":status", status_code),
            ]
            for k, v in headers.items():
                if k.lower() == "transfer-encoding":
                    continue
                for val in v:
                    header_list.append((k, val))
            
            transfer = "chunked" == (headers.get_one("transfer-encoding", ""))
            content_length = int(headers.get_one("content-length", 0) or 0)
            event_stream = "text/event-stream" == (headers.get_one("content-type", ""))


            await self.connection.send_headers(
                header_list,
                self.stream_id,
                not transfer and not event_stream and content_length == 0
            )

            if event_stream:
                while not self.conn.is_closing and (data := await self.conn.read(MAX_BUFFER)):
                    if not data:
                        break
                    self.connection.send_data(data, self.stream_id)
            elif transfer:
                while not self.conn.is_closing and (data := await self.conn.readuntil(b"\r\n")):
                    data_size = int(data[:-2], 16)
                    size = 0
                    while size < data_size and not self.conn.is_closing and (data := await self.conn.read(min(data_size - size, MAX_BUFFER))):
                        size += len(data)
                        self.connection.send_data(data, self.stream_id)
                    await self.conn.read(2)
                    if data_size == 0:
                        break

            elif content_length > 0:
                while not self.conn.is_closing and content_length > 0 and (data := await self.conn.read(min(content_length, MAX_BUFFER))):
                    self.connection.send_data(data, self.stream_id)
                    content_length -= len(data)
                    if not data:
                        break
            self.connection.send_data(b"", self.stream_id)


    async def _send(self):
        status = self.status
        headers = await self.headers

        headers["X-Forwarded-For"] = status.req_peername
        headers["X-Forwarded-Proto"] = "https" if self.connection.client.is_tls else "http" 
        headers["X-Forwarded-Host"] = status.req_host
        headers["X-Real-IP"] = status.req_peername
        byte_header = f"{self.status.req_method} {self.status.req_raw_path} HTTP/1.1\r\nHost: {self.status.req_host}\r\n"
        for k, v in headers.items():
            for val in v:
                byte_header += f"{k}: {val}\r\n"
        byte_header += "\r\n"

        status.req_time = time.perf_counter_ns()
        statistics.add_qps("proxy:" + status.proxy_url)

        self.conn.write(byte_header.encode())
        await self.conn.drain()

        while not self.req_data.at_eof() and (buffer := await self.req_data.read(65535)):
            self.conn.write(buffer)
            await self.conn.drain()

            await self.connection.update_server_flow(self.stream_id, len(buffer))



    def feed_headers(self, header_list: list[tuple[str, str]]):
        method, path, host = "", "", ""
        headers = Header()
        for k, v in header_list:
            if k.startswith(":"):
                if k == ":method":
                    method = v
                elif k == ":path":
                    path = v
                elif k == ":authority":
                    host = v
                continue
            headers.add(k, v)
        if not method or not path or not host:
            raise Exception("Invalid headers")
        self.status.req_user_agent = headers.get_one("user-agent", "")
        self.status.req_method = method
        self.status.req_raw_path = path
        self.status.req_host = host
        self.headers.set_result(headers)

class HTTP2ClientConnection(HTTP2Connection):
    def __init__(
        self, 
        client: Client
    ):
        super().__init__(client)
        self.connection: Optional['HTTP2WrapperConnection'] = None
        self.status: defaultdict[int, HTTPStatus] = defaultdict(HTTPStatus)
        self._task = None

    def start_loop(self):
        self._task = asyncio.get_running_loop().create_task(self.recv())

    def __del__(self):
        if self._task is not None:
            self._task.cancel()

    async def send(self):
        await self.send_settings()

    async def recv(self):
        while not self.client.is_closing and (frame := await self.read_frame()):
            if frame.type in self.__recv_mappings:
                await self.__recv_mappings[frame.type](self, frame)
            elif self.connection is not None:
                await self.connection.send_frame(frame)

    async def _recv_settings(self, frame: HTTP2Frame):
        if frame.flags & HTTP2FrameFlags.ACK:
            return
        payload = frame.payload
        for i in range(0, len(payload), 6):
            settings_id = int.from_bytes(payload[i:i+2])
            value = int.from_bytes(payload[i+2:i+6])
            if settings_id not in self.settings._idx:
                continue
            setattr(self.settings, self.settings._idx[settings_id], value)
        if self.connection is not None:
            await self.connection.send_frame(frame)

        await self.send_ack_settings()

    async def _recv_headers(self, frame: HTTP2Frame):
        if frame.stream_id in self.status:
            status = self.status[frame.stream_id]
            payload = frame.payload
            if frame.padded:
                payload = payload[1:-payload[0]]
            if frame.priority:
                payload = payload[5:]
            header_list = self.decoder.decode(payload)
            status_code = None
            for k, v in header_list:
                if k == ":status":
                    status_code = int(v)
            if status_code is not None: 
                status.resp_time = time.perf_counter_ns()

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
        if self.connection is not None:
            await self.connection.send_frame(frame)
    __recv_mappings = {
        HTTP2FrameType.SETTINGS: _recv_settings,
        HTTP2FrameType.HEADERS: _recv_headers
    }

class HTTP2WrapperConnection(HTTP2Connection):
    def __init__(
        self,
        client: Client,
        hostname: str,
        proxy: ProxyForward,
    ):
        super().__init__(
            client
        )
        self.hostname = hostname
        self.proxy = proxy
        self.http1_streams: dict[int, HTTP1Stream] = {}
        self.connection: Optional[HTTP2ClientConnection] = None
        self.http2_frames: deque[HTTP2Frame] = deque()
        self.cfg_grpc = False
        self.grpc = False


    async def recv(self):
        while not self.client.is_closing and (frame := await self.read_frame()):
            if frame.type in self.__recv_mappings:
                await self.__recv_mappings[frame.type](self, frame)

    async def _recv_settings_frame(self, frame: HTTP2Frame):
        if frame.flags & HTTP2FrameFlags.ACK:
            return
        
        payload = frame.payload
        for i in range(0, len(payload), 6):
            settings_id = int.from_bytes(payload[i:i+2])
            value = int.from_bytes(payload[i+2:i+6])
            if settings_id not in self.settings._idx:
                continue
            setattr(self.settings, self.settings._idx[settings_id], value)

        self.client_flow.initial_window_size = self.settings.initial_window_size

        await self.send_ack_settings()

    async def _recv_window_update(self, frame: HTTP2Frame):
        inc = int.from_bytes(frame.payload)
        if frame.stream_id == 0:
            self.client_flow.update_connection_window(inc)

            #await self.send_window_update(frame.stream_id, inc)
            #self.server_flow.update_connection_window(inc)
        else:
            self.client_flow.update_stream_window(frame.stream_id, inc)

        if frame.stream_id not in self.http1_streams:
            await self.send_http2_connection(frame)

    async def _recv_rst_stream(self, frame: HTTP2Frame):
        stream_id = frame.stream_id
        if stream_id in self.http1_streams:
            asyncio.ensure_future(self.http1_streams[stream_id].close())
            del self.http1_streams[stream_id]
        else:
            await self.send_http2_connection(frame)

    async def _recv_headers(self, frame: HTTP2Frame):
        payload = frame.payload
        if frame.type == HTTP2FrameType.HEADERS:
            padding = 0
            if frame.padded:
                padding = frame.payload[0]
                payload = frame.payload[1:-padding]
            if frame.priority:
                payload = payload[5:]
        if not frame.end_headers:
            self.header_payloads[frame.stream_id] += payload
            return
        payload = self.header_payloads[frame.stream_id] + payload
        del self.header_payloads[frame.stream_id]

        header_list = self.decoder.decode(payload)
        headers = Header()
        for header in header_list:
            headers.add(header[0], header[1])
        
        grpc = "application/grpc" in (headers.get_one("content-type") or "")
        if not self.cfg_grpc:
            self.cfg_grpc = True
            self.grpc = grpc
        if grpc and not self.proxy.http2:
            await self.init_http2_connection()
            # send rst stream
            await self.send_rst_stream(frame.stream_id, HTTP2Error.PROTOCOL_ERROR)
            return
        if grpc:
            if self.connection is None:
                await self.init_http2_connection()
            assert self.connection is not None
            status = self.connection.status[frame.stream_id]
            status.req_peername = self.client.peername[0]
            status.req_host = headers.get_one(":authority")
            status.req_raw_path = headers.get_one(":path")
            status.req_method = headers.get_one(":method")
            status.req_http_version = "GRPC"
            status.req_user_agent = headers.get_one("user-agent")
            for k, v in {
                "X-Forwarded-For": status.req_peername,
                "X-Forwarded-Proto": "https" if self.client.is_tls else "http",
                "X-Forwarded-Host": status.req_host,
                "X-Real-IP": status.req_peername,
            }.items():
                header_list.append((k.lower(), v))
            
            status.req_time = time.perf_counter_ns()

            await self.send_http2_connection(
                HTTP2Frame(
                    HTTP2FrameType.HEADERS,
                    HTTP2FrameFlags.END_HEADERS,
                    frame.stream_id,
                    self.connection.encoder.encode(header_list)
                )
            )
            return

        if frame.stream_id not in self.http1_streams:
            conn = await open_connection(
                self.proxy.host,
                self.proxy.port,
                self.proxy.is_ssl
            )
            stream = HTTP1Stream(
                frame.stream_id,
                conn,
                self
            )
            self.http1_streams[frame.stream_id] = stream
        
        stream.feed_headers(header_list)

    async def _recv_data(self, frame: HTTP2Frame):
        #await self.recver_flow.wait(frame.stream_id)
        self.server_flow.streams[frame.stream_id] -= len(frame.payload)
        self.server_flow.window_size -= len(frame.payload)
        payload = frame.payload
        if frame.padded:
            payload = payload[:-frame.payload[0]]

        if frame.stream_id not in self.http1_streams:
            await self.send_http2_connection(frame)
            return

        if frame.stream_id not in self.http1_streams:
            return
        self.http1_streams[frame.stream_id].req_data.feed_data(payload)
        if frame.end_stream:
            self.http1_streams[frame.stream_id].req_data.feed_eof()

    async def _recv_ping(self, frame: HTTP2Frame):
        if frame.flags & HTTP2FrameFlags.ACK:
            return
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.PING,
                HTTP2FrameFlags.ACK,
                0,
                frame.payload
            )
        )

    async def _recv_goway(self, frame: HTTP2Frame):
        await self.close()

    async def close(self):
        for stream in self.http1_streams.values():
            await stream.close()
        self.http1_streams.clear()
        if self.connection is not None:
            await self.connection.client.close()
        await self.client.close()

    async def init_http2_connection(self):
        conn = await open_connection(
            self.proxy.host,
            self.proxy.port,
            self.proxy.is_ssl
        )
        conn.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        await conn.drain()
        conn = HTTP2ClientConnection(
            conn
        )
        await conn.send()
        self.connection = conn
        self.connection.connection = self
        conn.start_loop()


    async def send_http2_connection(self, frame: HTTP2Frame):
        if self.cfg_grpc and not self.grpc:
            return
        if self.connection is None:
            self.http2_frames.append(frame)
            return
        frames = []
        if self.http2_frames:
            frames.extend(self.http2_frames)
            self.http2_frames.clear()
        frames.append(frame)
        await self.connection.send_frame(*frames)

    __recv_mappings = {
        HTTP2FrameType.SETTINGS: _recv_settings_frame,
        HTTP2FrameType.WINDOW_UPDATE: _recv_window_update,
        HTTP2FrameType.RST_STREAM: _recv_rst_stream,
        HTTP2FrameType.HEADERS: _recv_headers,
        HTTP2FrameType.DATA: _recv_data,
        HTTP2FrameType.CONTINUATION: _recv_headers,
        HTTP2FrameType.PING: _recv_ping,
        HTTP2FrameType.GOAWAY: _recv_goway
    }



async def process_http2_backend_proxy(
    client: Client,
    hostname: str,
    proxy: ProxyForward
):
    # read magic
    await client.read(24)
    connection = HTTP2WrapperConnection(
        client,
        hostname,
        proxy,
    )
    try:
        coroutines = [
            connection.recv(),
            connection.send()
        ]
        await asyncio.gather(*coroutines)
    except (
        asyncio.exceptions.IncompleteReadError,
        GeneratorExit
    ):
        ...
    except:
        logger.traceback()
    finally:
        await connection.close()

    


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
        headers["X-Forwarded-Proto"] = "https" if client.is_tls else "http"
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

