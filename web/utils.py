import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
import ssl
from typing import Any, Optional, MutableMapping

forwards: dict[tuple[str, int], tuple[str, int]] = {}
forwards_count: defaultdict[tuple[str, int], int] = defaultdict(int)
forwards_config: dict[tuple[str, int], Any] = {}

class Client:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        peername: Optional[tuple[str, int]] = None,
    ):
        self._reader = reader
        self._writer = writer
        self._peername = peername
        self._buffers: deque[bytes] = deque()
        self._closed = False

    def __repr__(self):
        return f'<Client {self.peername!r} {self.sockname!r}>'

    @property
    def peername(self) -> tuple[str, int]:
        return self._peername or self._writer.get_extra_info('peername')
    
    @property
    def sockname(self) -> tuple[str, int]:
        return self._writer.get_extra_info('sockname')
    
    def feed_reader_data(self, data: bytes):
        self._buffers.appendleft(data)

    async def read(self, n: int) -> bytes:
        if self._buffers:
            data = self._buffers.pop()
            ret, body = data[:n], data[n:]
            if body:
                self._buffers.appendleft(body)
            return ret
        return await self._reader.read(n)
    
    async def readuntil(self, separator: bytes) -> bytes:
        ret = b''
        if self._buffers:
            data = b''.join(self._buffers)
            self._buffers.clear()
            if separator in data:
                ret, body = data.split(separator, maxsplit=1)
                if body:
                    self._buffers.appendleft(body)
                ret += separator
                return ret
            ret = data
        return ret + await self._reader.readuntil(separator)

    async def readexactly(self, n: int) -> bytes:
        buffer = b''
        while self._buffers:
            data = self._buffers.pop()
            buffer += data
            if len(buffer) >= n:
                ret, body = buffer[:n], buffer[n:]
                if body:
                    self._buffers.appendleft(body)
                return ret
        return buffer + await self._reader.readexactly(n)

    
    def write(self, data: bytes):
        self._writer.write(data)

    async def drain(self):
        await self._writer.drain()

    async def close(self, timeout: int = 10):
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        try:
            await asyncio.wait_for(self._writer.wait_closed(), timeout)
        except (asyncio.CancelledError, TimeoutError, ssl.SSLError):
            pass

    @property
    def is_closing(self):
        return self._writer.is_closing() or self._closed
    
    @property
    def is_tls(self):
        return self._writer.get_extra_info('ssl_object') is not None
    
class ForwardAddress:
    def __init__(
        self,
        origin: tuple[str, int],
        target: tuple[str, int],
        cfg: 'ForwardConfig'
    ):
        self.origin = origin
        self.target = target
        self.cfg = cfg

    def __enter__(self):
        forwards[self.target] = self.origin
        forwards_count[self.target] += 1
        forwards_config[self.origin] = self.cfg

    def __exit__(self, exc_type, exc_val, exc_tb):
        forwards_count[self.target] -= 1
        if forwards_count[self.target] == 0 and self.target in forwards:
            origin = forwards[self.target]
            del forwards_config[origin]
            del forwards[self.target]
            del forwards_count[self.target]
    
class ForwardConfig:
    def __init__(
        self,
        sni: Optional[str] = None,
        pub_port: Optional[int] = None,
        tls: bool = False,
    ):
        self.sni = sni
        self.pub_port = pub_port
        self.tls = tls

    def __repr__(self):
        return f'<ForwardConfig sni={self.sni!r} pub_port={self.pub_port!r}>'

class Header(dict[str, list[str]]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # convert
        headers: defaultdict[str, list[str]] = defaultdict(list)
        for k, v in self.items():
            if not isinstance(v, list):
                v = [v]
            headers[k.lower()].extend(v)
        self.clear()
        for k, v in headers.items():
            self[k] = v

    def _get_key(self, key: str):
        for k in self:
            if k.lower() == key.lower():
                return k
        return key

    def __getitem__(self, key: str):
        return super().__getitem__(self._get_key(key))

    def __setitem__(self, key: str, value: list[str] | str | None):
        if value is None:
            self.__delitem__(key)
            return
        if not isinstance(value, list):
            value = [value]
        super().__setitem__(self._get_key(key), value)

    def __delitem__(self, key: str):
        super().__delitem__(self._get_key(key))

    def get(self, key: str, default=None):
        return super().get(self._get_key(key), default or [])
    
    def get_one(self, key: str, default: Optional[Any] = None) -> Any:
        ret = self.get(key, default)
        if not ret:
            return default
        return ret[0]
    
    def setdefault(self, key: str, default=None):
        return super().setdefault(self._get_key(key), default or [])

    def add(self, key: str, value: str):
        key = self._get_key(key)
        if key in self:
            self[key].append(value)
        else:
            self[key] = [value]

    def update(self, data: dict[str, list[str]] | dict[str, str]):
        for k, v in data.items():
            if not isinstance(v, list):
                v = [v]
            for val in v:
                self.add(k, val)

    def set(self, key: str, value: str | list[str]):
        if not isinstance(value, list):
            value = [value]
        self[key] = value

    def copy(self):
        return Header(self)


@dataclass
class Cookie:
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[int] = None
    secure: Optional[bool] = None
    http_only: Optional[bool] = None
    same_site: Optional[str] = None

    def to_response_header(self):
        return f'{self.name}={self.value};' + \
            (f' domain={self.domain};' if self.domain else '') + \
            (f' path={self.path};' if self.path else '') + \
            (f' expires={self.expires};' if self.expires else '') + \
            (f' max-age={self.max_age};' if self.max_age else '') + \
            (f' secure;' if self.secure else '') + \
            (f' httponly;' if self.http_only else '') + \
            (f' samesite={self.same_site};' if self.same_site else '')

def get_status_code_name(status_code: int):
    return STATUS_CODES.get(status_code, "Unknown")


STATUS_CODES: dict[int, str] = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",
    421: "Misdirected Request",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    511: "Network Authentication Required",
}

def find_origin(sockname: tuple[str, int]):
    if sockname not in forwards:
        return sockname
    return find_origin(forwards[sockname])

def get_origin_cfg(sockname: tuple[str, int]):
    return forwards_config.get(sockname, None)
    
class ClientStream:
    def __init__(
        self,
        client: Optional[Client] = None,
        tls: bool = False
    ):
        self._client = client
        self._read_buffers: deque[bytes] = deque()
        self._wait_read: deque[asyncio.Future] = deque()
        self._write_buffers: deque[bytes] = deque()
        self._wait_write: deque[asyncio.Future] = deque()
        self._tls = tls
        self._eof = False

    def set_client(self, client: Client):
        self._client = client

    def write(self, data: bytes):
        if self._client is not None:
            self._client.write(data)
            return
        self._write_buffers.append(data)
    
    async def read(self, n: int):
        if len(self._read_buffers) == 0 and self._client is None:
            fut = asyncio.Future()
            self._wait_read.append(fut)
            try:
                await fut
            finally:
                if fut in self._wait_read:
                    self._wait_read.remove(fut)

        if self._read_buffers:
            buf = self._read_buffers.popleft()
            ret, buf = buf[:n], buf[n:]
            if buf:
                self._read_buffers.appendleft(buf)
            return ret
        if self._client is not None:
            return await self._client.read(n)
        raise EOFError

    async def readuntil(self, separator: bytes):
        ret = b''
        if self._read_buffers:
            data = b''.join(self._read_buffers)
            self._read_buffers.clear()
            if separator in data:
                ret, body = data.split(separator, maxsplit=1)
                if body:
                    self._read_buffers.appendleft(body)
                ret += separator
                return ret
            ret = data
        if self._client is None:
            raise EOFError
        return ret + await self._client.readuntil(separator)
    
    async def readexactly(self, n: int):
        buffer = b''
        while len(buffer) < n:
            buf = await self.read(n - len(buffer))
            if not buf:  # EOF
                raise asyncio.IncompleteReadError(buffer, n)
            buffer += buf
        return buffer

    async def read_write(self, n: int):
        if self._client is not None:
            raise RuntimeError("read_write can only be called on fake client")
        if len(self._write_buffers) == 0 and not self._eof:
            fut = asyncio.Future()
            self._wait_write.append(fut)
            try:
                await fut
            finally:
                self._wait_write.remove(fut)
        if len(self._write_buffers) == 0 and self._eof:
            return b''
        buf = self._write_buffers.popleft()
        ret, buf = buf[:n], buf[n:]
        if buf:
            self._write_buffers.appendleft(buf)
        return ret
    
    async def readuntil_write(self, separator: bytes):
        if self._client is not None:
            raise RuntimeError("readuntil_write can only be called on fake client")
        if len(self._write_buffers) == 0:
            fut = asyncio.Future()
            self._wait_write.append(fut)
            try:
                await fut
            finally:
                if fut in self._wait_write:
                    self._wait_write.remove(fut)
        buf = self._write_buffers.popleft()
        if separator in buf:
            ret, body = buf.split(separator, maxsplit=1)
            if body:
                self._write_buffers.appendleft(body)
            ret += separator
            return ret
        ret = buf
        return ret + await self.readuntil_write(separator)

    async def close(self):
        if self._client is not None:
            await self._client.close(5)
            self._client = None
        for fut in self._wait_read:
            fut.set_result(True)
        self._wait_read.clear()

    def feed_read_data(self, data: bytes):
        self._read_buffers.append(data)
        while self._read_buffers and self._wait_read:
            fut = self._wait_read.popleft()
            fut.set_result(True)
        
    def feed_write_data(self, data: bytes):
        self._write_buffers.append(data)
        while self._write_buffers and self._wait_write:
            fut = self._wait_write.popleft()
            fut.set_result(True)

    async def drain(self):
        if self._client is not None:
            await self._client.drain()
        while self._write_buffers and self._wait_write:
            fut = self._wait_write.popleft()
            fut.set_result(True)

    def feed_eof(self):
        self._eof = True
        if self._client is not None:
            return
        for fut in self._wait_read:
            fut.set_result(True)
        self._wait_read.clear()

    @property
    def transport(self):
        assert self._client is not None
        return self._client._writer.transport
    
    @property
    def is_closing(self):
        return self._client is not None and self._client.is_closing
    
    @property
    def is_tls(self):
        return self._tls