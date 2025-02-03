import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, is_dataclass
import datetime
import hashlib
import inspect
import json
from pathlib import Path
import re
import time
from typing import Any, AsyncGenerator, AsyncIterable, AsyncIterator, Callable, Coroutine, Generator, Iterable, Iterator, Optional, Union, get_args, get_type_hints
import urllib.parse as urlparse
import uuid

from .compresstor import compress

from . import filetype
from bson import ObjectId

from logger import logger
from .common import statistics
from ..protocols import Protocol

from ..utils import Client, ClientStream, Cookie, Header, get_status_code_name

from .http2 import MAX_BUFFER, HTTP2Frame, HTTP2FrameType, HTTP2Connection, HTTP2FrameFlags

CONTENT_TYPES = Union[
    str, 
    
    int,
    bool,
    float,

    list,
    tuple,
    dict,
    set,
    
    Generator[bytes | str, None, None],
    Iterable [bytes | str],
    Iterator [bytes | str],

    AsyncGenerator[bytes | str, None],
    AsyncIterable [bytes | str],
    AsyncIterator [bytes | str],


    bytes, 
    bytearray, 
    memoryview,
    Callable,
    Coroutine,

    'Response',
    Path,
    None
]

@dataclass  
class RouteHandlerArg:  
    name: str  
    type_annotation: list[Any]
    default: Any = inspect._empty 

    @property
    def required(self) -> bool:
        return self.default is inspect._empty
  
class RouteHandlerArgs:  
    def __init__(self, handler) -> None:  
        self.handler = handler
        self.handler_args = inspect.getfullargspec(handler)  
        annotations_params = get_type_hints(handler)  
        defaults = self.handler_args.defaults or ()
        offset = len(self.handler_args.args) - len(defaults)
        self.route_handler_args = [  
            RouteHandlerArg(name=param, type_annotation=self._get_annotations(annotations_params.get(param, Any)), default=defaults[i - offset] if i - offset >= 0 else inspect._empty)  
            for i, param in enumerate(self.handler_args.args)  
        ]  
        self.kwargs = self.handler_args.varkw
        self.return_annotation = self.handler_args.annotations.get("return", Any)

    def _get_annotations(self, value: Any):
        if hasattr(value, "__origin__") and value.__origin__ is Union:
            return list(get_args(value))
        return [value]

    def __str__(self) -> str:
        return f"<{self.handler}: {self.route_handler_args}>"

class Route:
    def __init__(
        self,
        path: str,
        function: Callable[..., Any]
    ):
        self._path = path.strip("/")
        if not self._path.startswith("/"):
            self._path = "/" + self._path
        self._function = function
        self._parameters = RouteHandlerArgs(self._function)
        self._has_params = self._path.count("{") == self._path.count("}") >= 1
        self._re_path = re.compile("^" + self._replace_path(self._path) + "[/]?$")

    def _replace_path(self, path: str):
        # if {:url:} in path, replace it and not [^/]*
        if path.endswith("/{:url:}"):
            path = path.replace("/{:url:}", r"/(?P<url>.*)")
        elif path.endswith("{:url:}"):
            path = path.replace("{:url:}", r"(?P<url>.*)")
        return path.replace("{", "(?P<").replace("}", ">[^/]*)")
    
    @property
    def raw_path(self):
        return self._path
    
    @property
    def re_path(self):
        return self._re_path

    @property
    def has_params(self):
        return self._has_params

    @property
    def parameters(self):
        return self._parameters
    
    @property
    def function(self):
        return self._function

class RouteResult:
    def __init__(
        self,
        match: re.Match,
        route: Route
    ):
        self.match = match
        self.route = route

class Router:
    def __init__(
        self,
        prefix: str = "/"
    ):
        self._prefix = prefix
        self._routes: defaultdict[str, list['Route']] = defaultdict(list)
        self._mounts: defaultdict[str, list[Path]] = defaultdict(list)

    def add_route(
        self,
        method: str,
        path: str,
        function: Callable[..., Any]
    ):
        self._routes[method.upper()].append(
            Route(
                path,
                function
            )
        )

    def get_route(
        self,
        request: 'Request'
    ):
        method = request.method.upper()
        path = request.path
        if self._prefix and path.startswith(self._prefix):
            path = path[len(self._prefix):]
            if not path.startswith("/"):
                path = "/" + path
        for route in self._routes[method]:
            match = route.re_path.match(path)
            if match is not None:
                return RouteResult(
                    match,
                    route
                )
        return None


    def get(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("GET", path, function)
            return function
        return wrapper
    
    def post(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("POST", path, function)
            return function
        return wrapper
    
    def put(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("PUT", path, function)
            return function
        return wrapper

    def delete(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("DELETE", path, function)
            return function
        return wrapper

    def patch(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("PATCH", path, function)
            return function
        return wrapper
    
    def options(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("OPTIONS", path, function)
            return function
        return wrapper
    
    def head(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("HEAD", path, function)
            return function
        return wrapper
    
    def trace(self, path: str):
        def wrapper(function: Callable[..., Any]):
            self.add_route("TRACE", path, function)
            return function
        return wrapper
    
    def mount(self, path: str, root: Path):
        self._mounts[path].append(root)

    def get_mount(self, path: str) -> Any:
        if self._prefix and path.startswith(self._prefix):
            path = path[len(self._prefix):]
            if not path.startswith("/"):
                path = "/" + path
        roots = None
        for mount_path, mount_root in sorted(self._mounts.items(), key=lambda x: len(x[0]), reverse=True):
            if path.startswith(mount_path):
                roots = mount_root
                path = path[len(mount_path):].lstrip("/")
                break
        if roots is None:
            return 404
        forbidden = False
        for root in roots:
            file = root / path
            if not str(file).startswith(str(root)):
                forbidden = True
                continue
            if file.is_file():
                return file
        if forbidden:
            return 403
        return 404

class RequestTiming:
    def __init__(
        self,
        request: 'Request'
    ):
        self._request = request
        self._start: Optional[int] = None
        self._end: Optional[int] = None
        self._response: Optional['Response'] = None

    def __enter__(self):
        self._start = time.perf_counter_ns()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    async def set_result(self, res: 'Response'):
        self._response = res
        self._end = time.perf_counter_ns()
        await self.print()

    async def print(self):
        assert self._start is not None
        assert self._end is not None
        assert self._response is not None
        statistics.print_access_log(
            type="Application",
            host=self._request.hostname,
            rtt=self._end - self._start,
            method=self._request.method,
            path=self._request.raw_path,
            status=self._response.status,
            address=self._request.address,
            user_agent=self._request.user_agent,
            http_version=self._request.http_version
        )


class Application:
    def __init__(
        self,
        force_https: bool = False
    ):
        self._routers: deque['Router'] = deque(
            [
                Router()
            ]
        )
        self._force_https = force_https

    def get(self, path: str):
        return self._routers[0].get(path)

    def post(self, path: str):
        return self._routers[0].post(path)

    def put(self, path: str):
        return self._routers[0].put(path)

    def delete(self, path: str):
        return self._routers[0].delete(path)
    
    def patch(self, path: str):
        return self._routers[0].patch(path)

    def options(self, path: str):
        return self._routers[0].options(path)

    def head(self, path: str):
        return self._routers[0].head(path)

    def trace(self, path: str):
        return self._routers[0].trace(path)
    
    def mount(self, path: str, root: Path):
        return self._routers[0].mount(path, root)

    def add_router(self, router: Router):
        self._routers.append(router)
        return router
    
    def get_route(self, request: 'Request'):
        route = None
        for router in self._routers:
            route = router.get_route(request)
            if route is not None:
                break
        return route

    async def handle(
        self,
        request: 'Request'
    ) -> Any:
        statistics.add_qps("application:" + repr(self))
        if self._force_https and not request.client.is_tls:
            await LocationResponse("https://" + request.hostname + request.raw_path)(request)
            return
        with RequestTiming(request) as timing:
            route = self.get_route(request)
            result = inspect._empty
            if route is not None:
                result = await self.handle_route(request, route)
            if result is inspect._empty:
                result = self.get_mount(request.path)
                if isinstance(result, int):
                    result = Response(
                        status=result,
                        content=get_status_code_name(result)
                    )
            if not isinstance(result, Response):
                result = Response(result)
        try:
            await result(request, timing)
        except:
            logger.traceback()

    def get_mount(self, path: str) -> Any:
        for router in self._routers:
            result = router.get_mount(path)
            if not isinstance(result, int):
                return result
        return 404

    async def handle_route(self, request: 'Request', route_result: 'RouteResult') -> Any:
        func = route_result.route.parameters
        handle = func.handler
        params = {}
        url_params = route_result.match.groupdict()
        json_params = None
        for arg in func.route_handler_args:
            if Request in arg.type_annotation:
                params[arg.name] = request
            elif Application in arg.type_annotation:
                params[arg.name] = self
            else:
                # first url param
                if arg.name in url_params:
                    params[arg.name] = url_params[arg.name]
                elif arg.name in request.query:
                    params[arg.name] = request.query[arg.name]
                    if len(params[arg.name]) == 1:
                        params[arg.name] = params[arg.name][0]
                elif request.is_json:
                    if json_params is None:
                        json_params = await request.json()
                    if arg.name in json_params:
                        params[arg.name] = json_params[arg.name]

                elif request.is_www_form:
                    if json_params is None:
                        json_params = await request.json()
                    if arg.name in json_params:
                        params[arg.name] = json_params[arg.name]
        res = inspect._empty
        if inspect.iscoroutinefunction(handle):
            res = await handle(**params)
        else:
            res = await asyncio.get_running_loop().run_in_executor(None, lambda: handle(**params))
        return res


class Request:
    def __init__(
        self,
        client: ClientStream,
        method: str,
        path: str,
        http_version: str,
        headers: Header,
        peername: tuple[str, int]
    ) -> None:
        self._client = client
        self._method = method
        self._raw_path = urlparse.unquote(path)
        self._http_version = http_version
        self._headers = headers
        self._peername = peername
        self._address = peername[0]
        self._parse_path()
    
    @property
    def client(self) -> ClientStream:
        return self._client

    @property
    def address(self) -> str:
        return self._address
    
    @property
    def accept_encoding(self):
        return self.headers.get_one("Accept-Encoding") or ""

    @property
    def raw_path(self):
        return self._raw_path
    
    @property
    def user_agent(self):
        return self.headers.get_one("User-Agent") or ""

    @property
    def method(self) -> str:
        return self._method

    @property
    def hostname(self):
        return self.headers.get_one("Host", "") or ""

    @property
    def path(self) -> str:
        return self._path

    @property
    def query(self):
        return self._query

    @property
    def range(self):
        start_bytes, end_bytes = 0, None
        if 'Range' not in self.headers:
            return start_bytes, end_bytes
        range = (self.headers.get_one('Range') or "").split('=')[1]
        if '-' in range:
            start_bytes, end_bytes = map(lambda x: int(x) if x else None, range.split('-'))
        else:
            start_bytes = int(range)
        start_bytes = start_bytes or 0
        return start_bytes, end_bytes

    @property
    def http_version(self) -> str:
        return self._http_version

    @property
    def headers(self) -> Header:
        return self._headers

    @property
    def is_json(self):
        return (self.headers.get_one("Content-Type") or "").startswith("application/json") and self.method in ("POST", "PUT", "PATCH") and self.headers.get_one("Content-Length") or 0 > 0

    @property
    def is_www_form(self):
        return (self.headers.get_one("Content-Type") or "").startswith("application/x-www-form-urlencoded") and self.method in ("POST", "PUT", "PATCH") and self.headers.get_one("Content-Length") or 0 > 0
    
    async def read(self):
        content_length = int(self.headers.get_one("Content-Length") or 0)
        content = b''
        while len(content) < content_length:
            chunk = await self._client.read(16384)
            if not chunk:
                break
            content += chunk
        return content

    async def json(self):
        body = await self.read()
        return json.loads(body)

    def _parse_path(self):
        if not hasattr(self, "_path") or not hasattr(self, "_query"):
            parsed = urlparse.urlparse(self._raw_path)
            self._path = urlparse.unquote(parsed.path)
            self._query = urlparse.parse_qs(parsed.query)

    def __repr__(self) -> str:
        return f"<Request {self.method} {self.path}>"

class Response:
    def __init__(
        self, 
        content: CONTENT_TYPES = None,
        content_type: Optional[str] = None,
        headers: Optional['Header'] = None,
        cookies: Optional[list['Cookie']] = None,
        status: int = 200,
    ):
        self.content: CONTENT_TYPES = content
        self.content_type = content_type
        self.cookies = cookies or []
        self.headers = headers or Header({})
        self.status = status

    def __repr__(self) -> str:
        return f'<Response {self.status} {self.headers}>'
    
    async def get_content(self):
        if self.content is None:
            return memoryview(b'')
        if isinstance(self.content, Response):
            t = self.content
            for k in (param.name for param in inspect.signature(Response).parameters.values()
                    if not param.default == inspect.Parameter.empty 
                    and not inspect.isbuiltin(param.default)
            ):
                setattr(self, k, getattr(t, k))
            self.content = t.content
            return await self.get_content()
        if isinstance(self.content, Path):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'application/octet-stream'
            return self.content
        if isinstance(self.content, str):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'text/plain'
            return memoryview(self.content.encode('utf-8'))
        if isinstance(self.content, bytes):
            self.content_type = self.content_type or filetype.guess_mime(self.content) or 'application/octet-stream'
            return memoryview(self.content)
        if isinstance(self.content, ObjectId):
            self.content_type = self.content_type or 'application/json'
            return memoryview(json_dumps(self.content).encode('utf-8'))
        if isinstance(self.content, memoryview):
            self.content_type = self.content_type or filetype.guess_mime(self.content.tobytes()) or 'application/octet-stream'
            return memoryview(self.content.tobytes())
        if isinstance(self.content, (list, set, tuple, dict, bool, int, float)) or is_dataclass(self.content):
            self.content_type = self.content_type or 'application/json'
            return memoryview(json_dumps(self.content).encode('utf-8'))
        if isinstance(self.content, (AsyncGenerator, AsyncIterable, AsyncIterator, Generator, Iterable, Iterator)):
            self.content_type = self.content_type or 'application/octet-stream'
            return self.content
        if isinstance(self.content, bytearray):
            self.content_type = self.content_type or 'application/octet-stream'
            return memoryview(self.content)
        if asyncio.iscoroutine(self.content):
            self.content = await self.content
            return await self.get_content()
        if isinstance(self.content, Callable):
            self.content = await asyncio.get_event_loop().run_in_executor(None, self.content)
            return await self.get_content()
        if inspect.isgenerator(self.content):
            self.content = async_generator(self.content)
            return await self.get_content()
        return self.content
    
    async def __call__(self, request: 'Request', timing: Optional[RequestTiming] = None):
        content = await self.get_content()
        # if content instanceof Any, warning
        extra_headers = Header({})
        length = None
        if isinstance(content, Path):
            stat = content.stat()
            length = stat.st_size
            if self.content_type is None or ("text/" not in self.content_type and "application/json" not in self.content_type):
                extra_headers['Content-Disposition'] = f'attachment; filename="{content.name}"'
            etag = get_etag(content)
            if request.headers.get_one("If-None-Match", "") == etag and self.status == 200:
                self.status = 304
                content = memoryview(b'')
            extra_headers["ETag"] = etag
            extra_headers["Last-Modified"] = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%a, %d %b %Y %H:%M:%S GMT')
            #extra_headers["Cache-Control"] = "public, max-age=31536000"
        elif isinstance(content, memoryview):
            length = len(content)
        elif Any in type(content).__mro__:
            logger.debug(f'content is Any, {content}')

        # headers, to response headers
        headers = self.headers.copy()
        headers.update(extra_headers)
        headers.update({
            "Server": "TTB-Network",
            "Date": datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
        })
        start_bytes, end_bytes = request.range
        if length is not None:
            if end_bytes is not None:
                headers["Content-Range"] = f"bytes {start_bytes}-{end_bytes}/{length}"
                headers["Accept-Ranges"] = "bytes"
                length = end_bytes - start_bytes + 1
            else:
                headers["Content-Length"] = str(length)
            if isinstance(content, memoryview):
                compression = compress(content.tobytes(), request.accept_encoding)
                if compression.compressed:
                    headers["Content-Encoding"] = compression.compression
                    headers["Content-Length"] = str(compression.length)
                    content = memoryview(compression.data)
                content = memoryview(content.tobytes())[start_bytes:start_bytes + length]
            if self.content_type is not None:
                headers["Content-Type"] = self.content_type
        else:
            headers["Transfer-Encoding"] = "chunked"
    
        byte_header = f'{request.http_version} {self.status} {get_status_code_name(self.status)}\r\n'
        self.add_content_type_encoding(headers)
        for k, v in headers.items():
            if v is None:
                continue
            if isinstance(v, list):
                for val in v:
                    byte_header += f'{k}: {val}\r\n'
                continue
            byte_header += f'{k}: {v}\r\n'
        byte_header += '\r\n'
        # cookie
        if self.cookies:
            byte_header += '\r\n'.join([cookie.to_response_header() for cookie in self.cookies]) + '\r\n'
        if timing is not None:
            await timing.set_result(self)

        request.client.write(byte_header.encode('utf-8'))
        if request.method == 'HEAD':
            return self
        if isinstance(content, memoryview):
            request.client.write(content)
            await request.client.drain()
        elif inspect.isasyncgen(content) or inspect.isgenerator(content):
            if inspect.isgenerator(content):
                content = async_generator(content)
            async for chunk in content:
                request.client.write(send_chunk(chunk))
            request.client.write(send_chunk(b''))
            await request.client.drain()
        elif isinstance(content, Path):
            try:
                await self._send_file(request, content, start_bytes, end_bytes)
            except (
                ConnectionError,
                ConnectionResetError
            ):
                ...
            except:
                logger.traceback()
                raise
        else:
            logger.debug(content)
        request.client.feed_eof()
        return self

    async def _send_file(self, request: Request, content: Path, start_bytes: int, end_bytes: Optional[int] = None):
        # check support
        with content.open("rb") as f:
            try:
                return await asyncio.get_event_loop().sendfile(
                        request.client.transport,
                        f,
                        start_bytes,
                        end_bytes
                    )
            except AssertionError:
                while (data := f.read(1024 * 1024)):
                    if not data:
                        break
                    request.client.write(data)
                    await request.client.drain()


    def add_content_type_encoding(self, headers: Header):
        if 'Content-Type' not in headers:
            return 
        content_type = headers.get_one('Content-Type') or ""
        if 'charset=' in content_type:
            return
        if 'text/' in content_type or 'application/json' in content_type:
            headers['Content-Type'] = f'{content_type}; charset=utf-8'


class LocationResponse(Response):
    def __init__(self, location: str, status: int = 302, headers: Optional['Header'] = None, cookies: list['Cookie'] = []):
        super().__init__(status=status, headers=headers, cookies=cookies)
        self.headers['Location'] = location


class HTTPResponseJSONEncoder(json.JSONEncoder):
    def default(self, o):  
        if isinstance(o, datetime.datetime):  
            return o.isoformat()  
        if isinstance(o, uuid.UUID):
            return str(o)
        if is_dataclass(o):
            return asdict(o) # type: ignore
        if isinstance(o, (tuple, set, Generator)):
            return list(o)
        if isinstance(o, Callable):
            return o()
        if asyncio.iscoroutinefunction(o) or asyncio.iscoroutine(o):
            return asyncio.run_coroutine_threadsafe(o, asyncio.get_event_loop())
        if isinstance(o, ObjectId):
            return str(o)
        try:
            return json.JSONEncoder.default(self, o)
        except:
            logger.traceback(f"json encode error: {o}", type(o))
            return str(o)
        
json_encoder = HTTPResponseJSONEncoder(separators=(",", ":"))

def json_dumps(obj: Any):
    return json_encoder.encode(obj)

def send_chunk(data: bytes | str):
    if isinstance(data, str):
        data = data.encode("utf-8")
    # length (16) + data
    return b'\r\n'.join((f"{len(data):x}".encode("utf-8"), data, b""))

def fix_value(value: Any, type: list[type]):
    if bool in type:
        if value == "true":
            return True
        elif value == "false":
            return False
    if int in type:
        return int(value)
    if float in type:
        return float(value)
    if str in type:
        return value
    return value

async def async_generator(sync_generator: Generator):
    for item in sync_generator:
        await asyncio.sleep(0)
        yield item

def get_etag(path: Path):
    stat = path.stat()
    return f'"{hashlib.md5(f"{path.name};{stat.st_mtime_ns};{stat.st_ctime_ns};{stat.st_size}".encode()).hexdigest()}"'



async def process_application(
    client: Client,
    protocol: Protocol,
    hostname: str,
    app: Application
):
    if protocol == Protocol.HTTP1:
        stream = ClientStream()
        stream.set_client(client)
        try:
            while not client.is_closing and (buffer := await client.readuntil(b"\r\n\r\n")):
                buffer = buffer[:-4]
                pre_byte_header, byte_header = buffer.split(b"\r\n", 1)
                byte_method, byte_path, byte_version = pre_byte_header.split(b" ")
                method, path, http_version = (
                    byte_method.decode("utf-8"),
                    byte_path.decode("utf-8"),
                    byte_version.decode("utf-8"),
                )
                headers = Header({
                    k: v for k, v in (
                        line.decode("utf-8").split(": ", 1) for line in byte_header.split(b"\r\n")
                    )
                })
                req = Request(stream, method, path, http_version, headers, client.peername)
                await app.handle(req)
        except:
            await client.close(2)
    elif protocol == Protocol.HTTP2:
        await client.read(24)
        connection = HTTP2WrapperConnection(
            client=client,
            app=app
        )
        await asyncio.gather(*(
            connection.recv(),
            connection.send()
        ))

class HTTP1Stream:
    def __init__(
        self,
        stream_id: int,
        connection: 'HTTP2WrapperConnection'
    ):
        self.stream_id = stream_id
        self.connection = connection
        self.conn = ClientStream(tls=connection.client.is_tls)
        self.headers: asyncio.Future[Header] = asyncio.Future()
        self.req_data: asyncio.StreamReader = asyncio.StreamReader()
        self.task = asyncio.create_task(self._loop())

        self.method = ""
        self.path = ""
        self.user_agent = ""
        self.host = ""


    async def _loop(self):
        await asyncio.gather(
            self._recv(),
            self._send()
        )

    async def close(self):
        try:
            await asyncio.wait_for(self.conn.close(), 5)
        except:
            ...
        self.task.cancel()

    async def _recv(self):
        while not self.conn.is_closing and (buffer := await self.conn.readuntil_write(b"\r\n\r\n")):
            pre_byte_header, byte_header = buffer[:-4].split(b"\r\n", 1)
            status_code = pre_byte_header.split(b" ", 2)[1].decode()
            headers = Header()
            for line in byte_header.split(b"\r\n"):
                k, v = line.split(b": ", 1)
                headers.add(k.decode().lower(), v.decode())

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
                while not self.conn.is_closing and (data := await self.conn.read_write(MAX_BUFFER)):
                    if not data:
                        break
                    self.connection.send_data(data, self.stream_id)
            elif transfer:
                while not self.conn.is_closing and (data := await self.conn.readuntil_write(b"\r\n")):
                    data_size = int(data[:-2], 16)
                    size = 0
                    while size < data_size and not self.conn.is_closing and (data := await self.conn.read_write(min(data_size - size, MAX_BUFFER))):
                        size += len(data)
                        self.connection.send_data(data, self.stream_id)
                    await self.conn.read_write(2)
                    if data_size == 0:
                        break

            elif content_length > 0:
                while not self.conn.is_closing and content_length > 0 and (data := await self.conn.read_write(min(content_length, MAX_BUFFER))):
                    self.connection.send_data(data, self.stream_id)
                    content_length -= len(data)
                    if not data:
                        break
            self.connection.send_data(b"", self.stream_id)


    async def _send(self):
        req = Request(
            self.conn,
            self.method,
            self.path,
            "HTTP/2",
            await self.headers,
            self.connection.client.peername
        )
        await asyncio.gather(
            self._req_body(),
            self.connection.app.handle(req)
        )

    async def _req_body(self):
        while not self.req_data.at_eof() and (buffer := await self.req_data.read(65535)):
            self.conn.feed_read_data(buffer)

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
        self.user_agent = headers.get_one("user-agent", "")
        self.method = method
        self.path = path
        self.host = host

        headers["Host"] = host

        self.headers.set_result(headers)


class HTTP2WrapperConnection(HTTP2Connection):
    def __init__(
        self,
        client: Client,
        app: Application
    ):
        super().__init__(
            client
        )
        self.http1_streams: dict[int, HTTP1Stream] = {}
        self.connection = None
        self.app = app


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

            await self.send_window_update(frame.stream_id, inc)
            self.server_flow.update_connection_window(inc)
        else:
            self.client_flow.update_stream_window(frame.stream_id, inc)


    async def _recv_rst_stream(self, frame: HTTP2Frame):
        stream_id = frame.stream_id
        if stream_id in self.http1_streams:
            asyncio.ensure_future(self.http1_streams[stream_id].close())
            del self.http1_streams[stream_id]

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
        if grpc and self.connection is None:
            logger.warning("grpc connection not supported")
            return

        if frame.stream_id not in self.http1_streams:
            stream = HTTP1Stream(
                frame.stream_id,
                self,
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

    __recv_mappings = {
        HTTP2FrameType.SETTINGS: _recv_settings_frame,
        HTTP2FrameType.WINDOW_UPDATE: _recv_window_update,
        HTTP2FrameType.RST_STREAM: _recv_rst_stream,
        HTTP2FrameType.HEADERS: _recv_headers,
        HTTP2FrameType.DATA: _recv_data,
        HTTP2FrameType.CONTINUATION: _recv_headers,
        HTTP2FrameType.PING: _recv_ping
    }
  
        
"""

async def _handle_http2(
    stream: HTTP2FrameStream,
    app: Application
):
    client = ClientStream(tls=stream.stream.stream.is_tls)
    try:
        await asyncio.gather(
            _handle_http2_req(
                stream,
                client,
                app
            ),
            _handle_http2_resp(
                stream,
                client,
                app
            )
        )
    except asyncio.CancelledError:
        ...
    except:
        logger.traceback()
    
async def _handle_http2_resp(
    stream: HTTP2FrameStream,
    client: ClientStream,
    app: Application
):
    while (buffer := await client.readuntil_write(b"\r\n\r\n")):
        buffer = buffer[:-4]
        pre_byte_header, byte_header = buffer.split(b"\r\n", 1)
        http_version, status_code, reason = pre_byte_header.decode("utf-8").split(" ", 2)
        headers = Header({
            k: v for k, v in (
                line.decode("utf-8").split(": ", 1) for line in byte_header.split(b"\r\n")
            )
        })
        await stream.send_response_header(
            int(status_code),
            headers,
        )
        while (buffer := await client.read_write(16384)):
            if not buffer:
                break
            await stream.send_data(buffer)
        await stream.send_data(b'')

async def _handle_http2_req(
    stream: HTTP2FrameStream,
    client: ClientStream,
    app: Application
):
    req = Request(client, stream.method, stream.path, "HTTP/2", stream.headers, stream.stream.stream.peername)
    try:
        await asyncio.gather(
            app.handle(req),
            _handle_http2_req_content(stream, client)
        )
    except asyncio.CancelledError:
        ...
    except:
        logger.traceback()

async def _handle_http2_req_content(
    stream: HTTP2FrameStream,
    client: ClientStream,
):
    while (buffer := await stream.reader.read(16384)):
        if not buffer:
            break
        client.feed_read_data(buffer)
        if stream.reader.at_eof():
            break
"""