import asyncio
from collections import defaultdict, deque
import enum

import hpack

import utils
from ..utils import Client

class HTTP2FrameType(enum.IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

class HTTP2FrameFlags(enum.IntEnum):
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

class HTTP2Error(enum.IntEnum):
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xa
    ENHANCE_YOUR_CALM = 0xb
    INADEQUATE_SECURITY = 0xc
    HTTP_1_1_REQUIRED = 0xd

class HTTP2Frame:
    def __init__(
        self,
        type: HTTP2FrameType,
        flags: int,
        stream_id: int,
        payload: bytes
    ) -> None:
        self.type = type
        self.flags = flags
        self.stream_id = stream_id
        self.length = len(payload)
        self.payload = payload

    def to_bytes(self):
        return self.length.to_bytes(3, 'big') + self.type.to_bytes(1, 'big') + self.flags.to_bytes(1, 'big') + self.stream_id.to_bytes(4, 'big') + self.payload
    
    @property
    def end_stream(self):
        return self.flags & HTTP2FrameFlags.END_STREAM == HTTP2FrameFlags.END_STREAM

    @property
    def end_headers(self):
        return self.flags & HTTP2FrameFlags.END_HEADERS == HTTP2FrameFlags.END_HEADERS

    @property
    def padded(self):
        return self.flags & HTTP2FrameFlags.PADDED == HTTP2FrameFlags.PADDED

    @property
    def priority(self):
        return self.flags & HTTP2FrameFlags.PRIORITY == HTTP2FrameFlags.PRIORITY
    
    @property
    def ack(self):
        return self.flags & HTTP2FrameFlags.ACK == HTTP2FrameFlags.ACK
    
    def __repr__(self):
        return f'<HTTP2Frame type={self.type.name} flags={self.flags} stream_id={self.stream_id} length={self.length} payload={self.payload}>'

MAYBE_UPDATE_SIZE = 65535
UPDATE_MAX_SIZE = 16777216
MAX_BUFFER = 1024 * 1024 * 4

class HTTP2FlowControl:
    def __init__(
        self,
    ):
        self.initial_window_size = 65535
        self.streams: defaultdict[int, int] = defaultdict(lambda: self.initial_window_size)
        self.window_size = self.initial_window_size
        self._waiters: defaultdict[int, deque[asyncio.Future]] = defaultdict(deque)

    def update_connection_window(self, delta: int):
        self.window_size += delta
        
    def update_stream_window(self, stream_id: int, delta: int):
        self.streams[stream_id] += delta
        while self._waiters[stream_id] and self.get_can_send(stream_id) != 0:
            fut = self._waiters[stream_id].popleft()
            fut.set_result(True)

    def get_can_send(self, stream_id: int):
        return min(self.window_size, self.streams[stream_id])
    
    def send(self, stream_id: int, size: int):
        self.window_size -= size
        self.streams[stream_id] -= size

    def maybe_update_window_size(self):
        return self.window_size < MAYBE_UPDATE_SIZE
        
    
    def maybe_update_stream_window_size(self, stream_id: int):
        return self.streams[stream_id] < MAYBE_UPDATE_SIZE
    

    async def wait(self, stream_id: int):
        if self.get_can_send(stream_id) != 0:
            return
        fut = asyncio.Future()
        self._waiters[stream_id].append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            raise
        finally:
            if fut in self._waiters[stream_id]:
                self._waiters[stream_id].remove(fut)

class HTTP2Settings:
    header_table_size = 4096
    enable_push = False
    max_concurrent_streams = 100000
    initial_window_size = 65535
    max_frame_size = 16384
    max_header_list_size = 262144

    _idx = {
        1: "header_table_size",
        2: "enable_push",
        3: "max_concurrent_streams",
        4: "initial_window_size",
        5: "max_frame_size",
        6: "max_header_list_size"
    }

class HTTP2Connection:
    def __init__(
        self,
        client: Client
    ):
        self.client = client
        self.settings = HTTP2Settings()
        self.client_flow = HTTP2FlowControl()
        self.server_flow = HTTP2FlowControl()
        self.decoder = hpack.Decoder()
        self.encoder = hpack.Encoder()

        self.data_streams: defaultdict[int, HTTP2DataStream] = defaultdict(HTTP2DataStream)
        self.data_lock = utils.Lock()
        self.header_payloads: defaultdict[int, bytes] = defaultdict(bytes)

        self.data_lock.acquire()

    async def send(self):
        while not self.client.is_closing:
            await self.data_lock.wait()
            self.data_lock.acquire()
            clear = []
            for stream_id, reader in self.data_streams.items():
                while reader.can_read:
                    await self.client_flow.wait(stream_id)
                    flow_size = self.client_flow.get_can_send(stream_id)
                    data = reader.read(min(self.settings.max_frame_size, flow_size))
                    self.client_flow.window_size -= len(data)
                    self.client_flow.streams[stream_id] -= len(data)
                    flags = 0
                    if reader.at_eof:
                        flags |= HTTP2FrameFlags.END_STREAM
                        clear.append(stream_id)
                    await self.send_frame(
                        HTTP2Frame(
                            HTTP2FrameType.DATA,
                            flags,
                            stream_id,
                            data
                        )
                    )
            for stream_id in clear:
                del self.data_streams[stream_id]

    async def send_frame(self, *frames: HTTP2Frame):
        buffer = b''
        for frame in frames:
            buffer += frame.to_bytes()
        self.client.write(
            buffer
        )
        await self.client.drain()

    async def update_flow_window(self, flow: HTTP2FlowControl, stream_id: int, inc: int):
        frames = []
        payload = inc.to_bytes(4, "big")
        if flow.maybe_update_window_size():
            frames.append(
                HTTP2Frame(
                    HTTP2FrameType.WINDOW_UPDATE,
                    0,
                    0,
                    payload
                )
            )
            flow.update_connection_window(inc)

        if flow.maybe_update_stream_window_size(stream_id):
            frames.append(
                HTTP2Frame(
                    HTTP2FrameType.WINDOW_UPDATE,
                    0,
                    stream_id,
                    payload
                )
            )
            flow.update_stream_window(stream_id, inc)

        await self.send_frame(*frames)

    async def update_client_flow(self, stream_id: int, inc: int):
        await self.update_flow_window(self.client_flow, stream_id, inc)

    async def update_server_flow(self, stream_id: int, inc: int):
        await self.update_flow_window(self.server_flow, stream_id, inc)

    async def send_settings(self, cfg: dict[int, int] = {}):
        payload = b''
        for key, value in cfg.items():
            payload += key.to_bytes(2, "big")
            payload += value.to_bytes(4, "big")
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.SETTINGS,
                0,
                0,
                payload
            )
        )

    async def send_ack_settings(self):
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.SETTINGS,
                HTTP2FrameFlags.ACK,
                0,
                b""
            )
        )

    async def send_headers(self, header_list: list[tuple[str, str]], stream_id: int, end_stream: bool = False):
        payload = self.encoder.encode(header_list)
        flags = HTTP2FrameFlags.END_HEADERS
        if end_stream:
            flags |= HTTP2FrameFlags.END_STREAM
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.HEADERS,
                flags,
                stream_id,
                payload
            )
        )

    def send_data(self, data: bytes, stream_id: int):
        self.data_streams[stream_id].feed_data(data)

        for stream in self.data_streams.values():
            if stream.can_read:
                self.data_lock.release()
                break

    async def send_window_update(self, stream_id: int, inc: int):
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.WINDOW_UPDATE,
                0,
                stream_id,
                inc.to_bytes(4, "big")
            )
        )

    async def read_frame(self):
        header = await self.client.readexactly(9)
        length = int.from_bytes(header[:3], 'big')
        type = header[3]
        flags = header[4]
        stream_id = int.from_bytes(header[5:], 'big')
        payload = await self.client.readexactly(length)
        return HTTP2Frame(HTTP2FrameType(type), flags, stream_id, payload)

    async def send_rst_stream(self, stream_id: int, error_code: HTTP2Error):
        await self.send_frame(
            HTTP2Frame(
                HTTP2FrameType.RST_STREAM,
                0,
                stream_id,
                error_code.to_bytes(4, "big")
            )
        )

class HTTP2DataStream:
    def __init__(
        self
    ):
        self.buffer = b''
        self.end_stream = False
    
    def feed_data(self, data: bytes):
        self.buffer += data
        if not data:
            self.end_stream = True

    @property
    def can_read(self):
        return len(self.buffer) > 16384 or (self.end_stream and len(self.buffer) > 0)
    
    def read(self, size: int = MAX_BUFFER):
        buf, data = self.buffer[:size], self.buffer[size:]
        self.buffer = data
        return buf
    
    @property
    def at_eof(self):
        return not self.buffer and self.end_stream