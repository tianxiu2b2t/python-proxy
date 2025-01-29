import asyncio
from collections import defaultdict
import enum
import io
from typing import Optional

from ..utils import Client


class HTTP2HeaderFrame:
    def __init__(
        self,
        type: int,
        flags: int,
        length: int,
        stream_id: int
    ):
        self._type = type
        self._flags = flags
        self._length = length
        self._stream_id = stream_id
    
    def to_bytes(self):
        return self._length.to_bytes(3, "big") + self._type.to_bytes(1, "big") + self._flags.to_bytes(1, "big") + self._stream_id.to_bytes(4, "big")

    @property
    def type(self) -> int:
        return self._type

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def length(self) -> int:
        return self._length

    @property
    def stream_id(self) -> int:
        return self._stream_id
    
    @property
    def priority(self) -> bool:
        return self.flags & 0x20 != 0

    @property
    def end_headers(self) -> bool:
        return self.flags & 0x4 != 0

    @property
    def end_stream(self) -> bool:
        return self.flags & 0x1 != 0
    
    @property
    def padded(self) -> bool:
        return self.flags & 0x8 != 0

    def __repr__(self) -> str:
        return f"<HTTP2HeaderFrame {self.type} 0b{bin(self.flags)[2:].zfill(8)} {self.length} {self.stream_id}>"

class HTTP2FrameType(enum.Enum):
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

class HTTP2Frame:
    def __init__(
        self,
        header_frame: HTTP2HeaderFrame,
        payload: bytes
    ):
        self._header_frame = header_frame
        self._payload = payload

    def to_bytes(self):
        return self._header_frame.to_bytes() + self._payload
    
    @property
    def header_frame(self) -> HTTP2HeaderFrame:
        return self._header_frame

    @property
    def payload(self) -> bytes:
        return self._payload

    def __repr__(self) -> str:
        return f"<HTTP2Frame {self.header_frame} {self.payload}>"

class HTTP2HeadersFrame(HTTP2Frame):
    def __init__(
        self,
        header_frame: HTTP2HeaderFrame,
        payload: bytes,
    ):
        super().__init__(header_frame, payload)

    def _parse_headers(self):
        buffer = io.BytesIO(self.payload)
        pad_length = 0
        if self.header_frame.padded:
            pad_length = buffer.read(1)[0]
        if self.header_frame.priority:
            buffer.read(5)
        header_block = buffer.read()
        if self.header_frame.padded:
            header_block = header_block[:-pad_length]

        print(header_block)
        return []

    @property
    def headers(self) -> list:
        return self._parse_headers()


    def __repr__(self) -> str:
        return f"<HTTP2HeadersFrame {self.header_frame} {self.payload}>"
    


class HTTP2Settings:
    settings_header_table_size = 4096
    settings_enable_push = False
    settings_max_concurrent_streams = 100000
    settings_initial_window_size = 65535
    settings_max_frame_size = 16384
    settings_max_header_list_size = 262144

    _idx = {
        1: "settings_header_table_size",
        2: "settings_enable_push",
        3: "settings_max_concurrent_streams",
        4: "settings_initial_window_size",
        5: "settings_max_frame_size",
        6: "settings_max_header_list_size"
    }

def simple_hpack_decode(hpack_data):
    headers = []
    index = 0
    while index < len(hpack_data):
        if hpack_data[index] & 0x80 == 0:  # 字面量头部字段
            name_length = 0
            name_start = index + 1
            while True:
                byte = hpack_data[name_start]
                name_length = (name_length << 7) | (byte & 0x7F)
                if byte & 0x80 == 0:
                    break
                name_start += 1
            name_start += 1
            name = hpack_data[name_start:name_start + name_length]
            index = name_start + name_length

            value_length = 0
            value_start = index
            while True:
                byte = hpack_data[value_start]
                value_length = (value_length << 7) | (byte & 0x7F)
                if byte & 0x80 == 0:
                    break
                value_start += 1
            value_start += 1
            value = hpack_data[value_start:value_start + value_length]
            index = value_start + value_length

            headers.append((name, value))
        else:
            # 这里简单忽略索引头部字段
            index += 1
    return headers

def get_frame_type(frame_type: int) -> Optional[HTTP2FrameType]:
    try:
        return HTTP2FrameType(frame_type)
    except ValueError:
        return None

class HTTP2Stream:
    def __init__(
        self,
        client: Client
    ):
        self._client = client
        self._settings: HTTP2Settings = HTTP2Settings()

    async def read_header_frame(self):
        data = await self._client.read(9)
        length = int.from_bytes(data[:3], "big")
        type = int.from_bytes(data[3:4], "big")
        flags = int.from_bytes(data[4:5], "big")
        stream_id = int.from_bytes(data[5:9], "big")
        return HTTP2HeaderFrame(type, flags, length, stream_id)
    
    async def __aiter__(self):
        conn = await asyncio.open_connection(
            "127.0.0.1",
            8888
        )
        conn[1].write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        await conn[1].drain()
        streams: defaultdict[int, list[HTTP2Frame]] = defaultdict(list)
        while not self._client.is_closing:
            header_frame = await self.read_header_frame()
            frame = HTTP2Frame(header_frame, await self._client.read(header_frame.length))
            conn[1].write(frame.to_bytes())
            await conn[1].drain()

            if not header_frame.end_stream:
                streams[header_frame.stream_id].append(frame)
                continue
            payload = b""
            if header_frame.stream_id in streams:
                for frame in streams[header_frame.stream_id]:
                    payload += frame.payload
                streams.pop(header_frame.stream_id)
            payload += frame.payload
            frame_type = get_frame_type(frame.header_frame.type)
            if frame_type is None:
                raise Exception(f"Unknown frame type {frame.header_frame.type}")
            if frame_type == HTTP2FrameType.SETTINGS:
                self._process_settings_frame(payload)
                continue
            if frame_type == HTTP2FrameType.WINDOW_UPDATE:
                n = int.from_bytes(payload, "big")
                self._settings.settings_initial_window_size += n
                continue
            if frame_type == HTTP2FrameType.HEADERS:
                headers_frame = HTTP2HeadersFrame(frame.header_frame, payload)
                print(headers_frame.headers)
            yield frame

    def _process_settings_frame(self, payload: bytes):
        for setting in range(0, len(payload), 6):
            setting_id = int.from_bytes(payload[setting:setting+2], "big")
            setting_value = int.from_bytes(payload[setting+2:setting+6], "big")
            if setting_id in HTTP2Settings._idx:
                setattr(self._settings, HTTP2Settings._idx[setting_id], setting_value)
            else:
                raise Exception(f"Unknown setting id {setting_id}")
            