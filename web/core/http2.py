import asyncio
from collections import defaultdict
import enum
import hpack

from logger import logger
from ..utils import Client, Header

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

    @staticmethod
    def from_int(value: int):
        return HTTP2FrameType(value)

class HTTP2HeaderFrame:
    def __init__(
        self,
        type: int = 0,
        flags: int = 0,
        length: int = 0,
        stream_id: int = 0,
    ):
        self.type = HTTP2FrameType.from_int(type)
        self.flags = flags
        self.length = length
        self.stream_id = stream_id


    # flags bit
    # 0x1 END_STREAM
    # 0x2 ACK
    # 0x4 END_HEADERS
    # 0x8 PADDED
    # 0x20 PRIORITY

    @property
    def end_stream(self) -> bool:
        return self.flags & 0x1 == 0x1
    
    @property
    def ack(self) -> bool:
        return self.flags & 0x1 == 0x1
    
    @property
    def end_headers(self) -> bool:
        return self.flags & 0x4 == 0x4
    
    @property
    def padded(self) -> bool:
        return self.flags & 0x8 == 0x8
    
    @property
    def priority(self) -> bool:
        return self.flags & 0x20 == 0x20
    
    @end_stream.setter
    def end_stream(self, value: bool):
        if self.type not in (
            HTTP2FrameType.DATA,
            HTTP2FrameType.HEADERS,
            HTTP2FrameType.PUSH_PROMISE,
        ):
            raise ValueError('END_STREAM flag can only be set for DATA, HEADERS, PUSH_PROMISE frames')
        if value:
            self.flags |= 0x1
        else:
            self.flags &= ~0x1


    @ack.setter
    def ack(self, value: bool):
        if self.type != HTTP2FrameType.PING:
            raise ValueError('ACK flag can only be set for PING frames')
        if value:
            self.flags |= 0x1
        else:
            self.flags &= ~0x1

    @end_headers.setter
    def end_headers(self, value: bool):
        if self.type != HTTP2FrameType.HEADERS:
            raise ValueError('END_HEADERS flag can only be set for HEADERS frames')
        if value:
            self.flags |= 0x4
        else:
            self.flags &= ~0x4

    @padded.setter
    def padded(self, value: bool):
        if self.type not in (
            HTTP2FrameType.DATA,
            HTTP2FrameType.HEADERS,
            HTTP2FrameType.PUSH_PROMISE,
        ):
            raise ValueError('PADDED flag can only be set for DATA, HEADERS, PUSH_PROMISE frames')
        if value:
            self.flags |= 0x8
        else:
            self.flags &= ~0x8

    @priority.setter
    def priority(self, value: bool):
        if self.type != HTTP2FrameType.HEADERS:
            raise ValueError('PRIORITY flag can only be set for HEADERS frames')
        if value:
            self.flags |= 0x20
        else:
            self.flags &= ~0x20
    
    def __repr__(self):
        return f'HTTP2HeaderFrame(type={self.type}, flags={self.flags}, length={self.length}, stream_id={self.stream_id})'
    
    def to_bytes(self):
        return self.length.to_bytes(3, 'big') + self.type.value.to_bytes(1, 'big') + self.flags.to_bytes(1, 'big') + self.stream_id.to_bytes(4, 'big')

class HTTP2Frame:
    def __init__(
        self,
        header_frame: HTTP2HeaderFrame,
        stream_id: int,
        payload: bytes
    ):
        self.header_frame = header_frame
        self.stream_id = stream_id
        padding = 0
        if header_frame.padded:
            padding = payload[0]
            payload = payload[1:]
        
        if header_frame.type == HTTP2FrameType.HEADERS and header_frame.priority:
            payload = payload[5:]

        self.payload = payload[:len(payload) - padding]


    def __repr__(self):
        return f'HTTP2Frame(type={self.header_frame.type}, stream_id={self.stream_id}, payload={self.payload})'

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

RESP_HEADER_BLOCK_LENGTH = 512

class HTTP2FlagsType(enum.IntEnum):
    END_STREAM = 0x1
    ACK = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20

class HTTP2FrameStream:
    def __init__(
        self,
        stream: 'HTTP2Stream',
        stream_id: int,
    ):
        self.stream = stream
        self.stream_id = stream_id
        self.hpack_decoder = stream.hpack_decoder
        self.hpack_encoder = stream.hpack_encoder
        self.headers: Header = Header()
        self.method: str = ""
        self.path: str = ""
        self.host: str = ""
        self.reader: asyncio.StreamReader = asyncio.StreamReader()
        self.buffer: bytes = b''
        self.end_data_stream = False
        self.req_header = False

    def feed_frame(self, frame: HTTP2Frame):
        if frame.header_frame.type == HTTP2FrameType.HEADERS:
            headers: list[tuple[str, str]] = self.hpack_decoder.decode(frame.payload)
            for k, v in headers:
                if k.startswith(':'):
                    k = k[1:]
                    if k == 'method':
                        self.method = v
                    elif k == 'path':
                        self.path = v
                    elif k == 'authority':
                        self.host = v
                    continue
                self.headers.add(k, v)
            self._feed_header_request()
        if not self.req_header:
            logger.warning('Request header not received')
            return
        if frame.header_frame.type == HTTP2FrameType.DATA:
            self.reader.feed_data(frame.payload)

    def _feed_header_request(self):
        if not self.method or not self.path or not self.host:
            raise ValueError('Missing required header fields')
        buf = f'{self.method} {self.path} HTTP/1.1\r\nHost: {self.host}\r\n'.encode()
        for k, v in self.headers.items():
            if k.startswith(':'):
                continue
            for val in v:
                buf += f'{k}: {val}\r\n'.encode()
        buf += b'\r\n'
        self.reader.feed_data(buf)
        self.req_header = True

    async def send_response_header(self, status_code: int, headers: Header, end_stream: bool = False):
        header_list = [
            (':status', str(status_code))
        ]
        for k, v in headers.items():
            # ignore content-length
            if k.lower() in ('content-length', 'transfer-encoding'):
                continue
            for val in v:
                header_list.append((k.lower(), val))
            

        await self.stream._send_settings_ack(0)
        # to lower
        header_block = self.hpack_encoder.encode(header_list)
        flags = HTTP2FlagsType.END_HEADERS.value
        if end_stream:
            flags |= HTTP2FlagsType.END_STREAM.value
        header_frame = HTTP2HeaderFrame(
            type=HTTP2FrameType.HEADERS.value,
            flags=flags,
            stream_id=self.stream_id,
            length=len(header_block),
        )
        await self._send_frame(HTTP2Frame(
            header_frame,
            self.stream_id,
            header_block
        ))

    async def _send_frame(self, frame: HTTP2Frame):
        self.stream.stream.write(frame.header_frame.to_bytes() + frame.payload)


    async def send_data(self, data: bytes):
        self.buffer += data
        if len(data) == 0:
            self.end_data_stream = True
        if len(self.buffer) > 16384:
            await self._drain_data()
        while self.end_data_stream and len(self.buffer) > 0:
            await self._drain_data()

    async def drain(self):
        await self._drain_data()

    async def _drain_data(self):
        data = self.buffer[:16384]
        self.buffer = self.buffer[16384:]
        flags = HTTP2FlagsType.END_STREAM.value if len(self.buffer) == 0 else 0
        data_frame = HTTP2HeaderFrame(
            type=HTTP2FrameType.DATA.value,
            flags=flags,
            stream_id=self.stream_id,
            length=len(data),
        )
        await self._send_frame(HTTP2Frame(
            data_frame,
            self.stream_id,
            data
        ))
    

class HTTP2RstStream:
    def __init__(self, stream_id: int, error_code: int):
        self.stream_id = stream_id
        self.error_code = error_code

    def __repr__(self) -> str:
        return f'HTTP2RstStream(stream_id={self.stream_id}, error_code={self.error_code})'

class HTTP2GoAwayStream:
    def __init__(self, last_stream_id: int, error_code: int, debug_data: bytes):
        self.last_stream_id = last_stream_id
        self.error_code = error_code
        self.debug_data = debug_data

    def __repr__(self) -> str:
        return f'HTTP2GoAwayStream(last_stream_id={self.last_stream_id}, error_code={self.error_code}, debug_data={self.debug_data})'

class HTTP2Stream:
    def __init__(
        self,
        stream: Client
    ):
        self.stream = stream
        self.hpack_decoder = hpack.Decoder()
        self.hpack_encoder = hpack.Encoder()
        self.headers = []
        self.body = b''
        self.settings = HTTP2Settings()
        self.connection_window_size = self.settings.settings_initial_window_size

    async def __aiter__(self):
        frame_payloads: defaultdict[int, bytes] = defaultdict(bytes)
        streams: dict[int, HTTP2FrameStream] = {}
        while not self.stream.is_closing:
            try:
                frame_header = await self.read_header_frame()
            except:
                break 
            payload = await self.stream.read(frame_header.length)
            if frame_header.type == HTTP2FrameType.GOAWAY:
                logger.debug('goaway', payload)
                yield HTTP2GoAwayStream(
                    int.from_bytes(payload[:4], 'big'),
                    int.from_bytes(payload[4:8], 'big'),
                    payload[8:]
                )
                break
            if frame_header.type == HTTP2FrameType.PING:
                await self._send_pong(frame_header.stream_id, payload)
                continue
            if frame_header.type == HTTP2FrameType.SETTINGS:
                frame = HTTP2Frame(frame_header, frame_header.stream_id, payload)
                self._process_settings_frame(frame)
                # ack settings
                await self._send_settings_ack(frame_header.stream_id)
                continue
            if frame_header.type == HTTP2FrameType.WINDOW_UPDATE:
                self.connection_window_size += int.from_bytes(payload, 'big')
                continue
            if frame_header.type == HTTP2FrameType.RST_STREAM:
                yield HTTP2RstStream(frame_header.stream_id, int.from_bytes(payload, 'big'))
                continue
            if frame_header.type == HTTP2FrameType.HEADERS:
                stream = HTTP2FrameStream(
                    self,
                    frame_header.stream_id
                )
                streams[frame_header.stream_id] = stream
                stream.feed_frame(HTTP2Frame(
                    frame_header,
                    frame_header.stream_id,
                    payload
                ))
                yield stream
            if frame_header.type == HTTP2FrameType.DATA and frame_header.stream_id in streams:
                streams[frame_header.stream_id].feed_frame(HTTP2Frame(
                    frame_header,
                    frame_header.stream_id,
                    payload
                ))

    async def _send_pong(self, stream_id: int, payload: bytes):
        header_frame = HTTP2HeaderFrame(
            type=HTTP2FrameType.PING.value,
            flags=0,
            length=8,
            stream_id=stream_id,
        )
        header_frame.ack = True
        pong_frame = HTTP2Frame(
            header_frame=header_frame,
            stream_id=stream_id,
            payload=payload,
        )
        self.stream.write(header_frame.to_bytes() + pong_frame.payload)
        await self.stream.drain()

    async def read_header_frame(self):
        frame_header = await self.stream.read(9)
        length = int.from_bytes(frame_header[:3], 'big')
        type = frame_header[3]
        flags = frame_header[4]
        stream_id = int.from_bytes(frame_header[5:], 'big')
        return HTTP2HeaderFrame(
            type=type,
            flags=flags,
            length=length,
            stream_id=stream_id,
        )
    
    def _process_settings_frame(self, frame: HTTP2Frame):
        for i in range(0, len(frame.payload), 6):
            setting_id = int.from_bytes(frame.payload[i:i+2], 'big')
            setting_value = int.from_bytes(frame.payload[i+2:i+6], 'big')
            setattr(self.settings, HTTP2Settings._idx[setting_id], setting_value)
            

    async def _send_settings_ack(self, stream_id: int):
        header_frame = HTTP2HeaderFrame(
            type=HTTP2FrameType.SETTINGS.value,
            flags=HTTP2FlagsType.ACK.value,
            length=0,
            stream_id=stream_id,
        )
        self.stream.write(header_frame.to_bytes())