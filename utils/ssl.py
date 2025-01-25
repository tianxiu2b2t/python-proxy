

import io
from typing import Optional


def is_ssl_or_tls_data(data: bytes):
    if len(data) < 5:
        return None
    content_type = data[0]
    protocol_version = int.from_bytes(data[1:3], byteorder='big')
    length = int.from_bytes(data[3:5], byteorder='big')
    return content_type == 0x16 and protocol_version in (0x0301, 0x0302, 0x0303, 0x0304, 0x0305) and length != 0 and length < 16384 + 2048


SSL_PROTOCOLS = {
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
} # SSL ?

class ClientHandshakeInfo:
    def __init__(self, version: int, sni: Optional[str]):
        self.version = version
        self.sni = sni

    @property
    def version_name(self):
        return SSL_PROTOCOLS.get(self.version, "Unknown")
    
    def __str__(self):
        return f"ClientHandshakeInfo(version={self.version_name}, sni={self.sni})"
    def __repr__(self):
        return str(self)

def get_client_handshake_info(data: bytes):
    info = ClientHandshakeInfo(-1, None)
    try:
        buffer = io.BytesIO(data)
        if not buffer.read(1):
            raise
        info.version = int.from_bytes(buffer.read(2), 'big')
        if not buffer.read(40):
            raise
        buffer.read(buffer.read(1)[0])
        buffer.read(int.from_bytes(buffer.read(2), 'big'))
        buffer.read(buffer.read(1)[0])
        extensions_length = int.from_bytes(buffer.read(2), 'big')
        current_extension_cur = 0
        extensions = []
        while current_extension_cur < extensions_length:
            extension_type = int.from_bytes(buffer.read(2), 'big')
            extension_length = int.from_bytes(buffer.read(2), 'big')
            extension_data = buffer.read(extension_length)
            if extension_type == 0x00: # SNI
                info.sni = extension_data[5:].decode("utf-8")
            extensions.append((extension_type, extension_data))
            current_extension_cur += extension_length + 4
    except:
        ...
    return info
