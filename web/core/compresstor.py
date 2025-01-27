from dataclasses import dataclass
from typing import Optional
import pyzstd
import zlib
import gzip
import brotli
import lzma
import bz2

COMPRESSION_THRESHOLD = 4096
COMPRESSION_PERCENT = 0.8

COMPRESS_TARGET = {
    "zstd": pyzstd.compress,
    "gzip": gzip.compress,
    "deflate": zlib.compress,
    "brotli": brotli.compress,
    "lzma": lzma.compress,
    "bz2": bz2.compress,
    "none": lambda x: x
}

@dataclass
class Compressor:
    length: int
    compressed: bool = False
    data: bytes = b''
    compression: Optional[str] = None


    
def compress(data: bytes, compressions: str):
    origin_length = len(data)
    if origin_length < COMPRESSION_THRESHOLD:
        return Compressor(
            length=origin_length,
            compressed=False,
            data=data
        )
    for compression, function in COMPRESS_TARGET.items():
        if compression in compressions:
            compressed_data = function(data)
            compressed_length = len(compressed_data)
            if compressed_length >= origin_length or origin_length / compressed_length <= COMPRESSION_PERCENT:
                continue
            return Compressor(
                length=compressed_length,
                compressed=True,
                data=compressed_data,
                compression=compression
            )
    return Compressor(
        length=origin_length,
        compressed=False,
        data=data
    )

            
__all__ = ["compress", "Compressor"]