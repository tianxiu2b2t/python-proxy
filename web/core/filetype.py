import os
from typing import Any
import filetype as _filetype

types: dict[str, str] = {
    "js": "text/javascript",
    "css": "text/css",
    "html": "text/html",
    "htm": "text/html",
    "msi": "application/x-msdownload",
    "iso": "application/octet-stream",
}


def guess_mime(obj: Any):
    type = None
    try:
        type = _filetype.guess_mime(obj)
    except:
        ...
    try:
        if type is None and os.path.exists(obj):
            ext = str(obj).rsplit(".", 1)[1].lower()
            type = types.get(ext)
    except:
        ...
    return type
        