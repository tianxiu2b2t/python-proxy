import asyncio
import base64
from collections import deque
import hashlib
import hmac
import json
from typing import Optional


class Queue[T]:
    def __init__(
        self
    ):
        self._objs: deque[T] = deque()
        self._waiters: deque[asyncio.Future] = deque()

    def offer(
        self,
        obj: T
    ):
        self._objs.append(obj)
        self._wake_up()


    def offer_before(
        self,
        obj: T
    ):
        self._objs.appendleft(obj)
        self._wake_up()


    @property
    def size(self):
        return len(self._objs)
    
    @property
    def empty(
        self,
    ):
        return not self._objs

    
    async def poll(
        self,
    ):
        if not self._objs:
            fut = asyncio.get_running_loop().create_future()
            self._waiters.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self._waiters:
                    self._waiters.remove(fut)
        return self._objs.popleft()

    async def peek(
        self,
    ):
        if not self._objs:
            fut = asyncio.Future()
            self._waiters.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                raise
            finally:
                if fut in self._waiters:
                    self._waiters.remove(fut)
        return self._objs[0]

    def _wake_up(
        self,
    ):
        while self._waiters and self._objs:
            fut = self._waiters.popleft()
            fut.set_result(True)

class Lock:
    def __init__(
        self
    ):
        self._locked = False
        self._waiters: deque[asyncio.Future] = deque()

    async def wait(self):
        if not self._locked:
            return
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            raise
        finally:
            if fut in self._waiters:
                self._waiters.remove(fut)

    def acquire(self):
        self._locked = True

    def release(self):
        self._locked = False
        while self._waiters:
            fut = self._waiters.popleft()
            fut.set_result(True)
                

class JWT:
    defaultHeaders = {
        "alg": "HS256",
        "typ": "JWT"
    }
    def __init__(
        self,
        payload: str = "",
        secret: Optional[bytes] = None,
        exp: Optional[int] = None,
        iat: Optional[int] = None,
    ):
        self._payload = payload
        self._secret = secret
        self._exp = exp
        self._iat = iat

    @property
    def exp(
        self,
    ):
        return self._exp
    
    @property
    def iat(
        self,
    ):
        return self._iat

    @property
    def payload(
        self,
    ):
        return self._payload

    @property
    def secret(
        self,
    ):
        return self._secret
    
    @secret.setter
    def secret(
        self,
        secret: bytes,
    ):
        self._secret = secret

    @property
    def is_valid(
        self,
    ):
        if self._secret is None:
            return False
        try:
            byte_header, byte_payload, byte_sign = self._payload.encode().split(b".")
        except ValueError:
            return False
        return hmac.compare_digest(
            hmac.new(
                self._secret,
                b".".join([byte_header, byte_payload]),
                hashlib.sha256
            ).digest(),
            base64.b64decode(byte_sign)
        )
    
    def encode(
        self,
    ):
        assert self._secret is not None
        data = {}
        if self._exp is not None:
            data["exp"] = self._exp
        if self._iat is not None:
            data["iat"] = self._iat
        data["payload"] = self._payload
        payload = b".".join([base64.b64encode(
            json.dumps(self.defaultHeaders).encode("utf-8")
        ),
        base64.b64encode(
            json.dumps(data).encode("utf-8")
        )])
        sign = base64.b64encode(
            hmac.new(
                self._secret,
                payload,
                hashlib.sha256
            ).digest()
        )
        return (payload + b"." + sign).decode("utf-8")

    def decode(
        self
    ):
        assert self._secret is not None
        assert self.is_valid
        try:
            byte_header, byte_payload, byte_sign = self._payload.encode().split(b".")
            data = json.loads(base64.b64decode(byte_payload).decode("utf-8"))
            self._payload = data["payload"]
            self._exp = data.get("exp")
            self._iat = data.get("iat")
        except ValueError:
            raise ValueError("Invalid JWT")
        
        return self._payload