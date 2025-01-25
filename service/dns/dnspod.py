from collections import defaultdict
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
from typing import Any, Optional

import aiohttp
from .base import BaseDNS

TENCENT_HEADERS = ("content-type", "host")
DATE = "2021-03-23"
USERAGENT = "TTB-Network"
URL = "dnspod.tencentcloudapi.com"

@dataclass
class HTTPResponse:
    Response: dict[str, Any]

    @property
    def RequestId(self) -> str:
        return self.Response["RequestId"]
    
    def raise_for_error(self):
        if "Error" in self.Response:
            code = self.Response["Error"]["Code"]
            message = self.Response["Error"]["Message"]
            raise RuntimeError(f"Error {code}: {message}")
  
@dataclass
class Record:
    RecordId: int
    Name: str
    Type: str
    Value: str

@dataclass
class CacheResponse:
    resp: HTTPResponse
    timestamp: float

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.timestamp > 60

class DNSPod(BaseDNS):
    def __init__(self, key_id: str, secret: str) -> None:
        super().__init__()
        self._key_id = key_id
        self._secret = secret
        self.cache: defaultdict[str, CacheResponse] = defaultdict(lambda: CacheResponse(HTTPResponse({"RequestId": "0"}), 0))
    async def add_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
        record_value: str,
    ) -> None:
        resp = await self._post_action(
            "CreateRecord",
            {
                "Domain": domain,
                "SubDomain": hostname,
                "RecordType": record_type,
                "RecordLine": "默认",
                "Value": record_value,
            }
        )
        resp.raise_for_error()
        return resp.Response["RecordId"]

    async def remove_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
    ) -> None:
        records: list[Record] = await self.list_records(domain)
        for record in records:
            if record.Name == hostname and record.Type == record_type:
                await self._post_action(
                    "DeleteRecord",
                    {
                        "Domain": domain,
                        "RecordId": record.RecordId
                    }
                )
        
    async def modify_record(self, hostname: str, domain: str, record_type: str, record_value: str) -> None:
        records: list[Record] = await self.list_records(domain)
        for record in records:
            if record.Name == hostname and record.Type == record_type:
                await self._post_action(
                    "ModifyRecord",
                    {
                        "Domain": domain,
                        "SubDomain": hostname,
                        "RecordId": record.RecordId,
                        "RecordType": record_type,
                        "RecordLine": "默认",
                        "Value": record_type,
                    }
                )
        return None

    async def get_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
    ) -> Optional[str]:
        records: list[Record] = await self.list_records(domain)
        for record in records:
            if record.Name == hostname and record.Type == record_type:
                return record.Value
        return None

    async def list_records(
        self,
        domain: str,
    ) -> list:
        resp = await self._post_action(
            "DescribeRecordList",
            {
                "Domain": domain
            },
            True
        )
        results: list[Record] = []
        for record in resp.Response["RecordList"]:
            results.append(
                Record(
                    record["RecordId"],
                    record["Name"],
                    record["Type"],
                    record["Value"]
                )
            )
        return results

    async def _post_action(self, action: str, data: dict[str, Any] = {}, cache: bool = False) -> HTTPResponse:
        if cache:
            c = self.cache[action]
            if not c.expired:
                return c.resp

        timestamp = int(time.time())
        content = self._json_dumps(data or {})
        headers: dict[str, str] = dict(sorted(
            {
                "Content-Type": "application/json",
                "Host": URL,
                "User-Agent": USERAGENT,
                "X-TC-Action": action,
                "X-TC-Client": USERAGENT,
                "X-TC-Timestamp": str(timestamp),
                "X-TC-Version": DATE
            }.items(),
            key=lambda x: x[0]
        ))
        headers_str = "\n".join((f"{k}:{v}".lower() for k, v in headers.items() if k.lower() in TENCENT_HEADERS))
        headers_keys = ";".join(TENCENT_HEADERS)
        date = time.strftime("%Y-%m-%d", time.gmtime())
        sign = hmac.new(self._signature(f"TC3{self._secret}", date, "dnspod", "tc3_request"), f"TC3-HMAC-SHA256\n{timestamp}\n{date}/dnspod/tc3_request\n{self._hash_content(f"POST\n/\n\n{headers_str}\n\n{headers_keys}\n{self._hash_content(content)}")}".encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = f"TC3-HMAC-SHA256 Credential={self._key_id}/{date}/dnspod/tc3_request, SignedHeaders={headers_keys}, Signature={sign}"
    
        async with aiohttp.ClientSession(
            f"https://{URL}",
            headers={
                "Authorization": authorization,
                **headers
            }
        ) as session:
            async with session.post(
                "/",
                data=content,
            ) as resp:
                resp.raise_for_status()
                response_data = await resp.json()
                response = HTTPResponse(**response_data)
                response.raise_for_error()
                if cache:
                    self.cache[action].resp = response
                    self.cache[action].timestamp = time.monotonic()
                return response

    def _hash_content(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest().lower()
    def _signature(self, *args: str):
        key = args[0].encode("utf-8")
        for arg in args[1:]:
            key = hmac.new(key, arg.encode("utf-8"), hashlib.sha256).digest()
        return key          
    def _json_dumps(self, data):
        return json.dumps(data, separators=(",", ":"))