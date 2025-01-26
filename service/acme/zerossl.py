import asyncio
import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Optional

import aiohttp.typedefs

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID

import config
from logger import logger
from . import base

@dataclass
class Action:
    newNonce: str
    newAccount: str
    newOrder: str
    revokeCert: str
    keyChange: str

@dataclass
class ACMEEAB:
    key: str
    hmac: str

@dataclass
class ACMEConfig:
    account_url: str = ""

@dataclass
class ACMEOrderAuthorization:
    type: str
    value: str
    authorization: str

@dataclass
class ACMEOrder:
    identifiers: list[ACMEOrderAuthorization]
    finalize: str

@dataclass
class ACMEChallenge:
    authorization: str
    chall: str
    txt_value: str

@dataclass
class ACMEResponse:
    headers: aiohttp.typedefs._CIMultiDictProxy
    data: Any

class ZeroSSL(base.ACMEBase):
    def __init__(self, email: str, domain: str, dns_provider: base.BaseDNS):
        super().__init__(email, domain, dns_provider)
        self._eab = ACMEEAB("", "")
        self._config = self._load_config()
        self._share_nonce = ""
        self._subdomains: dict[str, list[str]] = self._load_subdomains()

    async def initialize(self):
        await self._fetch_eab_kid()
        await self._reg_account()
        return ...
    
    async def _reg_account(self):
        if self._config is not None and self._config.account_url:
            return
        eab_protected = self._base64_url_replace(json.dumps({"alg": "HS256","kid": self._eab.key, "url": ACTION.newAccount}))
        eab_payload = self._base64_url_replace(self._account_jwt)
        eab_signature = base64.urlsafe_b64encode(
            hmac.new(base64.urlsafe_b64decode(self._eab.hmac + "=="), f'{eab_protected}.{eab_payload}'.encode('utf-8'), hashlib.sha256).digest()
        ).decode('utf-8').replace('=', '')
        regjson = {
            "contact": [f"mailto:{self._email}"],
            "termsOfServiceAgreed": True,
            "externalAccountBinding": {
                "protected": eab_protected,
                "payload": eab_payload,
                "signature": eab_signature
            }
        }
        resp = await self._request(
            ACTION.newAccount,
            regjson,
            {
                "jwk": self._account_jwt
            }
        )
        headers = resp.headers
        self._config.account_url = headers.get("Location", "")
        self._save_config()
    
    async def _fetch_eab_kid(self):
        path = self._dir / 'eab.kid'
        if self._file_exists(path):
            try:
                self._eab = ACMEEAB(**json.loads(path.read_text()))
                return
            except:
                ...
        async with self._client_session() as session:
            async with session.post(
                "https://api.zerossl.com/acme/eab-credentials-email",
                data={
                    "email": self._email
                }
            ) as resp:
                data = await resp.json()
                self._eab = ACMEEAB(key=data["eab_kid"], hmac=data["eab_hmac_key"])
                path.write_text(json.dumps(asdict(self._eab)))
        
    async def _request(self, url: str, data: Any, protect: dict[str, Any] = {}) -> ACMEResponse:
        if isinstance(data, (dict, list, tuple)):
            raw_data = json.dumps(data)
        else:
            raw_data = data
        data_body = await self._signature_data_body(url, protect, self._base64_url_replace(raw_data))
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={
                    "Content-Type": "application/jose+json"
                }, data=data_body
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
                content = await resp.read()
                try:
                    data = json.loads(content)
                    if resp.status // 1 == 4 or "problem" in resp.content_type or data["status"] == 400:
                        logger.error(f"ACME Error: {data['type']} {data['status']}, detail: {data['detail']}, request data: {raw_data}")
                except:
                    data = content
                return ACMEResponse(
                    resp.headers,
                    data
                )       
    
    async def _new_nonce(self):
        if self._share_nonce:
            return self._share_nonce
        async with self._client_session() as session:
            async with session.head(
                ACTION.newNonce,
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
        return self._share_nonce

    async def _signature_data_body(self, url: str, protect: dict[str, Any], payload: str):
        protected = self._base64_url_replace(json.dumps({
            "nonce": await self._new_nonce(),
            "url": url,
            "alg": f"ES256",
            **protect
        }))
        return json.dumps({
            "protected": protected,
            "payload": payload,
            "signature": self._sign(f'{protected}.{payload}')
        })
    
    def _base64_url_replace(self, data: str):
        return base64.urlsafe_b64encode(data.encode("utf-8")).decode().replace('=', '')

    def _sign(self, data: str):
        path = self._dir / "account.key"
        private_key = serialization.load_pem_private_key(
            path.read_bytes(),
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign( # type: ignore
            data.encode(),
            ec.ECDSA(hashes.SHA256()) # type: ignore
        )
        der_signature_r, der_signature_s = utils.decode_dss_signature(signature)
        der_signature_hex = binascii.hexlify(
            der_signature_r.to_bytes(32, byteorder='big') + der_signature_s.to_bytes(32, byteorder='big'))
        return base64.urlsafe_b64encode(bytes.fromhex(der_signature_hex.decode('ascii'))).decode('ascii').replace('=', '')
    

    async def check_certificates(self):
        return ...
    
    async def get_certificate(self, *subdomains: str, force: bool = False) -> Optional[base.ACMECertificate]:
        subdomain_hash = self.get_subdomains_hash(subdomains)
        if subdomain_hash not in self._subdomains:
            self._subdomains[subdomain_hash] = list(subdomains)
            self._save_subdomains()

        ca_file = self._dir / f"fullchain_{subdomain_hash}.cer"
        key_file = self._dir / f"privkey_{subdomain_hash}.key"
        csrfile = self._dir / f"domain_{self.get_subdomains_hash(subdomains)}.csr"
        if self._file_exists(ca_file) and self._file_exists(key_file) and self._file_exists(csrfile) and not force:
            return base.ACMECertificate(
                csrfile,
                key_file,
                ca_file,
                x509.load_pem_x509_certificate(ca_file.read_bytes(), default_backend()),
            )
        
        display_subdomains = f"[{self._domain} ({', '.join(subdomains)})]"
        if not self._file_exists(key_file):
            logger.info(f"{display_subdomains} generating account key")
            self._write_random_key(key_file)
        
        logger.info(f"{display_subdomains} new order")
        order = await self._send_order(list(subdomains))
        logger.info(f"{display_subdomains} Send challenges")
        txt_records: dict[str, ACMEChallenge] = {
            i.value: await self._get_challenge(i) for i in order.identifiers
        }
    
        await self._add_record(txt_records)

        status = await self._start_verify(txt_records)
        await self._remove_record(txt_records)

        if not all(status.values()):
            for name, value in status.items():
                if not value:
                    logger.error(f"{display_subdomains} Challenge failed for {name}")
            return
        
        self._create_subdomains_csr(*subdomains)

        link = await self._finalize_order(*subdomains, order=order)
        if link is None:
            logger.error(f"{display_subdomains} Finalize failed")
            return
        
        logger.info(f"{display_subdomains} Download certificate")
        await self._download_certificate(link, ca_file)

        return base.ACMECertificate(
                csrfile,
                key_file,
                ca_file,
            x509.load_pem_x509_certificate(ca_file.read_bytes(), default_backend()),
        )

    async def _download_certificate(self, link: str, ca_file: Path):
        resp = await self._request(link, "", {
            "kid": self._config.account_url,
        })
        content = resp.data
        if not content:
            logger.error(f"download certificate failed, data: {content}")
        ca_file.write_bytes(content)


    async def _finalize_order(self, *subdomains: str, order: ACMEOrder):
        csrfile = self._dir / f"domain_{self.get_subdomains_hash(subdomains)}.csr"
        csr = csrfile.read_text().replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").replace("\r", "").replace("\n", "").replace(" ", "")
        der = base64.urlsafe_b64encode(base64.b64decode(csr)).decode().rstrip('=')
        resp = await self._request(
            order.finalize,
            {
                "csr": der
            },
            {
                "kid": self._config.account_url,
            }
        )
        data = resp.data
        status = data['status']
        if status == "valid":
            return data['certificate']
        elif status == "processing":
            while not status == "valid":
                await asyncio.sleep(5)
                link_order_url: str = resp.headers.get("Location") # type: ignore
                data = (await self._request(
                    link_order_url,
                    "",
                    {
                        "kid": self._config.account_url,
                    }
                )).data
                status = data['status']
                if status == "valid":
                    return data['certificate']
                elif status == "invalid":
                    logger.error(f"finalize failed, data: {data}")
                    return None
        else:
            logger.warning(f"unknown status: {status}, data: {data}")

    async def _start_verify(self, txt_records: dict[str, ACMEChallenge]):
        status: dict[str, bool] = {}
        for domain, result in zip(
            txt_records.keys(),
            await asyncio.gather(*[self._verify(i, challenge) for i, challenge in txt_records.items()]),
        ):
            status[domain] = result
        return status

    async def _verify(self, domain: str, challenge: ACMEChallenge) -> bool:
        resp = await self._request(
            challenge.chall,
            self._base64_url_replace(json.dumps({})),
            {
                "kid": self._config.account_url,
            }
        )
        if resp.data['status'] == "invaild":
            return False
        status = resp.data['status']
        while status != "valid":
            logger.debug(f"Verify {domain} {status}")
            await asyncio.sleep(5)
            resp = await self._request(
                challenge.authorization,
                "",
                {
                    "kid": self._config.account_url,
                }
            )
            status = resp.data['status']
        if status == "valid":
            return True
        return False

    async def _add_record(self, txt_values: dict[str, ACMEChallenge]):
        for name, challenge in txt_values.items():
            name = self._get_domain_name(name)
            logger.info(f"Add TXT record for {name}")
            await self._dns_provider.add_record(self._domain, name, challenge.txt_value)

    async def _remove_record(self, txt_values: dict[str, ACMEChallenge]):
        for name, challenge in txt_values.items():
            name = self._get_domain_name(name)
            logger.info(f"Remove TXT record for {name}")
            await self._dns_provider.remove_record(self._domain, name)

    async def _get_challenge(self, order: ACMEOrderAuthorization):
        authorization = order.authorization
        resp = await self._request(
            authorization,
            "",
            {
                "kid": self._config.account_url,
            }
        )
        data = resp.data
        token, chall = '', ''
        for i in (data['challenges']):
            if i['type'] == 'dns-01':
                token = i['token']
                chall = i['url']
                break
        key_authorization = token + "." + self._sha256_urlb64(self._account_jwt)
        txt_value = self._sha256_urlb64(key_authorization)
        return ACMEChallenge(
            authorization,
            chall, 
            txt_value
        )

    async def _send_order(self, domains: list[str]):
        data = (await self._request(
            ACTION.newOrder,
            {
                "identifiers": [{"type": "dns", "value": f"{domain}.{self._domain}"} for domain in domains]
            },
            {
                "kid": self._config.account_url,
            }
        )).data
        orders: list[ACMEOrderAuthorization] = []
        for i, value in enumerate(data['authorizations']):
            orders.append(ACMEOrderAuthorization(
                data['identifiers'][i]['type'],
                data['identifiers'][i]['value'],
                value
            ))
        return ACMEOrder(
            orders,
            data['finalize'],
        )


    def _load_subdomains(self):
        path = self._dir / "subdomains.json"
        if path.exists() and path.stat().st_size != 0:
            with open(path, "r") as f:
                try:
                    return json.load(f)
                except:
                    ...
        return {}

    def _save_subdomains(self):
        with open(self._dir / "subdomains.json", "w") as f:
            json.dump(self._subdomains, f)

    def _save_config(self):
        path = self._dir / "config.json"
        path.write_text(json.dumps(asdict(self._config)))


    def _load_config(self):
        path = self._dir / "config.json"
        if path.exists() and path.stat().st_size > 0:
            try:
                return ACMEConfig(**json.loads(path.read_text()))
            except:
                ...
        logger.error("failed to load config")
        return ACMEConfig()
    

    def _client_session(self):
        return aiohttp.ClientSession(
            headers={
                'User-Agent': "TTB-Network-Proxy/0.0.1"
            },
            proxy=HTTP_PROXY
        )

    def _create_subdomains_csr(self, *subdomains: str):
        subdomains_hash = self.get_subdomains_hash(subdomains)
        keyfile = self._dir / f"privkey_{subdomains_hash}.key"
        csrfile = self._dir / f"domain_{subdomains_hash}.csr"
        if csrfile.exists() and csrfile.stat().st_size > 0:
            return csrfile
        
        private_key = serialization.load_pem_private_key(
            keyfile.read_bytes(),
            password=None
        )
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subdomains[0] + "." + self._domain),
        ])
        alt_names = [x509.DNSName(f"{d}.{self._domain}") for d in subdomains]
        san = x509.SubjectAlternativeName(alt_names)

        eku_extension = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,  # TLS Web Server Authentication
            ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS Web Client Authentication
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .add_extension(eku_extension, critical=False)
                .add_extension(san, critical=False)
                .sign(private_key, hashes.SHA256(), default_backend()) # type: ignore
        )
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        csrfile.write_bytes(pem.encode())

    def _get_domain_name(self, name: str):
        return ("_acme-challenge." + name.removesuffix(self._domain).replace("*.", "")).rstrip(".")

    def _sha256_urlb64(self, data: str):
        return base64.urlsafe_b64encode(hashlib.sha256(data.replace(' ', '').encode("utf8")).digest()).decode().replace('=', '')


ACTION = Action(
    newNonce='https://acme.zerossl.com/v2/DV90/newNonce',
    newAccount='https://acme.zerossl.com/v2/DV90/newAccount',
    newOrder='https://acme.zerossl.com/v2/DV90/newOrder',
    revokeCert='https://acme.zerossl.com/v2/DV90/revokeCert',
    keyChange='https://acme.zerossl.com/v2/DV90/keyChange'
)
HTTP_PROXY = config.config.get("proxy.http")