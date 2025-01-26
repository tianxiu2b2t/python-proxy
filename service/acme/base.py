import abc
import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from ..dns.base import BaseDNS


ECC_KEY_LEN = 256
ROOT = Path(__file__).parent.parent.parent
CERTS_DIR = ROOT / ".cert"
CERTIFICATE_BEFORE_EXPIRED_DAYS = 7

@dataclass
class ACMECertificate:
    certfile: Path
    keyfile: Path
    fullchainfile: Path
    cert: x509.Certificate


class ACMEDNS:
    def __init__(
        self,
        dns_provider: BaseDNS,
    ) -> None:
        self._dns_provider = dns_provider
    
    async def add_record(self, domain: str, name: str, value: str):
        record = await self._dns_provider.get_record(name, domain, "TXT")
        if record is None:
            await self._dns_provider.add_record(name, domain, "TXT", value)
        else:
            await self._dns_provider.modify_record(name, domain, "TXT", value)

    async def remove_record(self, domain: str, name: str):
        record = await self._dns_provider.get_record(name, domain, "TXT")
        if record is not None:
            await self._dns_provider.remove_record(name, domain, "TXT")


class ACMEBase(metaclass=abc.ABCMeta):

    def __init__(
        self,
        email: str,
        domain: str,
        dns_provider: BaseDNS,
    ):
        self._email = email
        self._domain = domain
        self._dns_provider = ACMEDNS(dns_provider)
        self.__jwt = ""
        self._create_account_key()

    @property
    def _dir(self):
        dir = CERTS_DIR / self._domain
        dir.mkdir(parents=True, exist_ok=True)
        return dir

    @abc.abstractmethod
    async def get_certificate(
        self,
        *subdomains: str,
        force: bool = False 
    ) -> Optional[ACMECertificate]:
        raise NotImplementedError

    @abc.abstractmethod
    async def initialize(self):
        raise NotImplementedError
    
    @abc.abstractmethod
    async def check_certificates(self):
        raise NotImplementedError
    
    def _create_account_key(self):
        path = self._dir / "account.key"
        if self._file_exists(path):
            return
        self._write_random_key(path)

    def _write_random_key(self, path: Path):
        path.write_bytes(
            ec.generate_private_key(
                ec.SECP256R1(), 
                default_backend()
            ).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    def _file_exists(self, path: Path):
        return path.exists() and path.stat().st_size > 0
    
    @property
    def _account_jwt(self):
        if self.__jwt:
            return self.__jwt
        path = self._dir / "account.key"
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        x, y = public_numbers.x, public_numbers.y
        x_bytes, y_bytes = x.to_bytes(32, 'big'), y.to_bytes(32, 'big')
        x64, y64 = base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('='), base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('=')
        self.__jwt = json.dumps({
            "crv": "P-256",
            "kty": "EC",
            "x": x64,
            "y": y64
        })
        return self.__jwt
    
    def get_subdomains_hash(self, subdomains: tuple[str, ...]):
        return hashlib.sha256(''.join(subdomains).encode()).hexdigest()
    
    

def get_subject_names(
    cert: x509.Certificate
):
    res = []
    for name in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if isinstance(name, bytes):
            res.append(name.decode())
            continue
        res.append(name.value)
    return res