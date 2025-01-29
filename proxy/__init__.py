import asyncio
from dataclasses import dataclass
import datetime
from pathlib import Path
from typing import Optional
import config
from service.acme import ACMECertificate, ACMEBase
from service.acme.zerossl import ZeroSSL
from service.dns import DNSPod, BaseDNS
import web

from cryptography import x509

@dataclass
class ProxyConfigBackendProxyCertificate:
    fullchain: Path
    keyfile: Path
    certfile: Path

@dataclass
class ProxyConfigBackendProxyDNSCertificate:
    dns: BaseDNS
    email: str
    root: str
    subdomains: list[str]

@dataclass
class ProxyConfigBackendProxy:
    hosts: list[str]
    ports: list[int]
    url: str
    force_https: bool = False
    certificate: Optional[ProxyConfigBackendProxyCertificate | ProxyConfigBackendProxyDNSCertificate] = None

class ProxyConfig:
    def __init__(
        self,
        config = config.config,
    ):
        self._config = config
        self._dns_providers: dict[str, BaseDNS] = {}

    def load_dns_provider(self):
        if "dns_providers" not in self._config:
            return 
        cfg = self._config.get("dns_providers")
        for provider in cfg:
            name, type, key, secret = provider['name'], provider['type'], provider['key'], provider['secret']
            if type == "dnspod":
                self._dns_providers[name] = DNSPod(key, secret)

    def load_backend_proxies(self):
        if "backend_proxies" not in self._config:
            return []
        cfg = self._config.get("backend_proxies")
        result = []
        for proxy in cfg:
            hosts = proxy['hosts']
            ports = proxy['ports']
            url = proxy['url']
            force_https = proxy.get('force_https', False)
            certificate = proxy.get('certificate')
            cert = None
            if certificate is not None:
                crt_type = certificate['type']
                if crt_type == "dns":
                    crt_name = certificate['name']
                    dns = self._dns_providers[crt_name]
                    root = certificate['root']
                    subdomains = certificate['subdomains']
                    email = certificate['email']
                    cert = ProxyConfigBackendProxyDNSCertificate(dns, email, root, subdomains)
                elif crt_type == "file":
                    cert = ProxyConfigBackendProxyCertificate(
                        Path(certificate['fullchain']), 
                        Path(certificate['keyfile']),  
                        Path(certificate['certfile'])
                    )
            result.append(
                ProxyConfigBackendProxy(
                    hosts,
                    ports,
                    url,
                    force_https,
                    cert
                )
            )
        return result
                    
cfg = ProxyConfig()
acme_instances: dict[str, ACMEBase] = {}
certs: list[ACMECertificate] = []

async def init():
    cfg.load_dns_provider()
    proxies = cfg.load_backend_proxies()
    for proxy in proxies:
        await start_proxy(proxy)
                

async def start_proxy(
    proxy: ProxyConfigBackendProxy
):
    ...
    # first start server
    cert = None
    if proxy.certificate is not None:
        if isinstance(proxy.certificate, ProxyConfigBackendProxyDNSCertificate):
            root = proxy.certificate.root
            instance = None
            if root not in acme_instances:
                instance = ZeroSSL(
                    proxy.certificate.email,
                    root,
                    proxy.certificate.dns
                )
                acme_instances[root] = instance
                await instance.initialize()
            instance = acme_instances[root]
            cert = await instance.get_certificate(*proxy.certificate.subdomains)
        elif isinstance(proxy.certificate, ProxyConfigBackendProxyCertificate):
            cert = ACMECertificate(
                proxy.certificate.certfile,
                proxy.certificate.keyfile,
                proxy.certificate.fullchain,
                x509.load_pem_x509_certificate(
                    proxy.certificate.certfile.read_bytes(),
                )
            )
    for port in proxy.ports:
        await web.start_server(
            port,
            cert,
        )
    for host in proxy.hosts:
        web.create_proxy(
            host,
            proxy.url,
            proxy.force_https
        )