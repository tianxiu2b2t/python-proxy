import asyncio
from collections import deque
import ssl
from typing import Optional

import config
from logger import logger
import utils

from .common import Client, Proxy, find_origin_ip, get_origin_info, process, ForwardAddress, add_proxy
from service import acme_zerossl, dns

SUPPORT_PROTOCOLS = []#["h2", "http/1.1"]

pub_tcp_port_tasks: dict[int, asyncio.Task] = {}
pri_tcp_port_tasks: dict[int, asyncio.Task] = {}
pri_sni_context: dict[str, ssl.SSLContext] = {}
pri_context_port: dict[ssl.SSLContext, int] = {}
forward_tasks: deque[asyncio.Task] = deque()
pri_tasks: deque[asyncio.Task] = deque()
pub_servers: dict[int, asyncio.Server] = {}
pri_servers: dict[int, asyncio.Server] = {}

async def init():
    instance = acme_zerossl.ACMEZeroSSL(
        "administrator@ttb-network.top",
        "ttb-network.top",
        dns_provider=dns.DNSPod(
            config.env.get("TENCENT_ID") or "",
            config.env.get("TENCENT_SECRET") or ""
        )
    )
    await instance.init()
    await start_server(80, None)
    for proxy in config.config.get("proxies", []):
        hosts = proxy["hosts"]
        ports = proxy["ports"]
        subdomains = proxy["subdomains"]
        url = proxy["url"]
        forward_ip_headers = proxy.get("forward_ip_headers", [])
        for host in hosts:
            add_proxy(host, Proxy(
                url,
                forward_ip_headers
            ))
        cert = await instance.get_certificate(*subdomains)
        for port in ports:
            await start_server(port, cert)


async def _pub_handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    client = Client(reader, writer)
    buffer = await client.read(16384)
    if not utils.ssl.is_ssl_or_tls_data(buffer):
        client.feed_data(buffer)
        await process(client)
        return

    sni = utils.ssl.get_client_handshake_info(buffer)
    if sni.sni is None:
        await client.close()
        return
    context = pri_sni_context.get(sni.sni)
    if context is None:
        await client.close()
        return
    pri_port = pri_context_port.get(context)
    if pri_port is None:
        await client.close()
        return
    client.feed_data(buffer)
    _start_forward(
        client,
        pri_port,
        sni.sni
    )

async def _forward_data(
    from_conn: Client,
    to_conn: Client,
):
    while 1:
        data = await from_conn.read(16384)
        if not data:
            break
        await to_conn.write(data)
    
def _start_forward(
    client: Client,
    pri_port: int,
    sni: Optional[str] = None 
):
    task = asyncio.create_task(_forward(client, pri_port, sni))
    task.add_done_callback(lambda _: pri_tasks.remove(task))
    pri_tasks.append(task)

async def _forward(
    client: Client,
    pri_port: int,
    sni: Optional[str] = None 
):
    try:
        conn = Client(
            *await asyncio.wait_for(
                asyncio.open_connection(
                    '127.0.0.1',
                    pri_port
                ), 5
            )
        )
        with ForwardAddress(
            client.address,
            conn._writer.get_extra_info('sockname'),
            sni
        ):
            try:
                await asyncio.gather(
                    asyncio.create_task(_forward_data(client, conn)),
                    asyncio.create_task(_forward_data(conn, client))
                )
            except:
                await conn.close()
    except:
        logger.traceback()
        return

async def _start_pub_server_tcp(
    port: int,
):
    if port in pub_servers:
        return
    server = await asyncio.start_server(
        _pub_handle_tcp,
        '',
        port=port
    )
    pub_servers[port] = server
    await server.start_serving()
    logger.info(f"Public server start on {port}")

async def _pri_handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    client = Client(reader, writer, find_origin_ip(writer.get_extra_info('peername')))
    origin_info = get_origin_info(client.address)
    sni = None if origin_info is None else origin_info.sni
    task = asyncio.create_task(process(client, sni))
    task.add_done_callback(
        lambda _: pri_tasks.remove(task)
    )
    pri_tasks.append(task)

async def _start_pri_server_tcp(
    context: ssl.SSLContext
):
    server = await asyncio.start_server(
        _pri_handle_tcp,
        '127.0.0.1',
        port=0,
        ssl=context
    )
    pri_servers[server.sockets[0].getsockname()[1]] = server
    pri_context_port[context] = server.sockets[0].getsockname()[1]
    await server.start_serving()
    logger.info(f"Private server start on {server.sockets[0].getsockname()[1]}")
    return server.sockets[0].getsockname()[1]

async def start_server(
    port: int,
    certificate: Optional[acme_zerossl.ACMECertificate] = None
):
    await _start_pub_server_tcp(port)
    if certificate is None:
        return
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certificate.fullchainfile, certificate.keyfile)
    if SUPPORT_PROTOCOLS:
        context.set_alpn_protocols(SUPPORT_PROTOCOLS)
    for domain in acme_zerossl.get_subject_names(certificate.cert):
        pri_sni_context[domain] = context
    await _start_pri_server_tcp(context)

async def unload():
    for server in pri_servers.values():
        server.close()
    for server in pub_servers.values():
        server.close()
    for task in pub_tcp_port_tasks.values():
        task.cancel()
    for task in pri_tcp_port_tasks.values():
        task.cancel()
    for task in forward_tasks:
        task.cancel()
    for task in pri_tasks:
        task.cancel()
