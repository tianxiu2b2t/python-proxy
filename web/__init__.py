import asyncio
import ssl
from typing import Optional
import config
from logger import logger
from service import acme, dns
from .protocols import get_client_handshake_info
from .utils import Client, ForwardAddress, ForwardConfig, find_origin, get_origin_cfg
from .core import process, create_application, create_proxy
from .core.app import Request, Response
from .core.common import statistics

pub_servers: dict[int, asyncio.Server] = {}
pri_servers: dict[ssl.SSLContext, asyncio.Server] = {}
contexts_domain: dict[str, ssl.SSLContext] = {}
check_task = None

async def start_server(
    port: int,
    cert: Optional[acme.ACMECertificate],
    http2: bool = False
):
    if port not in pub_servers:
        await _start_pub_server(port)

    if cert is None:
        return
    
    domains = acme.get_subject_names(cert.cert)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert.fullchainfile, keyfile=cert.keyfile)
    context.check_hostname = False
    context.hostname_checks_common_name = False
    context.verify_mode = ssl.CERT_NONE
    if http2:
        context.set_alpn_protocols(['h2', 'http/1.1'])
    for domain in domains:
        contexts_domain[domain] = context
    await _start_pri_server(context)
    
async def _start_pri_server(
    context: ssl.SSLContext,
):
    server = await asyncio.start_server(
        _pri_handle,
        host='127.0.0.1',
        port=0,
        ssl=context
    )
    pri_servers[context] = server
    logger.success(f'Started private server on port {server.sockets[0].getsockname()[1]}')
    
async def _pri_handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    peername = writer.get_extra_info('peername')
    origin = find_origin(peername)
    cfg = get_origin_cfg(origin)
    client = Client(reader, writer, peername=origin or peername)
    try:
        await process(client, cfg)
    except:
        ...
    finally:
        await client.close(10)

async def _pub_handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    client = Client(reader, writer)
    try:
        buffer = await client.read(8192)
        handshake = get_client_handshake_info(buffer)
        client.feed_reader_data(buffer)
        if handshake.version == -1:
            await process(client, ForwardConfig(
                pub_port=client.sockname[1],
            ))
            return
        host = handshake.sni or '*'
        if host not in contexts_domain:
            host = "*"
        server = pri_servers[contexts_domain[host]]
        conn = Client(*(
            await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1",
                    server.sockets[0].getsockname()[1],
                ),
                timeout=5
            )
        ))
        try:
            with ForwardAddress(
                client.peername,
                conn.sockname,
                ForwardConfig(
                    sni=host,
                    pub_port=client.sockname[1],
                    tls=True
                )
            ):
                await forward(
                    client,
                    conn
                )
        except:
            logger.traceback()
            await client.close(10)
    except:
        ...
    finally:
        try:
            await client.close(10)
        except:
            ...
    
async def forward(
    client: Client,
    conn: Client
):
    try:
        await asyncio.gather(
            _forward(client, conn),
            _forward(conn, client)
        )
    except:
        ...

async def _forward(
    from_conn: Client,
    to_conn: Client
):
    while not from_conn.is_closing and (data := await from_conn.read(16384)):
        if not data:
            break
        to_conn.write(data)
        await to_conn.drain()
    await to_conn.close()

async def _start_pub_server(
    port: int
):
    server = await asyncio.start_server(
        _pub_handle,
        host='0.0.0.0',
        port=port
    )
    pub_servers[port] = server
    logger.success(f'Started public server on port {port}')

async def init():
    global check_task
    await start_server(80, None)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False
    contexts_domain['*'] = context
    await _start_pri_server(context)

    zerossl = acme.zerossl.ZeroSSL(
        "administrator@ttb-network.top",
        "ttb-network.top",
        dns.DNSPod(
            config.env.get("TENCENT_ID") or "",
            config.env.get("TENCENT_SECRET") or ""
        )
    )
    await zerossl.initialize()
    cert = await zerossl.get_certificate(
        "api"
    )
    await start_server(443, cert, False)

    check_task = asyncio.get_running_loop().create_task(check_status())
    statistics.start()

async def check_status():
    while True:
        await asyncio.sleep(2)
        # pub
        for server in list(pub_servers.values()):
            failed = any([
                sock.fileno() == -1 for sock in server.sockets
            ])
            if not failed:
                continue
            port = dict((v, k) for k, v in pub_servers.items())[server]
            logger.warning(f"Public server on port {port} is down, restarting...")
            pub_servers.pop(port)
            await _start_pub_server(port)
        # pri
        for server in list(pri_servers.values()):
            failed = any([
                sock.fileno() == -1 for sock in server.sockets
            ])
            if not failed:
                continue
            logger.warning(f"Private server is down, restarting...")
            context = dict((v, k) for k, v in pri_servers.items())[server]
            pri_servers.pop(context)
            await _start_pri_server(context)


async def unload():
    await statistics.stop()
    if check_task:
        check_task.cancel()