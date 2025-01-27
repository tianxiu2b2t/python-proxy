import asyncio

local_port = 443
remote_host = 'localhost'
remote_port = 23333

async def forward(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    while (data := await reader.read(16384)):
        if not data:
            break
        writer.write(data)
        await writer.drain()
    writer.close()


async def handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    # TODO: implement
    try:
        r, w = await asyncio.open_connection(
            'localhost', 23333
        )
        try:
            await asyncio.gather(
                forward(reader, w),
                forward(r, writer),
            )
        finally:
            w.close()
    finally:
        writer.close()


async def main():

    server = await asyncio.start_server(
        handle,
        port=local_port
    )

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())