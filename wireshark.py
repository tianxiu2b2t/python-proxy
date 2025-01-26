import asyncio


async def main():
    server = await asyncio.start_server(
        client_connected_cb=handle_client,
        host="127.0.0.1",
        port=8888,
    )
    async with server:
        await server.serve_forever()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
) -> None:
    while (data := await reader.read(16384)):
        print(data)
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())