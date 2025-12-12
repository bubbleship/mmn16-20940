import asyncio

from client.client import Client
from config.config import ServerConfig, ClientConfig
from server.server import Server


async def main() -> None:
    server_config = ServerConfig('0.0.0.0', 8080)
    client_config = ClientConfig('http://localhost:8080/login')

    server = Server(server_config)
    server.start()

    async with Client(client_config) as client:
        coroutine = client.send_login_request(
            username='admin',
            password='admin'
        )
        responses = await asyncio.gather(coroutine)
        for response in responses:
            print(response, response.json())


if __name__ == "__main__":
    asyncio.run(main())
