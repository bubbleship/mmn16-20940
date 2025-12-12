import httpx

from config.config import ClientConfig


class Client:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.async_client: httpx.AsyncClient | None = None

    async def send_login_request(self, username: str, password: str) -> httpx.Response:
        return await self.async_client.post(
            url=self.config.target_url,
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )

    async def __aenter__(self) -> 'Client':
        self.async_client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.async_client.aclose()
