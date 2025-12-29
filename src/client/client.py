import httpx

from src.config.config import ClientConfig


class Client:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.async_client: httpx.AsyncClient | None = None

    async def get_captcha_token(self) -> str:
        admin_url = f"{self.config.admin_url}/get_captcha_token"
        params = {"request_group_seed": self.config.group_seed}
        response = await self.async_client.get(admin_url, params=params)
        if response.status_code == 200:
            return response.json().get("captcha_token")

        raise Exception(f"Failed to get captcha token from admin endpoint {response}")

    async def send_login_request(self, username: str, password: str, totp_token: str | None = None,
                                 captcha_token: str | None = None) -> httpx.Response:
        data = {"username": username, "password": password}
        if totp_token is not None:
            data["totp_token"] = totp_token
        if captcha_token is not None:
            data["captcha_token"] = captcha_token
        response = await self.async_client.post(
            url=self.config.target_url,
            json=data,
            headers={"Content-Type": "application/json"}
        )

        return response

    async def __aenter__(self) -> 'Client':
        self.async_client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.async_client.aclose()
