import httpx

from config.config import ClientConfig


class Client:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.async_client: httpx.AsyncClient | None = None

    async def get_captcha_token(self) -> str:
        self.group_seed = "123456789"
        admin_url = f"{self.config.admin_url}/get_captcha_token"
        params = {"request_group_seed": self.group_seed}
        response = await self.async_client.get(admin_url, params=params)
        if response.status_code == 200:
            return response.json().get("captcha_token")

        raise Exception("Failed to get captcha token from admin endpoint")

    async def send_login_request(self, username: str, password: str, totp_token: str | None = None) -> httpx.Response:
        data = {"username": username, "password": password}
        if totp_token is not None:
            data["totp_token"] = totp_token
        response = await self.async_client.post(
            url=self.config.target_url,
            json=data,
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 403:
            try:
                error_data = response.json()
                if error_data.get("captcha_required"):

                    new_token = await self.get_captcha_token()
                    data["captcha_token"] = new_token
                    response = await self.async_client.post(
                        url=self.config.target_url,
                        json=data,
                        headers={"Content-Type": "application/json"}
                    )
                    return response
            except Exception as e:
                print(e)

        return response


    async def __aenter__(self) -> 'Client':
        self.async_client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.async_client.aclose()
