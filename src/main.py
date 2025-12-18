import asyncio
import pyotp
from pathlib import Path

from client.client import Client
from config.config import ServerConfig, ClientConfig, MFADefenseConfig, RateLimitDefenseConfig, \
    AccountLockoutDefenseConfig, DefensesConfig
from server import server


async def main() -> None:
    server_config = ServerConfig('0.0.0.0', 8080)
    client_config = ClientConfig('http://localhost:8080/login')

    defense_config = DefensesConfig(
        {MFADefenseConfig(), RateLimitDefenseConfig(10, 20), AccountLockoutDefenseConfig(20)})

    server.start(server_config)
    server.set_users(Path('users.csv'))
    server.set_defenses(defense_config)

    # Give the server some time to start up
    await asyncio.sleep(1)

    async with Client(client_config) as client:
        coroutine1 = client.send_login_request(
            username='admin',
            password='admin'
        )
        coroutine2 = client.send_login_request(
            username='user_1',
            password='london1',
            totp_token=pyotp.TOTP('ZZWLMQ6EGGRI32FQ5TPQ46WUSOMSFNQG').now()  # TEMP
        )
        responses = await asyncio.gather(coroutine1, coroutine2)
        for response in responses:
            try:
                print(f"Status: {response.status_code}")
                if response.status_code == 200:  # Only try to parse JSON for successful responses
                    json_data = response.json()
                    print(f"Response: {json_data}")
                else:
                    print(f"Error response: {response.text}")
            except ValueError as e:
                print(f"Could not parse JSON response: {response.text}")


if __name__ == "__main__":
    asyncio.run(main())
