import asyncio
import pyotp
from pathlib import Path

from client.client import Client
from config.config import ServerConfig, ClientConfig, MFADefenseConfig, RateLimitDefenseConfig, \
    AccountLockoutDefenseConfig, DefensesConfig , CaptchaDefenseConfig
from server import server



async def main() -> None:
    server_config = ServerConfig('0.0.0.0', 8080)
    client_config = ClientConfig(
        target_url='http://localhost:8080/login',
        admin_url='http://localhost:8080/admin'
    )

    defense_config = DefensesConfig(
        {CaptchaDefenseConfig(2), RateLimitDefenseConfig(10, 20), AccountLockoutDefenseConfig(20)})

    server.start(server_config)
    server.set_users(Path('users.csv'))
    server.set_defenses(defense_config)
    server.set_group_seed(Path('users.csv'))

    # Give the server some time to start up
    await asyncio.sleep(2)


    responses = []
    # 3 login attemps where max tries for captcha is 2
    # after 2 bad attemps captcha is required
    # i didn't use async.gather because of race-condition
    async with  Client(client_config) as client1:
        responses.append(await client1.send_login_request(
            username='admin',
            password='wrong')
        )

        responses.append(await client1.send_login_request(
            username='admin',
            password='wrong')
        )

        responses.append(await client1.send_login_request(
            username='admin',
            password='admin')
        )

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

    """
    async with Client(client_config) as client:
        coroutine1_1 = client.send_login_request(
            username='admin',
            password='bad'
        )
        coroutine1_2 = client.send_login_request(
            username='admin',
            password='bad'
        )
        coroutine1_3 = client.send_login_request(
            username='admin',
            password='admin'
        )


        responses = await asyncio.gather(coroutine1_1,coroutine1_2,coroutine1_3)
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


       
         coroutine2 = client.send_login_request(
            username='user_1',
            password='london1',
            totp_token=pyotp.TOTP('ZZWLMQ6EGGRI32FQ5TPQ46WUSOMSFNQG').now()  # TEMP
        )
        """


if __name__ == "__main__":
    asyncio.run(main())
