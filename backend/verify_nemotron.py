import asyncio

from app.services.ai.nemotron_client import NemotronClient


async def main():
    client = NemotronClient()

    print("Configured:", client.is_configured)
    print("Model:", client.model)
    print("Base URL:", client.base_url)

    response = await client._call_model(
        system_prompt="You are a cybersecurity assistant.",
        user_prompt="Reply with exactly: NEMOTRON_OK",
        temperature=0.0,
        max_tokens=20,
    )

    print("NVIDIA RESPONSE:")
    print(response)


if __name__ == "__main__":
    asyncio.run(main())