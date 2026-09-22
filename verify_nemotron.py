import asyncio

from backend.app.services.ai.nemotron_client import NemotronClient


async def main():
    print("Initializing Nemotron client...")

    client = NemotronClient()

    print("Configured:", client.is_configured)
    print("Model:", client.model)
    print("Base URL:", client.base_url)

    print("\nSending test request to NVIDIA Nemotron...")

    result = await client.chat_advisory(
        message=(
            "Explain why an open SMB port 445 should be reviewed "
            "on a home network. Give defensive security advice only."
        )
    )

    print("\n--- NEMOTRON RESPONSE ---")
    print("AI available:", result.ai_available)
    print("Model:", result.model_name)
    print("Reply:")
    print(result.reply)

    print("\n--- TEST COMPLETE ---")


if __name__ == "__main__":
    asyncio.run(main())