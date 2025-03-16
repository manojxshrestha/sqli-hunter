import os
import sys
import asyncio
import json
import aiohttp
from urllib.parse import quote

# Bot token (prefer env var)
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    print("Error: TELEGRAM_BOT_TOKEN environment variable not set.")
    sys.exit(1)

# Telegram API base URL
TELEGRAM_API = f"https://api.telegram.org/bot{TOKEN}"

# Persistent chat IDs
CHAT_IDS_FILE = "registered_chat_ids.txt"
REGISTERED_CHAT_IDS = set()
if os.path.exists(CHAT_IDS_FILE):
    with open(CHAT_IDS_FILE, "r") as f:
        REGISTERED_CHAT_IDS.update(int(line.strip()) for line in f if line.strip().isdigit())

async def save_chat_ids():
    """Save registered chat IDs to file."""
    with open(CHAT_IDS_FILE, "w") as f:
        for chat_id in REGISTERED_CHAT_IDS:
            f.write(f"{chat_id}\n")

async def send_message(chat_id: int, message: str, require_registration: bool = True) -> None:
    """Send a message to a specific chat ID using the Telegram API."""
    if require_registration and chat_id not in REGISTERED_CHAT_IDS:
        print(f"Chat ID {chat_id} not registered—ignoring.")
        return

    async with aiohttp.ClientSession() as session:
        url = f"{TELEGRAM_API}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message[:4096],  # Truncate to Telegram limit
            "parse_mode": "Markdown"
        }
        try:
            async with session.post(url, json=payload) as response:
                data = await response.json()
                if not data.get("ok"):
                    print(f"Failed to send to {chat_id}: {data.get('description', 'Unknown error')}")
                else:
                    print(f"Sent to {chat_id}: {message[:50]}...")
        except Exception as e:
            print(f"Failed to send to {chat_id}: {e}")

async def start_command(chat_id: int) -> None:
    """Handle the /start command."""
    REGISTERED_CHAT_IDS.add(chat_id)
    await save_chat_ids()
    message = (
        f"*SQLiHunterBot*\nYour chat ID: `{chat_id}`\n"
        f"Use with `-n {chat_id}` in `sqli-hunter.sh` for updates."
    )
    await send_message(chat_id, message, require_registration=False)

async def id_command(chat_id: int) -> None:
    """Handle the /id command."""
    message = f"Your chat ID: `{chat_id}`"
    await send_message(chat_id, message, require_registration=False)

async def process_update(update: dict) -> None:
    """Process incoming updates from Telegram."""
    if "message" not in update:
        return

    message = update["message"]
    chat_id = message["chat"]["id"]
    text = message.get("text", "")

    if not text.startswith("/"):
        return  # Ignore non-commands for now

    command = text.split()[0].lower()
    if command == "/start":
        await start_command(chat_id)
    elif command == "/id":
        await id_command(chat_id)

async def get_updates(offset: int = None) -> dict:
    """Fetch updates from Telegram using long polling."""
    async with aiohttp.ClientSession() as session:
        url = f"{TELEGRAM_API}/getUpdates"
        params = {"timeout": 60}  # Long polling timeout
        if offset:
            params["offset"] = offset
        try:
            async with session.get(url, params=params) as response:
                data = await response.json()
                if not data.get("ok"):
                    print(f"Failed to get updates: {data.get('description', 'Unknown error')}")
                    return {"ok": False, "result": []}
                return data
        except Exception as e:
            print(f"Error fetching updates: {e}")
            return {"ok": False, "result": []}

async def main() -> None:
    """Run the bot using long polling."""
    print("Bot running. Ctrl+C to stop.")
    offset = None
    while True:
        updates = await get_updates(offset)
        if not updates["ok"]:
            await asyncio.sleep(1)  # Avoid hammering the API on failure
            continue

        for update in updates["result"]:
            await process_update(update)
            offset = update["update_id"] + 1  # Update the offset to mark this update as processed

        await asyncio.sleep(0.1)  # Small delay to avoid excessive CPU usage

if __name__ == "__main__":
    if len(sys.argv) > 2:  # CLI mode: python3 sqlihunter_bot.py <chat_id> <message>
        chat_id = int(sys.argv[1])
        message = " ".join(sys.argv[2:])
        asyncio.run(send_message(chat_id, message))
    else:
        asyncio.run(main())
