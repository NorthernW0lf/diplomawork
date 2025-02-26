import logging
import asyncio
from aiogram import Bot, Dispatcher
from bot.handlers import handle_text, start_command

TOKEN = "YOUR_BOT_TOKEN"

logging.basicConfig(level=logging.INFO)

bot = Bot(token=TOKEN, parse_mode="Markdown")
dp = Dispatcher()

dp.message.register(handle_text)
dp.message.register(start_command, Command("start"))

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
