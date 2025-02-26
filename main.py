import os
import asyncio

# Запускаем базу данных (если её нет)
if not os.path.exists("database/cybersecurity.db"):
    os.system("python database/init_db.py")

# Запускаем Telegram-бота
os.system("python bot/bot.py")
