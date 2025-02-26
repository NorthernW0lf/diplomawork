from aiogram import types
from aiogram.filters import Command
from aiogram.types import Message
from database.db_manager import check_threats
from bot.ollama_client import ask_ollama

async def handle_text(message: Message):
    response = check_threats(message.text)
    if response:
        await message.answer(response)
    else:
        await message.answer(ask_ollama(f"Анализируй угрозу: {message.text}"))

async def start_command(message: Message):
    await message.answer("👋 Привет! Отправьте мне текст, URL или файл для анализа.")
