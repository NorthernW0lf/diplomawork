import os
import re
import logging
import asyncio
import aiohttp
import uuid

from aiogram import Bot, Dispatcher, types
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from aiogram.client.default import DefaultBotProperties 

# Import functions from virustotal.py for scanning attachments and URLs
import virustotal

from filter_vt_report import filter_vt_report
from process_full_report import process_full_report  # Импортируем функцию для обработки полного отчёта

# Global dictionary for storing full reports temporarily
full_reports = {}

# 🔹 Set Ollama parameters 
os.environ["OLLAMA_PARALLEL"] = "1"
os.environ["OLLAMA_THREADS"] = "12"
os.environ["OLLAMA_BACKEND"] = "cuda"
os.environ["OLLAMA_N_GPU_LAYERS"] = "20"
os.environ["OLLAMA_CUDA_MEMORY_LIMIT"] = "3000M"

# 🔹 Telegram Bot Token 
TOKEN = "7631168296:AAHr1A-ZOlYm3sjBRt0NqXznrfHv2IVtvQg"

# 🔹 Ollama API URL and model
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

# 🔹 Logging
logging.basicConfig(level=logging.INFO)

# 🔹 Initialize bot
bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode="Markdown"))
dp = Dispatcher()

WELCOME_MESSAGE = """👋 Hi there! I'm your **Cybersecurity AI Assistant**.

🔹 *Send text* – I'll analyze it.  
🔹 *Send a file* (PDF, DOCX, TXT, EXE, BAT, or JS) – I'll extract & scan it.  
🔹 *Send a URL* – I'll check the webpage for threats.  

💡 I deliver concise responses. Ask for details if needed! 🚀
"""

# 🔹 Precompiled regex pattern for optimization
THINK_PATTERN = re.compile(r"</?think>")

# 🔹 Global aiohttp session
session: aiohttp.ClientSession = None

# ─────────────────────────────────────────────────────────────
#  Function to send a request to Ollama using aiohttp
# ─────────────────────────────────────────────────────────────
async def ask_ollama(prompt: str) -> str:
    system_prompt = (
        "You are a cybersecurity AI agent. You must provide tips and explanations about cybersecurity and answer related questions. "
        "Give a *short response (3-5 words)* with the main result. "
        "Use Markdown formatting: *bold* for key details, _italic_ for emphasis, and include emojis to brighten the text. "
    )
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False
    }
    
    try:
        async with session.post(OLLAMA_URL, json=payload) as response:
            if response.status != 200:
                return f"*Error:* Received status code {response.status} from Ollama."
            response_data = await response.json()
            clean_response = THINK_PATTERN.sub("", response_data.get("response", "")).strip()
            return clean_response if clean_response else "*Error:* No valid response from Ollama."
    except aiohttp.ClientError as e:
        return f"*Error:* Failed to connect to Ollama - {e}"

# ─────────────────────────────────────────────────────────────
#  Function to send long messages (Markdown) with fallback to plain text on error
# ─────────────────────────────────────────────────────────────
async def send_long_message(message: Message, text: str):
    MAX_MESSAGE_LENGTH = 4096
    for i in range(0, len(text), MAX_MESSAGE_LENGTH):
        chunk = text[i:i+MAX_MESSAGE_LENGTH]
        try:
            await message.answer(chunk)
        except Exception as e:
            await message.answer(chunk, parse_mode=None)

# ─────────────────────────────────────────────────────────────
#  Periodically sends a "chat action" until the task completes
# ─────────────────────────────────────────────────────────────
async def show_chat_action(chat_id: int, action: str, task: asyncio.Task, delay: float = 3.0):
    while not task.done():
        await bot.send_chat_action(chat_id, action)
        await asyncio.sleep(delay)

# ─────────────────────────────────────────────────────────────
#  Start command handler
# ─────────────────────────────────────────────────────────────
@dp.message(Command("start"))
async def start_command(message: Message):
    await message.answer(WELCOME_MESSAGE)

# ─────────────────────────────────────────────────────────────
#  Text message handler (excluding documents and URLs)
# ─────────────────────────────────────────────────────────────
@dp.message(lambda message: message.text is not None 
            and message.document is None 
            and message.chat.type == "private" 
            and not message.text.strip().startswith("http"))
async def handle_text(message: Message):
    ai_task = asyncio.create_task(ask_ollama(message.text))
    asyncio.create_task(show_chat_action(message.chat.id, "typing", ai_task))
    response = await ai_task
    await send_long_message(message, response)

# ─────────────────────────────────────────────────────────────
#  URL message handler – messages starting with "http"
# ─────────────────────────────────────────────────────────────
@dp.message(lambda message: message.text is not None and message.text.strip().startswith("http"))
async def handle_url(message: Message):
    url = message.text.strip()
    await message.answer("🌐 URL received! Scanning the webpage via VirusTotal...")
    
    url_scan_task = asyncio.create_task(virustotal.vt_scan_url(url))
    asyncio.create_task(show_chat_action(message.chat.id, "typing", url_scan_task))
    vt_result_json = await url_scan_task
    filtered_report = filter_vt_report(vt_result_json)
    
    prompt_for_ai = (
        "You are a cybersecurity AI assistant. Analyze the following filtered VirusTotal report JSON. "
        "The JSON contains key statistics in the 'stats' field (including 'malicious' and 'suspicious').\n\n"
        "Decision criteria:\n"
        "1. If 'malicious' count is greater than 5, classify it as 'DANGEROUS'.\n"
        "2. If 'malicious' count is 5 or less and there is at least one 'suspicious' detection, classify it as 'SUSPICIOUS'.\n"
        "3. Otherwise, classify it as 'SAFE'.\n\n"
        "Additional recommendations:\n"
        "- For a URL that is SUSPICIOUS, provide brief precaution recommendations for cautious browsing (e.g., verify the source, avoid entering personal data).\n"
        "- For a file that is DANGEROUS, provide short advice on handling dangerous files (e.g., do not open, run a thorough antivirus scan, isolate from network).\n\n"
        "Respond with a one-word verdict ('DANGEROUS', 'SUSPICIOUS', or 'SAFE') followed by any necessary recommendations, and nothing else.\n\n"
        "JSON Report:\n\n"
        f"{filtered_report}")

    
    ai_task = asyncio.create_task(ask_ollama(prompt_for_ai))
    asyncio.create_task(show_chat_action(message.chat.id, "typing", ai_task))
    short_report = await ai_task

    # Store full report and create inline keyboard for detailed view
    report_key = str(uuid.uuid4())
    full_reports[report_key] = vt_result_json

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📄 View Full Report", callback_data=f"view_full_report:{report_key}")]
    ])
    
    await send_long_message(message, short_report)
    await message.answer("Click the button below to view the detailed report summary:", reply_markup=keyboard)

# ─────────────────────────────────────────────────────────────
#  Document (file) handler
# ─────────────────────────────────────────────────────────────
@dp.message(lambda message: message.document is not None)
async def handle_document(message: Message):
    document = message.document
    file = await bot.get_file(document.file_id)
    file_url = f"https://api.telegram.org/file/bot{TOKEN}/{file.file_path}"
    try:
        async with session.get(file_url, ssl=False) as resp:
            if resp.status != 200:
                await message.answer("❌ *Error:* Failed to download the file.")
                return
            file_bytes = await resp.read()
    except Exception as e:
        await message.answer(f"❌ Error: Failed to download the file - {e}", parse_mode=None)

        return

    await message.answer("✅ File received! 🚀 Sending it for VirusTotal scanning...")
    
    scanning_task = asyncio.create_task(virustotal.vt_scan_file(file_bytes, document.file_name))
    asyncio.create_task(show_chat_action(message.chat.id, "upload_document", scanning_task))
    vt_result_json = await scanning_task
    filtered_report = filter_vt_report(vt_result_json)
    
    prompt_for_ai = (
        "You are a cybersecurity AI assistant. Analyze the following filtered VirusTotal report JSON for the file. "
        "The JSON contains key statistics in the 'stats' field (including 'malicious' and 'suspicious').\n\n"
        "Decision criteria:\n"
        "1. If the 'malicious' count is greater than 5, classify the file as 'DANGEROUS'.\n"
        "2. If the 'malicious' count is 5 or less and there is at least one 'suspicious' detection, classify it as 'SUSPICIOUS'.\n"
        "3. Otherwise, classify it as 'SAFE'.\n\n"
        "Additional recommendations for files:\n"
        "- For a file classified as DANGEROUS, provide a brief advice such as 'Do not open, run a thorough antivirus scan, and isolate from network.'\n\n"
        "Respond with a one-word verdict ('DANGEROUS', 'SUSPICIOUS', or 'SAFE') followed by any necessary recommendations, and nothing else.\n\n"
        "JSON Report:\n\n"
        f"{filtered_report}")

    
    ai_task = asyncio.create_task(ask_ollama(prompt_for_ai))
    asyncio.create_task(show_chat_action(message.chat.id, "typing", ai_task))
    short_report = await ai_task

    # Store full report with unique key
    report_key = str(uuid.uuid4())
    full_reports[report_key] = vt_result_json
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📄 View Full Report", callback_data=f"view_full_report:{report_key}")]
    ])
    
    await send_long_message(message, short_report)
    await message.answer("Click the button below to view the detailed report summary:", reply_markup=keyboard)

# ─────────────────────────────────────────────────────────────
#  Callback query handler to process full report summary
# ─────────────────────────────────────────────────────────────
@dp.callback_query(lambda c: c.data and c.data.startswith("view_full_report:"))
async def process_full_report_callback(callback_query: types.CallbackQuery):
    report_key = callback_query.data.split(":", 1)[1]
    full_report_str = full_reports.get(report_key, None)
    if not full_report_str:
        await callback_query.message.answer("Full report not found.")
        await callback_query.answer()
        return

    # Use the external module to process the full report and generate a summary
    summary = process_full_report(full_report_str)
    await callback_query.message.answer(summary, parse_mode="Markdown")
    await callback_query.answer()

# ─────────────────────────────────────────────────────────────
#  Main function to run the bot
# ─────────────────────────────────────────────────────────────
async def main():
    global session
    async with aiohttp.ClientSession() as sess:
        session = sess
        await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
