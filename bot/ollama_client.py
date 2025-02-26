import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "wizardcoder:latest"

def ask_ollama(prompt):
    """Отправка запроса в Ollama."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        response_data = response.json()
        return response_data.get("response", "❌ *Ошибка анализа.*")
    except requests.exceptions.RequestException as e:
        return f"*Ошибка подключения к Ollama:* {e}"
