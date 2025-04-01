import requests
import json

# Ваш OTX API key
OTX_API_KEY = "152b846985bbc971cf67664a4572f915b8f2fbb5b76a5afe6f4894867904cbd9"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def get_otx_url_reputation(url: str) -> dict:
    """
    Получает репутационную информацию для URL через OTX.
    Endpoint: GET /api/v1/indicators/url/{indicator}/general

    Аргументы:
      url: адрес сайта (без протокола, например "example.com")
    Возвращает:
      JSON-ответ с информацией о репутации URL.
    """
    endpoint = f"{OTX_BASE_URL}/indicators/url/{url}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

def get_otx_file_reputation(file_hash: str) -> dict:
    """
    Получает репутационную информацию для файла по его хэшу (SHA-256) через OTX.
    Endpoint: GET /api/v1/indicators/file/{indicator}/general

    Аргументы:
      file_hash: SHA-256 хэш файла.
    Возвращает:
      JSON-ответ с информацией о репутации файла.
    """
    endpoint = f"{OTX_BASE_URL}/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

# Пример использования:
if __name__ == "__main__":
    # Пример для URL (без протокола)
    test_url = "brevis.by"
    url_info = get_otx_url_reputation(test_url)
    print("URL Reputation:")
    print(json.dumps(url_info, indent=2, ensure_ascii=False))
    
    # Пример для файла (укажите валидный SHA-256, если есть)
    test_file_hash = "dbae2d0204aa489e234eb2f903a0127b17c712386428cab12b86c5f68aa75867"
    file_info = get_otx_file_reputation(test_file_hash)
    print("\nFile Reputation:")
    print(json.dumps(file_info, indent=2, ensure_ascii=False))
