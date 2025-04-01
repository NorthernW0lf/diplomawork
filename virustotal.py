import logging
import json
import asyncio
import requests

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Your VirusTotal API key (replace with your actual key or use environment variables)
VT_API_KEY = "9a59a403e9dd240205d61b4d050569d1dbc3831601d403932ab09738cff04f0e"

# VirusTotal endpoints
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSES_URL_TEMPLATE = "https://www.virustotal.com/api/v3/analyses/{}"

async def poll_analysis(analysis_id: str, headers: dict, max_attempts: int = 100, delay: int = 5) -> dict:
    """
    Polls the analysis status until completion or until max_attempts is reached.
    """
    status_url = VT_ANALYSES_URL_TEMPLATE.format(analysis_id)
    for attempt in range(max_attempts):
        response = await asyncio.to_thread(requests.get, status_url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            status_text = json_response.get("data", {}).get("attributes", {}).get("status", "")
            if status_text.lower() == "completed":
                logger.info(f"✅ Analysis {analysis_id} completed.")
                return json_response
            else:
                logger.info(f"⚠️ Analysis {analysis_id} not completed (status: {status_text}). Attempt {attempt}/{max_attempts}.")
        else:
            logger.error(f"❌ Error getting analysis {analysis_id}: {response.status_code}")
        await asyncio.sleep(delay)
    return None

async def vt_scan_file(file_bytes: bytes, file_name: str) -> str:
    """
    Submits a file to VirusTotal for scanning and returns the full JSON report as a string.
    """
    headers = {"x-apikey": VT_API_KEY}
    files = {"file": (file_name, file_bytes)}
    response = await asyncio.to_thread(requests.post, VT_FILE_SCAN_URL, headers=headers, files=files)
    if response.status_code in (200, 202):
        json_response = response.json()
        analysis_id = json_response.get("data", {}).get("id")
        if analysis_id:
            result = await poll_analysis(analysis_id, headers)
            if result:
                return json.dumps(result, indent=2, ensure_ascii=False)
            else:
                return f"Analysis not completed. Please check status later with analysis ID {analysis_id}"
        else:
            return "Error: Analysis ID not received."
    else:
        return f"Error scanning file: {response.status_code}, {response.text}"

async def vt_scan_url(url: str) -> str:
    """
    1) Submits the URL for analysis using POST /urls.
    2) Retrieves the analysis_id from the response.
    3) Polls for analysis completion.
    4) Returns the final JSON report as a formatted string.
    """
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    
    # Step 1: Submit URL for analysis
    response = await asyncio.to_thread(requests.post, VT_URL_SCAN_URL, headers=headers, data=data)
    
    if response.status_code in (200, 202):
        json_response = response.json()
        analysis_id = json_response.get("data", {}).get("id")
        if analysis_id:
            # Step 2: Poll for analysis completion
            result = await poll_analysis(analysis_id, headers)
            if result:
                return json.dumps(result, indent=2, ensure_ascii=False)
            else:
                return f"Analysis not completed. Please check status later with analysis ID {analysis_id}"
        else:
            return "Error: Analysis ID not received."
    else:
        return f"Error scanning URL: {response.status_code}, {response.text}"
