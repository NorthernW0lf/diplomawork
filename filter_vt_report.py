import json

def filter_vt_report(json_report: str) -> str:
    """
    Filters the full VirusTotal JSON report to keep only key data:
    - 'stats': malicious, suspicious, undetected, harmless
    - 'status'
    - 'id'
    """
    try:
        report = json.loads(json_report)
    except Exception:
        return json_report  # Return original report if parsing fails

    filtered = {}
    data = report.get("data", {})
    attributes = data.get("attributes", {})

    filtered["id"] = data.get("id", "N/A")
    filtered["stats"] = attributes.get("stats", {})
    filtered["status"] = attributes.get("status", "unknown")

    return json.dumps(filtered, indent=2, ensure_ascii=False)
