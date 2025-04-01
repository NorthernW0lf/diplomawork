import json

def process_full_report(full_report_str: str) -> str:
    
    try:
        report = json.loads(full_report_str)
    except Exception:
        return "❌ Error parsing full report."
    
    data = report.get("data", {})
    report_id = data.get("id", "N/A")
    attributes = data.get("attributes", {})
    stats = attributes.get("stats", {})
    status = attributes.get("status", "unknown")
    sha256 = attributes.get("sha256", "N/A")
    
    summary = "🔍 **Full Report Summary:**\n"
    summary += f"🆔 **ID:** {report_id}\n"
    summary += f"📊 **Status:** {status}\n"
    summary += f"🔑 **SHA-256:** `{sha256}`\n\n"
    summary += "📈 **Stats:**\n"
    summary += f"  • 🚨 **Malicious:** {stats.get('malicious', 0)}\n"
    summary += f"  • ⚠️ **Suspicious:** {stats.get('suspicious', 0)}\n"
    summary += f"  • ❓ **Undetected:** {stats.get('undetected', 0)}\n"
    summary += f"  • ✅ **Harmless:** {stats.get('harmless', 0)}\n\n"
    
   
    return summary
