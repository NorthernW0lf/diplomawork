import sqlite3

DB_PATH = "database/cybersecurity.db"

def check_threats(indicator):
    """Проверяем, есть ли угроза в базе данных."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT description, threat_level FROM threats WHERE indicator = ?", (indicator,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return f"⚠️ *Обнаружена угроза!*\n🔹 {result[0]}\n🚨 Уровень: *{result[1]}*"
    else:
        return None
