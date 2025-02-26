import sqlite3
import pandas as pd

DB_PATH = "database/cybersecurity.db"
CSV_PATH = "data/cyber_threats.csv"

def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY,
            indicator TEXT UNIQUE,
            description TEXT,
            threat_level TEXT
        )
    ''')

    df = pd.read_csv(CSV_PATH)
    df.to_sql("threats", conn, if_exists="replace", index=False)

    conn.commit()
    conn.close()

    print("✅ База данных успешно создана!")

if __name__ == "__main__":
    initialize_database()
