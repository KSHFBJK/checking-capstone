import sqlite3

DB_PATH = "system.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # =========================
    # HISTORY TABLE (FIXED)
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score REAL DEFAULT 0,
            ip TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =========================
    # WHITELIST TABLE (FIXED UNIQUE SAFE)
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL
        )
    """)

    # =========================
    # SETTINGS TABLE (SAFE KEY-VALUE)
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cursor.execute("INSERT OR IGNORE INTO settings VALUES ('phishing_threshold', '0.70')")
    cursor.execute("INSERT OR IGNORE INTO settings VALUES ('suspicious_threshold', '0.40')")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("DB FIXED & SAFE READY")