from flask import Flask, render_template, request, jsonify, redirect, session, send_file
import sqlite3
import csv
import os
from predictor import detector

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_RANDOM_SECRET_123"

DB_PATH = "system.db"


# =========================
# DATABASE INIT
# =========================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            verdict TEXT,
            score REAL,
            ip TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    c.execute("INSERT OR IGNORE INTO settings VALUES ('phishing_threshold','0.75')")
    c.execute("INSERT OR IGNORE INTO settings VALUES ('suspicious_threshold','0.50')")

    conn.commit()
    conn.close()


init_db()


# =========================
# DB HELPER
# =========================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_settings():
    conn = db()
    rows = conn.execute("SELECT * FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


# =========================
# LOGIN SYSTEM
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == "admin123":
            session["admin"] = True
            return redirect("/admin")
        return render_template("login.html", error="Invalid password")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# ADMIN PAGE (PROTECTED)
# =========================
@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect("/login")

    conn = db()
    history = conn.execute("SELECT * FROM history ORDER BY id DESC LIMIT 100").fetchall()
    whitelist = conn.execute("SELECT * FROM whitelist").fetchall()
    conn.close()

    return render_template(
        "admin.html",
        history=history,
        whitelist=whitelist,
        settings=get_settings()
    )


# =========================
# SCAN PAGE
# =========================
@app.route("/")
def home():
    return redirect("/scan")


@app.route("/scan")
def scan():
    return render_template("scan.html")


# =========================
# DETECT API (SCAN)
# =========================
@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json()
    url = data.get("url", "")

    result = detector.detect_url(url)

    conn = db()
    conn.execute(
        "INSERT INTO history (target, verdict, score, ip) VALUES (?, ?, ?, ?)",
        (url, result["verdict"], result["score"], request.remote_addr)
    )
    conn.commit()
    conn.close()

    return jsonify(result)


# =========================
# HISTORY API (DASHBOARD LIVE)
# =========================
@app.route("/api/history")
def history_api():
    conn = db()
    rows = conn.execute("SELECT * FROM history ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


# =========================
# SETTINGS UPDATE
# =========================
@app.route("/settings", methods=["POST"])
def settings():
    if not session.get("admin"):
        return redirect("/login")

    phishing = request.form.get("phishing_threshold")
    suspicious = request.form.get("suspicious_threshold")

    conn = db()
    conn.execute("UPDATE settings SET value=? WHERE key='phishing_threshold'", (phishing,))
    conn.execute("UPDATE settings SET value=? WHERE key='suspicious_threshold'", (suspicious,))
    conn.commit()
    conn.close()

    return redirect("/admin")


# =========================
# WHITELIST ADD
# =========================
@app.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    if not session.get("admin"):
        return redirect("/login")

    domain = request.form.get("domain")

    conn = db()
    try:
        conn.execute("INSERT INTO whitelist (domain) VALUES (?)", (domain,))
        conn.commit()
    except:
        pass
    conn.close()

    return redirect("/admin")


# =========================
# WHITELIST DELETE
# =========================
@app.route("/whitelist/delete/<domain>")
def whitelist_delete(domain):
    
    if not session.get("admin"):
        return redirect("/login")

    conn = db()
    conn.execute("DELETE FROM whitelist WHERE domain=?", (domain,))
    conn.commit()
    conn.close()

    return redirect("/admin")


# =========================
# CSV EXPORT (FIXED)
# =========================
@app.route("/export/csv")
def export_csv():
    if not session.get("admin"):
        return redirect("/login")

    conn = db()
    rows = conn.execute("SELECT * FROM history").fetchall()
    conn.close()

    file_path = "history.csv"

    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "target", "verdict", "score", "ip", "date"])

        for r in rows:
            writer.writerow([r["id"], r["target"], r["verdict"], r["score"], r["ip"], r["date"]])

    return send_file(file_path, as_attachment=True)


# =========================
# RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)