import os
import re
import math
import pickle
import numpy as np
import sqlite3
from urllib.parse import urlparse
from difflib import SequenceMatcher

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV

# =========================
# CONFIG
# =========================
DB_PATH = "system.db"
MODEL_PATH = "models/model.pkl"
SCALER_PATH = "models/scaler.pkl"

TRUSTED_DOMAINS = {
    "google.com", "facebook.com", "paypal.com",
    "microsoft.com", "apple.com", "amazon.com",
    "github.com", "cloudflare.com"
}

RISKY_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".icu", ".click")

PHISH_WORDS = (
    "login", "verify", "secure", "update",
    "account", "password", "bank", "signin",
    "wallet", "confirm", "unlock", "support"
)


# =========================
# SAFE LOAD
# =========================
def safe_load(path):
    try:
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return pickle.load(f)
    except:
        return None


# =========================
# ENTROPY ENGINE
# =========================
def entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


# =========================
# FEATURE ENGINE (STABLE 17)
# =========================
def extract_features(url: str):
    if not url:
        url = ""

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    p = urlparse(url)
    domain = (p.netloc or "").lower()
    path = p.path or ""
    full = url.lower()

    trusted_sim = 0.0
    if domain and TRUSTED_DOMAINS:
        trusted_sim = max(
            SequenceMatcher(None, domain, d).ratio()
            for d in TRUSTED_DOMAINS
        )

    return np.array([
        len(url),
        len(domain),
        domain.count("."),
        domain.count("-"),
        domain.count("_"),
        full.count("@"),
        full.count("?"),
        full.count("="),
        int(any(c.isdigit() for c in domain)),
        int(p.scheme == "https"),
        sum(w in full for w in PHISH_WORDS),
        int(domain.endswith(RISKY_TLDS)),
        entropy(domain),
        trusted_sim,
        int(len(url) > 75),
        len(path.split("/")),
        int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)))
    ]).reshape(1, -1)


# =========================
# TRAINING (ENTERPRISE SAFE)
# =========================
def train_model():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT target, verdict FROM history").fetchall()
    conn.close()

    if len(rows) < 50:
        X = np.random.rand(500, 17)
        y = np.random.randint(0, 3, 500)
    else:
        X = np.array([extract_features(r[0])[0] for r in rows])
        y = np.array([
            2 if r[1] == "phishing"
            else 1 if r[1] == "suspicious"
            else 0
            for r in rows
        ])

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    base = RandomForestClassifier(
        n_estimators=400,
        max_depth=25,
        random_state=42,
        class_weight="balanced"
    )

    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(X, y)

    os.makedirs("models", exist_ok=True)
    pickle.dump(model, open(MODEL_PATH, "wb"))
    pickle.dump(scaler, open(SCALER_PATH, "wb"))

    return model, scaler


# =========================
# ENTERPRISE DETECTOR
# =========================
class Detector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.class_map = {}
        self.load()

    def load(self):
        self.model = safe_load(MODEL_PATH)
        self.scaler = safe_load(SCALER_PATH)

        if self.model is None or self.scaler is None:
            self.model, self.scaler = train_model()

        self.class_map = {c: i for i, c in enumerate(self.model.classes_)}

    # =========================
    # ENTERPRISE RULE ENGINE
    # =========================
    def rule_engine(self, url, domain, url_lower):
        score = 0.0

        if "@" in url:
            score += 0.35
        if domain.count(".") > 4:
            score += 0.25
        if any(x in url_lower for x in PHISH_WORDS):
            score += 0.25
        if any(domain.endswith(t) for t in RISKY_TLDS):
            score += 0.30
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            score += 0.40

        return min(score, 1.0)

    # =========================
    # MAIN DETECTION
    # =========================
    def detect_url(self, url, ip=None):
        try:
            if not url:
                return self._response(url, 0, "safe", 0, 0, 0, "empty")

            # =========================
            # WHITELIST FIRST (FAST EXIT)
            # =========================
            conn = sqlite3.connect(DB_PATH)
            wl = conn.execute("SELECT domain FROM whitelist").fetchall()
            conn.close()

            domain = (urlparse(url).netloc or "").lower()
            url_lower = url.lower()

            if any(domain.endswith(w[0]) for w in wl):
                return self._response(url, 5, "safe", 1, 0, 0, "whitelisted")

            # =========================
            # ML PREDICTION
            # =========================
            X = extract_features(url)
            X = self.scaler.transform(X)

            proba = self.model.predict_proba(X)[0]

            safe = proba[self.class_map.get(0, 0)]
            susp = proba[self.class_map.get(1, 1)]
            phish = proba[self.class_map.get(2, 2)]

            # =========================
            # RULE ENGINE
            # =========================
            rule_score = self.rule_engine(url, domain, url_lower)

            # =========================
            # TRUST SIMILARITY
            # =========================
            trust_score = 0.0
            if TRUSTED_DOMAINS:
                trust_score = max(
                    SequenceMatcher(None, domain, d).ratio()
                    for d in TRUSTED_DOMAINS
                )
                if 0.80 < trust_score < 1.0:
                    rule_score += 0.6

            # =========================
            # FINAL FUSION MODEL
            # =========================
            ml_risk = (phish * 0.8) + (susp * 0.2)

            final_score = (
                (ml_risk * 0.65) +
                (rule_score * 0.25) +
                (trust_score * 0.10)
            )

            final_score = float(np.clip(final_score, 0.01, 0.99))

            # =========================
            # ENTERPRISE VERDICT
            # =========================
            if final_score < 0.25:
                verdict = "safe"
            elif final_score < 0.45:
                verdict = "low_risk"
            elif final_score < 0.70:
                verdict = "suspicious"
            else:
                verdict = "phishing"

            return self._response(
                url,
                final_score * 100,
                verdict,
                safe,
                susp,
                phish,
                "ok"
            )

        except Exception as e:
            return self._response(url, 0, "safe", 0, 0, 0, str(e), "error")

    # =========================
    # API RESPONSE FORMAT
    # =========================
    def _response(self, url, score, verdict, safe, susp, phish, message, status="ok"):
        return {
            "url": url,
            "score": round(score, 2),
            "verdict": verdict,

            "ensemble_score": f"{round(score, 2)}%",

            "safe_prob": round(safe, 4),
            "suspicious_prob": round(susp, 4),
            "phishing_prob": round(phish, 4),

            "threat_level":
                "High Critical" if verdict == "phishing"
                else "Medium Warning" if verdict == "suspicious"
                else "Low Risk",

            "recommendation":
                "Avoid entering sensitive data"
                if verdict != "safe"
                else "Safe to proceed",

            "status": status,
            "message": message
        }


# =========================
# GLOBAL INSTANCE
# =========================
detector = Detector()