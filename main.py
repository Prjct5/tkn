import hashlib, os, sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import jwt
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
DB_PATH    = os.getenv("DB_PATH", "./licenses.db")
ALGORITHM  = "HS256"

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST"])

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS licenses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash  TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            is_active   INTEGER DEFAULT 1,
            activated_at TEXT,
            notes       TEXT
        )""")
        db.commit()

init_db()

class ActivateRequest(BaseModel):
    token: str
    mac: str

@app.post("/activate")
@limiter.limit("5/minute")
async def activate(req: Request, body: ActivateRequest):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    mac = body.mac.upper().replace(":", "").replace("-", "")

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM licenses WHERE token_hash = ?", (token_hash,)
        ).fetchone()

    if not row or not row["is_active"]:
        raise HTTPException(403, "Invalid or inactive token")

    if row["mac_address"] and row["mac_address"] != mac:
        raise HTTPException(403, "Token is bound to a different device")

    if not row["mac_address"]:
        with get_db() as db:
            db.execute(
                "UPDATE licenses SET mac_address=?, activated_at=? WHERE token_hash=?",
                (mac, datetime.utcnow().isoformat(), token_hash)
            )
            db.commit()

    payload = {
        "mac": mac,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    token_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"session": token_jwt}

@app.get("/health")
def health():
    return {"status": "ok"}
