import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://admin:secret@db:5432/shadow_ai"
)

# In-memory buffer if PostgreSQL is starting up or temporarily offline
FALLBACK_LOGS: List[Dict[str, Any]] = []


def get_conn():
    import psycopg2
    return psycopg2.connect(DATABASE_URL, connect_timeout=3)


def init_db():
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS incident_logs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ DEFAULT NOW(),
                        client_ip TEXT,
                        username TEXT,
                        action TEXT,
                        findings JSONB,
                        original_prompt TEXT,
                        forwarded_prompt TEXT,
                        response TEXT
                    );
                    ALTER TABLE incident_logs ADD COLUMN IF NOT EXISTS response TEXT;
                """)
    except Exception as e:
        print(f"[DB WARN] Database not yet ready ({e}), using in-memory log buffer.")


def log_incident(client_ip, user, action, findings, original_prompt, forwarded_prompt, response=None):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incident_logs
                        (client_ip, username, action, findings, original_prompt, forwarded_prompt, response)
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        client_ip,
                        user,
                        action,
                        json.dumps(findings),
                        original_prompt,
                        forwarded_prompt,
                        response,
                    ),
                )
                return
    except Exception as e:
        print(f"[DB WARN] Could not write to PostgreSQL ({e}). Storing in memory fallback.")

    FALLBACK_LOGS.insert(0, {
        "id": len(FALLBACK_LOGS) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "username": user,
        "action": action,
        "findings": findings,
        "original_prompt": original_prompt,
        "forwarded_prompt": forwarded_prompt,
        "response": response,
    })


def fetch_logs(limit: int = 500):
    try:
        from psycopg2.extras import RealDictCursor
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM incident_logs ORDER BY timestamp DESC LIMIT %s;",
                    (limit,),
                )
                rows = cur.fetchall()
                for row in rows:
                    if hasattr(row["timestamp"], "isoformat"):
                        row["timestamp"] = row["timestamp"].isoformat()
                return list(rows)
    except Exception as e:
        print(f"[DB WARN] Could not fetch from PostgreSQL ({e}). Returning fallback buffer.")
        return FALLBACK_LOGS[:limit]
