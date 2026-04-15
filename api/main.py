"""
api/main.py
────────────
FastAPI backend serving alert and traffic data from SQLite.
Start with:  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sqlite3
from pathlib import Path
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

DB_PATH = os.environ.get("OT_DB", "data/alerts.db")

app = FastAPI(title="OT Security Monitor", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# Serve dashboard at /
dashboard_dir = Path(__file__).parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(dashboard_dir), html=True), name="ui")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(100, le=500),
    severity: str = Query(None),
    offset: int = 0,
):
    q = "SELECT * FROM alerts"
    params = []
    if severity:
        q += " WHERE severity = ?"
        params.append(severity.upper())
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = db().execute(q, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/stats")
def get_stats():
    con = db()
    total    = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical = con.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    high     = con.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    medium   = con.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0]
    low      = con.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0]

    by_type  = con.execute(
        "SELECT anomaly_type, COUNT(*) AS c FROM alerts GROUP BY anomaly_type ORDER BY c DESC"
    ).fetchall()
    by_port  = con.execute(
        "SELECT dst_port, COUNT(*) AS c FROM alerts GROUP BY dst_port ORDER BY c DESC LIMIT 8"
    ).fetchall()

    flows    = con.execute("SELECT COUNT(*) FROM conn_events").fetchone()[0]
    recent   = con.execute(
        "SELECT ts FROM alerts ORDER BY id DESC LIMIT 1"
    ).fetchone()

    return {
        "total_alerts":  total,
        "total_flows":   flows,
        "by_severity":   {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
        "by_type":       {r[0]: r[1] for r in by_type},
        "by_port":       {str(r[0]): r[1] for r in by_port},
        "last_alert_ts": recent[0] if recent else None,
    }


@app.get("/api/conn_events")
def get_conn_events(limit: int = Query(200, le=1000)):
    rows = db().execute(
        "SELECT * FROM conn_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/health")
def health():
    return {"status": "ok", "db": DB_PATH}