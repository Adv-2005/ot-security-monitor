"""
api/main.py  —  OT Security Monitor backend
Start with:  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
Dashboard:   http://localhost:8000
"""

import os
import sqlite3
from pathlib import Path
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

DB_PATH       = os.environ.get("OT_DB", "data/alerts.db")
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"

app = FastAPI(title="OT Security Monitor", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ── Serve dashboard HTML at root ────────────────────────────────────
@app.get("/", response_class=FileResponse, include_in_schema=False)
def serve_dashboard():
    index = DASHBOARD_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index), media_type="text/html")
    return HTMLResponse("<h2>Dashboard not found. Place dashboard/index.html.</h2>", status_code=404)


# ── SQLite helper ────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# ── Alerts ───────────────────────────────────────────────────────────
@app.get("/api/alerts")
def get_alerts(
    limit:    int = Query(150, le=1000),
    severity: str = Query(None),
    offset:   int = Query(0),
):
    try:
        con    = get_db()
        q      = "SELECT * FROM alerts"
        params = []
        if severity:
            q     += " WHERE severity = ?"
            params.append(severity.upper())
        q     += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows   = con.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        return {"error": str(e), "rows": []}


# ── Stats ────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    try:
        con = get_db()

        def one(q, *p):
            return con.execute(q, p).fetchone()[0]

        total    = one("SELECT COUNT(*) FROM alerts")
        critical = one("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
        high     = one("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
        medium   = one("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'")
        low      = one("SELECT COUNT(*) FROM alerts WHERE severity='LOW'")
        flows    = one("SELECT COUNT(*) FROM conn_events")

        by_type = con.execute(
            "SELECT anomaly_type, COUNT(*) c FROM alerts GROUP BY anomaly_type ORDER BY c DESC"
        ).fetchall()
        by_port = con.execute(
            "SELECT dst_port, COUNT(*) c FROM alerts WHERE dst_port IS NOT NULL "
            "GROUP BY dst_port ORDER BY c DESC LIMIT 10"
        ).fetchall()
        last_ts = con.execute(
            "SELECT ts FROM alerts ORDER BY id DESC LIMIT 1"
        ).fetchone()

        return {
            "total_alerts":  total,
            "total_flows":   flows,
            "by_severity":   {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
            "by_type":       {r[0]: r[1] for r in by_type},
            "by_port":       {str(r[0]): r[1] for r in by_port},
            "last_alert_ts": last_ts[0] if last_ts else None,
        }
    except Exception as e:
        return {"error": str(e)}


# ── Connection events ─────────────────────────────────────────────────
@app.get("/api/conn_events")
def get_conn_events(limit: int = Query(200, le=1000)):
    try:
        con  = get_db()
        rows = con.execute(
            "SELECT * FROM conn_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        return {"error": str(e), "rows": []}


# ── Health ────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    try:
        con   = get_db()
        total = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        flows = con.execute("SELECT COUNT(*) FROM conn_events").fetchone()[0]
        return {"status": "ok", "db": DB_PATH, "alerts": total, "flows": flows}
    except Exception as e:
        return {"status": "error", "detail": str(e)}