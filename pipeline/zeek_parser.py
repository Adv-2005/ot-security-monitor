"""
pipeline/zeek_parser.py
────────────────────────
Tails Zeek's conn.log in real time, extracts features from each flow,
runs the NetworkDetector, and writes anomalies to SQLite.

Usage:
    python pipeline/zeek_parser.py [--log /path/to/conn.log] [--db data/alerts.db]

Zeek must be running with:
    sudo /opt/zeek/bin/zeek -C -i any zeek_scripts/ics_monitor.zeek
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

# ── make repo root importable regardless of cwd ──────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.detector import NetworkDetector

# ── defaults ─────────────────────────────────────────────────────────
DEFAULT_LOG = Path("/home/advar/zeek-logs/conn.log")
DEFAULT_DB  = "data/alerts.db"
ZEEK_FIELDS = [
    "ts", "uid",
    "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p",
    "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto",
]

INTERESTING_PORTS = {502, 5020, 20000, 47808, 102, 44818}  # OT ports to highlight


def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT,
            src_ip       TEXT,
            src_port     INTEGER,
            dst_ip       TEXT,
            dst_port     INTEGER,
            proto        TEXT,
            conn_state   TEXT,
            anomaly_type TEXT,
            severity     TEXT,
            score        REAL,
            raw_uid      TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS conn_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT,
            src_ip     TEXT,
            dst_ip     TEXT,
            dst_port   INTEGER,
            proto      TEXT,
            duration   REAL,
            orig_bytes INTEGER,
            resp_bytes INTEGER,
            conn_state TEXT
        )
    """)
    con.commit()
    return con


def parse_zeek_line(line: str) -> dict | None:
    """Parse a single TSV conn.log line into a dict. Returns None for headers."""
    if line.startswith("#") or not line.strip():
        return None
    parts = line.split("\t")
    if len(parts) < len(ZEEK_FIELDS):
        return None
    rec = dict(zip(ZEEK_FIELDS, parts))
    # Zeek uses '-' for unset fields
    for k, v in rec.items():
        if v == "-":
            rec[k] = None
    return rec


def tail_file(path: Path):
    """Yield new lines appended to a log file (tail -f behaviour)."""
    try:
        fh = open(path)
    except FileNotFoundError:
        print(f"[!] Log not found: {path}. Waiting …", flush=True)
        while not path.exists():
            time.sleep(2)
        fh = open(path)

    fh.seek(0, 2)           # jump to end so we see only new events
    print(f"[✓] Tailing {path}", flush=True)

    while True:
        line = fh.readline()
        if not line:
            time.sleep(0.3)
            continue
        yield line.rstrip()


def classify_anomaly_type(rec: dict) -> str:
    """Heuristic labels based on dest port and conn_state."""
    dst_port = int(rec.get("id.resp_p") or 0)
    state    = rec.get("conn_state") or "OTH"

    if dst_port in INTERESTING_PORTS:
        return "ot_protocol_probe"
    if state in ("REJ", "RSTO", "RSTRH"):
        return "refused_connection"
    if state == "S0":
        return "syn_no_reply"
    return "network_anomaly"


def main(log_path: Path, db_path: str, model_dir: str):
    print("[*] Loading NetworkDetector …", flush=True)
    try:
        detector = NetworkDetector(model_dir=model_dir)
    except FileNotFoundError as e:
        print(f"\n[✗] Model not found: {e}")
        print("    Run first:  python bootstrap_train.py\n")
        sys.exit(1)

    con = init_db(db_path)
    print(f"[✓] Alert DB: {db_path}", flush=True)
    print("[*] Waiting for Zeek conn.log events …\n", flush=True)

    total = 0
    alerts = 0

    for line in tail_file(log_path):
        rec = parse_zeek_line(line)
        if rec is None:
            continue

        total += 1

        # Log every connection to conn_events
        try:
            con.execute("""
                INSERT INTO conn_events
                (ts, src_ip, dst_ip, dst_port, proto, duration, orig_bytes, resp_bytes, conn_state)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                rec.get("ts"),
                rec.get("id.orig_h"),
                rec.get("id.resp_h"),
                int(rec.get("id.resp_p") or 0),
                rec.get("proto"),
                float(rec.get("duration") or 0),
                int(rec.get("orig_bytes") or 0),
                int(rec.get("resp_bytes") or 0),
                rec.get("conn_state"),
            ))
        except Exception:
            pass

        # Run detector
        result = detector.score_from_zeek_record({
            "duration":    rec.get("duration"),
            "orig_bytes":  rec.get("orig_bytes"),
            "resp_bytes":  rec.get("resp_bytes"),
            "orig_pkts":   rec.get("orig_pkts"),
            "resp_pkts":   rec.get("resp_pkts"),
            "missed_bytes": rec.get("missed_bytes"),
            "proto":       rec.get("proto"),
            "conn_state":  rec.get("conn_state"),
        })

        # Force-flag OT protocol connections as at least LOW
        dst_port = int(rec.get("id.resp_p") or 0)
        if dst_port in INTERESTING_PORTS and not result["anomaly"]:
            result["anomaly"]  = True
            result["severity"] = "LOW"

        if result["anomaly"]:
            alerts += 1
            atype = classify_anomaly_type(rec)
            con.execute("""
                INSERT INTO alerts
                (ts, src_ip, src_port, dst_ip, dst_port, proto,
                 conn_state, anomaly_type, severity, score, raw_uid)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                rec.get("ts"),
                rec.get("id.orig_h"), int(rec.get("id.orig_p") or 0),
                rec.get("id.resp_h"), dst_port,
                rec.get("proto"),
                rec.get("conn_state"),
                atype,
                result["severity"],
                round(result["score"], 4),
                rec.get("uid"),
            ))
            con.commit()

            print(
                f"[ALERT] {result['severity']:8s} | "
                f"{rec.get('id.orig_h')}:{rec.get('id.orig_p')} → "
                f"{rec.get('id.resp_h')}:{dst_port} "
                f"({rec.get('proto')}) | {atype} | score={result['score']:.3f}",
                flush=True
            )

        if total % 50 == 0:
            print(f"  … {total} flows processed, {alerts} alerts so far", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zeek conn.log → ML anomaly detector")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to Zeek conn.log (default: /opt/zeek/logs/current/conn.log)")
    parser.add_argument("--db",  default=DEFAULT_DB,
                        help="Path to SQLite alert DB (default: data/alerts.db)")
    parser.add_argument("--models", default="models",
                        help="Directory containing trained .pkl files")
    args = parser.parse_args()

    main(Path(args.log), args.db, args.models)