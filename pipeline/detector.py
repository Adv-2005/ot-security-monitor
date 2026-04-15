"""
pipeline/detector.py
────────────────────
Loads trained models and runs inference on feature vectors.
Feature name lists are loaded from .pkl so they stay in sync
with whatever bootstrap_train.py (or real training) produced.
"""

import numpy as np
import joblib
import os


class ProcessDetector:
    """Isolation Forest over BATADAL-style sensor feature vectors."""

    def __init__(self, model_dir: str = "models"):
        self.model   = joblib.load(os.path.join(model_dir, "isolation_forest.pkl"))
        self.scaler  = joblib.load(os.path.join(model_dir, "process_scaler.pkl"))
        self.features = joblib.load(os.path.join(model_dir, "process_feature_names.pkl"))

    def score(self, feature_vec: np.ndarray) -> dict:
        """
        feature_vec: 1-D numpy array aligned to self.features.
        Returns:
            score    – anomaly score (higher = more anomalous)
            anomaly  – bool
            severity – LOW / MEDIUM / HIGH / CRITICAL
        """
        X  = self.scaler.transform([feature_vec])
        raw_score  = float(-self.model.score_samples(X)[0])
        is_anomaly = bool(self.model.predict(X)[0] == -1)
        return {
            "score":    raw_score,
            "anomaly":  is_anomaly,
            "severity": self._severity(raw_score),
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score < 0.30: return "LOW"
        if score < 0.50: return "MEDIUM"
        if score < 0.65: return "HIGH"
        return "CRITICAL"


class NetworkDetector:
    """One-Class SVM over TON_IoT-style network flow feature vectors."""

    EXPECTED_FEATURES = [
        "duration", "orig_bytes", "resp_bytes", "orig_pkts",
        "resp_pkts", "missed_bytes", "proto", "conn_state",
    ]

    def __init__(self, model_dir: str = "models"):
        self.model    = joblib.load(os.path.join(model_dir, "ocsvm.pkl"))
        self.scaler   = joblib.load(os.path.join(model_dir, "network_scaler.pkl"))
        self.features = joblib.load(os.path.join(model_dir, "network_feature_names.pkl"))

    def score(self, feature_vec: np.ndarray) -> dict:
        """
        feature_vec: 1-D numpy array aligned to self.features.
        Returns:
            score    – anomaly score (higher = more anomalous)
            anomaly  – bool
            severity – LOW / MEDIUM / HIGH / CRITICAL
        """
        X  = self.scaler.transform([feature_vec])
        raw_score  = float(-self.model.decision_function(X)[0])
        is_anomaly = bool(self.model.predict(X)[0] == -1)
        return {
            "score":    raw_score,
            "anomaly":  is_anomaly,
            "severity": self._severity(raw_score),
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score < 0.20: return "LOW"
        if score < 0.40: return "MEDIUM"
        if score < 0.60: return "HIGH"
        return "CRITICAL"

    def score_from_zeek_record(self, record: dict) -> dict:
        """
        Convenience wrapper: extract features directly from a parsed
        Zeek conn.log dict (keys use Zeek field names).
        """
        PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}
        STATE_MAP = {
            "S0":1, "S1":2, "SF":0, "REJ":3, "S2":4, "S3":5,
            "RSTO":6, "RSTR":7, "RSTOS0":8, "RSTRH":9,
            "SH":10, "SHR":11, "OTH":12,
        }

        def safe_float(v, default=0.0):
            try: return float(v)
            except (TypeError, ValueError): return default

        vec = np.array([
            safe_float(record.get("duration")),
            safe_float(record.get("orig_bytes")),
            safe_float(record.get("resp_bytes")),
            safe_float(record.get("orig_pkts")),
            safe_float(record.get("resp_pkts")),
            safe_float(record.get("missed_bytes")),
            float(PROTO_MAP.get(str(record.get("proto", "")).lower(), 6)),
            float(STATE_MAP.get(str(record.get("conn_state", "OTH")), 12)),
        ], dtype=float)

        return self.score(vec)