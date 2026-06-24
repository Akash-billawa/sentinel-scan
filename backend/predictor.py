"""Advanced Machine-Learning attack prediction engine.

Forecasts:
1. Likelihood of follow-up scans/escalation within 10 minutes.
2. Next target ports most likely to be scanned.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier
    _HAS_ML = True
except ImportError:
    _HAS_ML = False

from . import database as db
from .config import get_settings

log = logging.getLogger("sentinelscan.predictor")

# Global ML model states
_model_lock = threading.Lock()
_trained_classifier: Optional[DecisionTreeClassifier] = None
_port_association_matrix: Dict[int, Dict[int, int]] = {}  # port_a -> {port_b -> co_occurrence_count}
_port_total_counts: Dict[int, int] = {}                  # port -> total_scanned_count
_last_train_time = 0.0
_TRAIN_COOLDOWN_SEC = 30.0  # Retrain at most once every 30 seconds


def train_models() -> None:
    """Query historical attacks, extract features and train classification and association models."""
    global _trained_classifier, _port_association_matrix, _port_total_counts, _last_train_time
    
    if not _HAS_ML:
        return

    now = time.time()
    with _model_lock:
        if now - _last_train_time < _TRAIN_COOLDOWN_SEC:
            return
        _last_train_time = now

    try:
        with db.session_scope() as sess:
            # Fetch all attacks ordered by start time
            from sqlalchemy import select
            attacks = list(sess.scalars(select(db.Attack).order_by(db.Attack.started_at)).all())

        if len(attacks) < 10:
            log.debug("Not enough attacks in database (%d/10) to train ML model. Using heuristics.", len(attacks))
            return

        # 1. Train Port Association Model (Item-based Collaborative Transition)
        new_association: Dict[int, Dict[int, int]] = {}
        new_totals: Dict[int, int] = {}

        for a in attacks:
            try:
                ports = json.loads(a.target_ports_json or "[]")
            except Exception:
                continue
            ports = [int(p) for p in ports if isinstance(p, (int, float))]
            if not ports:
                continue

            for p in ports:
                new_totals[p] = new_totals.get(p, 0) + 1

            for i, p_a in enumerate(ports):
                for p_b in ports[i + 1:]:
                    if p_a == p_b:
                        continue
                    if p_a not in new_association:
                        new_association[p_a] = {}
                    new_association[p_a][p_b] = new_association[p_a].get(p_b, 0) + 1

                    if p_b not in new_association:
                        new_association[p_b] = {}
                    new_association[p_b][p_a] = new_association[p_b].get(p_a, 0) + 1

        # 2. Build training set for Follow-up Classifier
        scan_types = [
            "port_scan", "host_sweep", "rate_anomaly", "ecn_probe",
            "syn_scan", "connect_scan", "fin_scan", "xmas_scan",
            "null_scan", "udp_scan", "ping_sweep"
        ]
        scan_type_map = {name: idx for idx, name in enumerate(scan_types)}

        tools = ["nmap", "zenmap", "masscan", "angry ip scanner", "custom"]
        tool_map = {name: idx for idx, name in enumerate(tools)}

        X = []
        y = []
        follow_up_window = 600.0  # 10 minutes

        for idx, a in enumerate(attacks):
            has_follow_up = 0
            for other in attacks[idx + 1:]:
                if other.source_ip == a.source_ip:
                    time_diff = (other.started_at - a.ended_at).total_seconds()
                    if 0 <= time_diff <= follow_up_window:
                        has_follow_up = 1
                        break
                    elif time_diff > follow_up_window:
                        break

            scan_type_val = scan_type_map.get((a.scan_type or "").lower(), len(scan_types))
            tool_val = tool_map.get((a.source_tool_guess or "").lower(), len(tools))

            feats = [
                float(a.risk_score or 0.0),
                float(a.packet_count or 0.0),
                float(a.unique_ports or 0.0),
                float(a.unique_targets or 0.0),
                float(a.duration_seconds or 0.0),
                float(scan_type_val),
                float(tool_val)
            ]
            X.append(feats)
            y.append(has_follow_up)

        X_arr = np.array(X)
        y_arr = np.array(y)

        # We must have both classes (0 and 1) to fit a binary classifier
        if len(np.unique(y_arr)) < 2:
            log.debug("Only one class represented in labels. Fallback to heuristics.")
            return

        clf = DecisionTreeClassifier(max_depth=3, random_state=42)
        clf.fit(X_arr, y_arr)

        with _model_lock:
            _trained_classifier = clf
            _port_association_matrix = new_association
            _port_total_counts = new_totals

        log.info("ML Predictor trained successfully on %d attack samples.", len(attacks))

    except Exception as e:
        log.exception("Error training ML Predictor: %s", e)


def predict_attack_behavior(attack: db.Attack) -> Dict:
    """Predict follow-up likelihood and next port targets for the given attack."""
    train_models()

    try:
        ports = json.loads(attack.target_ports_json or "[]")
    except Exception:
        ports = []
    ports = [int(p) for p in ports if isinstance(p, (int, float))]

    # 1. Predict Next Port Targets
    predicted_ports = []
    is_seq = False

    if len(ports) >= 5:
        sorted_ports = sorted(ports)
        diffs = [sorted_ports[i + 1] - sorted_ports[i] for i in range(len(sorted_ports) - 1)]
        # If the scan is sequential (interval of 1)
        if diffs.count(1) / len(diffs) > 0.7:
            is_seq = True
            max_port = max(ports)
            predicted_ports = [max_port + 1, max_port + 2, max_port + 3]
            predicted_ports = [p for p in predicted_ports if 1 <= p <= 65535]

    if not is_seq:
        with _model_lock:
            assoc = _port_association_matrix
            totals = _port_total_counts

        if assoc and ports:
            candidate_scores: Dict[int, float] = {}
            for current_p in ports:
                if current_p in assoc:
                    for other_p, co_count in assoc[current_p].items():
                        if other_p in ports:
                            continue
                        p_cond = co_count / max(totals.get(current_p, 1), 1)
                        candidate_scores[other_p] = candidate_scores.get(other_p, 0.0) + p_cond

            if candidate_scores:
                sorted_candidates = sorted(candidate_scores.items(), key=lambda x: -x[1])
                predicted_ports = [p for p, score in sorted_candidates[:3]]

    # Ensure we always recommend 3 ports, using common ports as fallback
    if len(predicted_ports) < 3:
        common_ports = [22, 80, 443, 8080, 3389, 3306, 21, 23, 53, 445]
        for cp in common_ports:
            if cp not in ports and cp not in predicted_ports:
                predicted_ports.append(cp)
                if len(predicted_ports) >= 3:
                    break

    # 2. Predict Follow-up Likelihood
    prob = 0.50
    explanation = "Moderate likelihood of follow-up scan."

    with _model_lock:
        clf = _trained_classifier

    if _HAS_ML and clf is not None:
        scan_types = [
            "port_scan", "host_sweep", "rate_anomaly", "ecn_probe",
            "syn_scan", "connect_scan", "fin_scan", "xmas_scan",
            "null_scan", "udp_scan", "ping_sweep"
        ]
        scan_type_map = {name: idx for idx, name in enumerate(scan_types)}
        tools = ["nmap", "zenmap", "masscan", "angry ip scanner", "custom"]
        tool_map = {name: idx for idx, name in enumerate(tools)}

        scan_type_val = scan_type_map.get((attack.scan_type or "").lower(), len(scan_types))
        tool_val = tool_map.get((attack.source_tool_guess or "").lower(), len(tools))

        feats = [
            float(attack.risk_score or 0.0),
            float(attack.packet_count or 0.0),
            float(attack.unique_ports or 0.0),
            float(attack.unique_targets or 0.0),
            float(attack.duration_seconds or 0.0),
            float(scan_type_val),
            float(tool_val)
        ]
        try:
            prob_arr = clf.predict_proba(np.array([feats]))[0]
            prob = float(prob_arr[1])
        except Exception as e:
            log.warning("Classifier prediction failed: %s", e)

    else:
        # Heuristic fallback if ML is unavailable or not trained yet
        score = attack.risk_score or 0.0
        st = (attack.scan_type or "").lower()
        if score >= 7.0 or any(t in st for t in ["syn", "xmas", "null", "fin"]):
            prob = 0.85
        elif score >= 4.0:
            prob = 0.50
        else:
            prob = 0.15

    # Narrative explanation
    if prob >= 0.70:
        explanation = f"High probability ({prob*100:.0f}%) of follow-up scans or infiltration. The scan signature patterns match aggressive reconnaissance profiling."
    elif prob >= 0.35:
        explanation = f"Moderate probability ({prob*100:.0f}%) of follow-up activity. Standard scanning patterns detected."
    else:
        explanation = f"Low probability ({prob*100:.0f}%) of follow-up scans. This appears to be an isolated or random probe."

    # ponytail: surface ML vs heuristic so the dashboard can render a badge
    # instead of trusting a heuristic fallback as if it were trained output.
    source = "heuristic"
    notes = ""
    if not _HAS_ML:
        notes = "sklearn/numpy not installed; using heuristic fallback"
    elif clf is None:
        notes = "model not yet trained (need >=10 attacks); using heuristic fallback"
    else:
        source = "ml"
        notes = f"trained classifier; last train attempted at {_last_train_iso()}"

    return {
        "predicted_next_ports": predicted_ports,
        "follow_up_probability": prob,
        "explanation": explanation,
        "source": source,
        "notes": notes,
    }


def _last_train_iso() -> str:
    """ISO timestamp of last train attempt (UTC). Empty if never."""
    if not _last_train_time:
        return ""
    return datetime.fromtimestamp(_last_train_time, tz=timezone.utc).isoformat()
