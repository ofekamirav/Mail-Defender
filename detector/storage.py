from __future__ import annotations

import csv
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import Optional

from pathlib import Path
import pandas as pd

from .config import CSV_PATH, DATA_DIR

_CSV_LOCK = Lock()
_EVENTS_LOCK = Lock()

EVENTS_CSV_PATH = Path(DATA_DIR) / "events.csv"

CSV_COLUMNS = [
    "id",
    "fingerprint",
    "scan_count",
    "first_seen_at",
    "last_seen_at",
    "labeled_at",
    "label_source",
    "subject",
    "body",
    "sender",
    "label",
    "source",
    "ml_score",
    "rule_score",
    "final_score",
]

EVENT_COLUMNS = ["event_type", "timestamp", "email_id", "payload_summary"]


@dataclass(frozen=True)
class UpsertResult:
    email_id: str
    already_seen: bool
    already_labeled: bool
    label_source: str
    scan_count: int
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True)
class UpdateLabelResult:
    success: bool
    newly_labeled: bool
    previous_label: Optional[int]


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ensure_data_dir_exists() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def ensure_csv_exists(path: Optional[str | object] = None) -> None:
    ensure_data_dir_exists()
    csv_path = CSV_PATH if path is None else path
    csv_path = str(csv_path)

    with _CSV_LOCK:
        if not pd.io.common.file_exists(csv_path):
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()


def ensure_events_csv_exists() -> None:
    ensure_data_dir_exists()
    with _EVENTS_LOCK:
        if not EVENTS_CSV_PATH.exists():
            with open(str(EVENTS_CSV_PATH), "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
                writer.writeheader()


def append_event(event_type: str, email_id: str, payload_summary: str) -> None:
    ensure_events_csv_exists()
    row = {
        "event_type": event_type,
        "timestamp": _utc_now_iso(),
        "email_id": email_id,
        "payload_summary": (payload_summary or "")[:500],
    }
    with _EVENTS_LOCK:
        with open(str(EVENTS_CSV_PATH), "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
            writer.writerow(row)


def _safe_read_csv(csv_path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(csv_path)
    except pd.errors.EmptyDataError:
        df = pd.DataFrame()

    if df.empty:
        return pd.DataFrame(columns=CSV_COLUMNS)

    for col in CSV_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    return df[CSV_COLUMNS]


def _compute_fingerprint(subject: str, body: str, sender: str) -> str:
    norm = (subject or "").strip() + "\n" + (body or "").strip() + "\n" + (sender or "").strip()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _label_to_int_or_none(value) -> Optional[int]:
    x = pd.to_numeric(value, errors="coerce")
    if pd.isna(x):
        return None
    xi = int(x)
    if xi in (0, 1):
        return xi
    return None


def _parse_scan_count(value) -> int:
    x = pd.to_numeric(value, errors="coerce")
    if pd.isna(x):
        return 1
    try:
        xi = int(x)
        return xi if xi >= 1 else 1
    except Exception:
        return 1


def upsert_scan_record(
    subject: str,
    body: str,
    sender: str,
    source: str,
    ml_score: float,
    rule_score: float,
    final_score: float,
    predicted_label: str,
    csv_path: Optional[str] = None,
) -> UpsertResult:
    ensure_csv_exists(csv_path)
    path = str(CSV_PATH if csv_path is None else csv_path)

    now = _utc_now_iso()
    fingerprint = _compute_fingerprint(subject, body, sender)

    with _CSV_LOCK:
        df = _safe_read_csv(path)

        mask = df["fingerprint"].astype(str) == fingerprint
        if mask.any():
            row_idx = df.index[mask][0]
            email_id = str(df.loc[row_idx, "id"])
            first_seen_at = str(df.loc[row_idx, "first_seen_at"] or now)

            scan_count = _parse_scan_count(df.loc[row_idx, "scan_count"]) + 1

            df.loc[row_idx, "scan_count"] = scan_count
            df.loc[row_idx, "last_seen_at"] = now

            df.loc[row_idx, "ml_score"] = float(ml_score)
            df.loc[row_idx, "rule_score"] = float(rule_score)
            df.loc[row_idx, "final_score"] = float(final_score)

            existing_label_int = _label_to_int_or_none(df.loc[row_idx, "label"])
            already_labeled = existing_label_int is not None

            label_source = str(df.loc[row_idx, "label_source"] or "").strip()
            if already_labeled and label_source == "":
                label_source = "user_feedback"
                df.loc[row_idx, "label_source"] = label_source
            if not already_labeled and label_source == "":
                label_source = "model"

            df.to_csv(path, index=False)

            append_event(
                event_type="scan",
                email_id=email_id,
                payload_summary=f"seen_before=1 predicted={predicted_label} score={float(final_score):.3f}",
            )

            return UpsertResult(
                email_id=email_id,
                already_seen=True,
                already_labeled=already_labeled,
                label_source=label_source or "model",
                scan_count=int(scan_count),
                first_seen_at=first_seen_at,
                last_seen_at=now,
            )

        email_id = str(uuid.uuid4())
        row = {
            "id": email_id,
            "fingerprint": fingerprint,
            "scan_count": 1,
            "first_seen_at": now,
            "last_seen_at": now,
            "labeled_at": "",
            "label_source": "model",
            "subject": subject,
            "body": body,
            "sender": sender,
            "label": "",
            "source": source,
            "ml_score": float(ml_score),
            "rule_score": float(rule_score),
            "final_score": float(final_score),
        }

        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        df.to_csv(path, index=False)

    append_event(
        event_type="scan",
        email_id=email_id,
        payload_summary=f"seen_before=0 predicted={predicted_label} score={float(final_score):.3f}",
    )

    return UpsertResult(
        email_id=email_id,
        already_seen=False,
        already_labeled=False,
        label_source="model",
        scan_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )


def update_label(email_id: str, true_label: int, csv_path: Optional[str] = None, label_source: str = "user_feedback") -> bool:
    ensure_csv_exists(csv_path)
    path = str(CSV_PATH if csv_path is None else csv_path)
    now = _utc_now_iso()

    with _CSV_LOCK:
        df = _safe_read_csv(path)

        mask = df["id"].astype(str) == str(email_id)
        if not mask.any():
            return UpdateLabelResult(success=False, newly_labeled=False, previous_label=None)

        current_value = df.loc[mask, "label"].iloc[0]
        prev_label_int = _label_to_int_or_none(current_value)
        newly_labeled = prev_label_int is None

        df.loc[mask, "label"] = int(true_label)
        df.loc[mask, "label_source"] = label_source
        df.loc[mask, "labeled_at"] = now
        df.to_csv(path, index=False)

    append_event(
        event_type="feedback",
        email_id=str(email_id),
        payload_summary=f"prev={prev_label_int} new={int(true_label)} newly_labeled={1 if newly_labeled else 0}",
    )

    return UpdateLabelResult(success=True, newly_labeled=newly_labeled, previous_label=prev_label_int)


def load_dataset(csv_path: Optional[str] = None) -> pd.DataFrame:
    ensure_csv_exists(csv_path)
    path = str(CSV_PATH if csv_path is None else csv_path)
    with _CSV_LOCK:
        return _safe_read_csv(path)
