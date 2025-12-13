from __future__ import annotations

import csv
import os
import uuid
from datetime import datetime
from threading import Lock
from typing import Optional

import pandas as pd

from .config import CSV_PATH, DATA_DIR

_CSV_LOCK = Lock()

CSV_COLUMNS = [
    "id", "timestamp", "subject", "body", "sender", 
    "label", "source", "ml_score", "rule_score", "final_score"
]

def ensure_data_dir_exists() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

def ensure_csv_exists(path: Optional[str] = None) -> None:
    ensure_data_dir_exists()
    csv_path = path or CSV_PATH
    
    with _CSV_LOCK:
        if not os.path.exists(csv_path):
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()

def append_email_record(
    subject: str, body: str, sender: str, source: str,
    ml_score: float, rule_score: float, final_score: float,
    label: Optional[int | str] = "",
    csv_path: Optional[str] = None,
) -> str:
    ensure_csv_exists(csv_path)
    csv_path = csv_path or CSV_PATH
    
    with _CSV_LOCK:
        try:
            df = pd.read_csv(csv_path)
            clean_subj = str(subject).strip()
            clean_body = str(body).strip()
            
        
            existing = df[
                (df['subject'].str.strip() == clean_subj) & 
                (df['body'].str.strip() == clean_body) &
                (df['sender'].str.strip() == str(sender).strip())
            ]
            
            if not existing.empty:
                print(f"[STORAGE] Duplicate email detected. Returning existing ID.")
                return str(existing.iloc[0]['id'])
                
        except Exception as e:
            print(f"[STORAGE] Warning reading CSV for duplicates: {e}")

        email_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        row = {
            "id": email_id,
            "timestamp": timestamp,
            "subject": subject,
            "body": body,
            "sender": sender,
            "label": label,
            "source": source,
            "ml_score": ml_score,
            "rule_score": rule_score,
            "final_score": final_score,
        }

        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(row)

    return email_id

def update_label(email_id: str, true_label: int, csv_path: Optional[str] = None) -> bool:
    ensure_csv_exists(csv_path)
    csv_path = csv_path or CSV_PATH

    with _CSV_LOCK:
        try:
            df = pd.read_csv(csv_path)
        except pd.errors.EmptyDataError:
            return False

        mask = df["id"] == email_id
        if not mask.any():
            return False

        df.loc[mask, "label"] = true_label
        df.to_csv(csv_path, index=False)
        return True

def load_dataset(csv_path: Optional[str] = None) -> pd.DataFrame:
    ensure_csv_exists(csv_path)
    csv_path = csv_path or CSV_PATH
    
    with _CSV_LOCK:
        try:
            return pd.read_csv(csv_path)
        except pd.errors.EmptyDataError:
            return pd.DataFrame(columns=CSV_COLUMNS)