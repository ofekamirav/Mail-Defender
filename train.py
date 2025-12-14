import pandas as pd

from detector.storage import load_dataset, upsert_scan_record, update_label
from detector.model import MailPhishingModel
from detector.config import CSV_PATH


SEED_DATA = [
    {"subject": "Win a Lottery Now!", "body": "Click here to claim your prize urgent", "sender": "lottery@winner-lucky.xyz", "label": 1},
    {"subject": "Security Alert", "body": "Your account is compromised verify now", "sender": "security@paypa1.com", "label": 1},
    {"subject": "Meeting Updates", "body": "See you at 10:00 AM in the conference room", "sender": "boss@company.com", "label": 0},
    {"subject": "Lunch?", "body": "Do you want to grab pizza later?", "sender": "friend@gmail.com", "label": 0},
    {"subject": "Invoice 1023", "body": "Attached is the invoice for your recent purchase", "sender": "billing@amazon-support-fake.com", "label": 1},
    {"subject": "Project Plan", "body": "Here is the roadmap for Q4", "sender": "pm@upwind.io", "label": 0},
]


def count_labeled(df: pd.DataFrame) -> int:
    if df.empty or "label" not in df.columns:
        return 0
    label_num = pd.to_numeric(df["label"], errors="coerce")
    return int(label_num.isin([0, 1]).sum())


def has_both_classes(df: pd.DataFrame) -> bool:
    if df.empty or "label" not in df.columns:
        return False
    label_num = pd.to_numeric(df["label"], errors="coerce")
    vals = set(label_num[label_num.isin([0, 1])].astype(int).tolist())
    return 0 in vals and 1 in vals


def ensure_seed_data(min_labeled: int = 6) -> None:
    df = load_dataset(CSV_PATH)

    labeled = count_labeled(df)
    if labeled >= min_labeled and has_both_classes(df):
        print(f"[TRAIN] Found {labeled} labeled emails (both classes present). Skipping seed.")
        return

    print(f"[TRAIN] Not enough labeled data ({labeled}). Injecting SEED DATA...")

    for item in SEED_DATA:
        upsert = upsert_scan_record(
            subject=item["subject"],
            body=item["body"],
            sender=item["sender"],
            source="seed",
            ml_score=0.0,
            rule_score=0.0,
            final_score=0.0,
            predicted_label="seed",
            csv_path=CSV_PATH,
        )
        update_label(
            email_id=upsert.email_id,
            true_label=int(item["label"]),
            csv_path=CSV_PATH,
            label_source="seed",
        )

    print("[TRAIN] Seed data injected successfully.")


def main():
    print("[TRAIN] Starting Training Pipeline...")

    ensure_seed_data()

    df = load_dataset(CSV_PATH)

    label_num = pd.to_numeric(df["label"], errors="coerce")
    mask = label_num.isin([0, 1])
    df = df.loc[mask].copy()
    df["label"] = label_num.loc[mask].astype(int)

    print(f"[TRAIN] Training on {len(df)} samples...")

    model = MailPhishingModel()
    model.train_from_dataframe(df)

    print("[TRAIN] Training Complete. Model is ready!")


if __name__ == "__main__":
    main()
