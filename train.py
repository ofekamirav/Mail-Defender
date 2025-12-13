import os
import pandas as pd
from detector.storage import load_dataset, append_email_record
from detector.model import MailPhishingModel
from detector.config import CSV_PATH, MODEL_PATH

#First data for training the model at the first run
SEED_DATA = [
    {"subject": "Win a Lottery Now!", "body": "Click here to claim your prize urgent", "sender": "lottery@winner-lucky.xyz", "label": 1},
    {"subject": "Security Alert", "body": "Your account is compromised verify now", "sender": "security@paypa1.com", "label": 1},
    {"subject": "Meeting Updates", "body": "See you at 10:00 AM in the conference room", "sender": "boss@company.com", "label": 0},
    {"subject": "Lunch?", "body": "Do you want to grab pizza later?", "sender": "friend@gmail.com", "label": 0},
    {"subject": "Invoice 1023", "body": "Attached is the invoice for your recent purchase", "sender": "billing@amazon-support-fake.com", "label": 1},
    {"subject": "Project Plan", "body": "Here is the roadmap for Q4", "sender": "pm@upwind.io", "label": 0},
]

def ensure_seed_data():
    df = load_dataset(CSV_PATH)
    
    if not df.empty and 'label' in df.columns:
        labeled_df = df[pd.to_numeric(df['label'], errors='coerce').notnull()]
        if len(labeled_df) >= 5:
            print(f"[TRAIN] Found {len(labeled_df)} existing labeled emails. Skipping seed data.")
            return

    print("[TRAIN] Not enough data found. Injecting SEED DATA...")
    for item in SEED_DATA:
        append_email_record(
            subject=item["subject"],
            body=item["body"],
            sender=item["sender"],
            source="seed",
            ml_score=0.0, 
            rule_score=0.0,
            final_score=0.0,
            label=item["label"],
            csv_path=CSV_PATH
        )
    print("[TRAIN] Seed data injected successfully.")

def main():
    print("[TRAIN] Starting Training Pipeline!!!!")
    
    ensure_seed_data()
    
    df = load_dataset(CSV_PATH)
    
    df = df[pd.to_numeric(df['label'], errors='coerce').notnull()]
    df['label'] = df['label'].astype(int)

    print(f"[TRAIN] Training on {len(df)} samples...")

    model = MailPhishingModel()
    model.train_from_dataframe(df)
    
    print("[TRAIN] Training Complete. Model is ready!")

if __name__ == "__main__":
    main()