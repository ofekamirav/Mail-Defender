from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

CSV_PATH = DATA_DIR / "emails_dataset.csv"
MODEL_PATH = MODELS_DIR / "phishing_model.joblib"

VECTORIZER_MAX_FEATURES = 10000

RETRAIN_BATCH_SIZE = 3