# ml/scripts/train.py

from pathlib import Path
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = PROJECT_ROOT / "ml" / "datasets" / "final_dataset.csv"
MODEL_DIR = PROJECT_ROOT / "ml" / "models"
PROCESSED_DIR = PROJECT_ROOT / "ml" / "datasets" / "processed"

FEATURE_ORDER_PATH = PROJECT_ROOT / "backend" / "model" / "feature_order.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20

FEATURES = [
    "ip_address",
    "url_length",
    "tiny_url",
    "at_symbol",
    "redirect_double_slash",
    "prefix_suffix",
    "subdomains",
    "https",
    "non_standard_port",
    "https_in_domain",
    "favicon",
    "request_url",
    "url_of_anchor",
    "links_in_script_link",
    "server_form_handler",
    "suspicious_inline_js",
    "hidden_html_elements",
    "unicode_present",
    "mixed_script",
    "homograph_similarity",
    "domain_age_days",
]

TARGET = "label"


def main():

    print("=" * 60)
    print("PHISHCATCHER MODEL TRAINING")
    print("=" * 60)

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: {len(df)}")

    missing = [
        feature
        for feature in FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing features: {missing}"
        )

    if TARGET not in df.columns:
        raise ValueError("Missing target column: label")

    X = df[FEATURES].copy()
    y = pd.to_numeric(
        df[TARGET],
        errors="raise"
    ).astype(int)

    # Keep the original finalized dataset unchanged.
    # Handle unavailable domain age only inside training.
    X["domain_age_days"] = X["domain_age_days"].fillna(
        X["domain_age_days"].median()
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print("\nSplit:")
    print(f"Training: {len(X_train)}")
    print(f"Testing : {len(X_test)}")

    print("\nTraining labels:")
    print(y_train.value_counts().sort_index())

    print("\nTesting labels:")
    print(y_test.value_counts().sort_index())

    # --------------------------------------------------------
    # RANDOM FOREST
    # --------------------------------------------------------

    print("\nTraining Random Forest...")

    random_forest = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1
    )

    random_forest.fit(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # XGBOOST
    # --------------------------------------------------------

    print("Training XGBoost...")

    xgboost = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    xgboost.fit(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # SAVE MODELS
    # --------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        random_forest,
        MODEL_DIR / "random_forest.pkl"
    )

    joblib.dump(
        xgboost,
        MODEL_DIR / "xgboost.pkl"
    )

    # Save test data for evaluation.
    test_df = X_test.copy()
    test_df[TARGET] = y_test

    test_df.to_csv(
        PROCESSED_DIR / "test.csv",
        index=False
    )

    # Save feature order.
    FEATURE_ORDER_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        FEATURE_ORDER_PATH,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            FEATURES,
            file,
            indent=4
        )

    print("\nModels saved:")
    print(MODEL_DIR / "random_forest.pkl")
    print(MODEL_DIR / "xgboost.pkl")

    print("\nFeature order saved:")
    print(FEATURE_ORDER_PATH)

    print("\nTraining complete.")


if __name__ == "__main__":
    main()