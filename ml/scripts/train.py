from __future__ import annotations

import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

DATASET_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "datasets",
    "final_dataset_domain_age.csv",
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ml",
    "models",
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "random_forest.pkl",
)

FEATURE_ORDER_FILE = os.path.join(
    BASE_DIR,
    "backend",
    "model",
    "feature_order.json",
)

PROCESSED_DIR = os.path.join(
    BASE_DIR,
    "ml",
    "datasets",
    "processed",
)

# ============================================================
# EXACT 21 FEATURES USED BY THE MODEL
# ============================================================

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

# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20

N_ESTIMATORS = 300

# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 70)
print("PHISHING DETECTION MODEL TRAINING")
print("=" * 70)

print(f"\nDataset:")
print(DATASET_FILE)

if not os.path.exists(DATASET_FILE):
    raise FileNotFoundError(
        f"\nDataset not found:\n{DATASET_FILE}\n"
        "\nMake sure final_dataset_domain_age.csv is inside:\n"
        "ml/datasets/"
    )

df = pd.read_csv(DATASET_FILE)

print(f"\nDataset shape: {df.shape[0]} rows x {df.shape[1]} columns")

# ============================================================
# VALIDATE REQUIRED COLUMNS
# ============================================================

required_columns = FEATURES + [TARGET]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        "\nMissing required columns:\n"
        + "\n".join(missing_columns)
    )

print("\nAll required columns are present.")

# ============================================================
# CLEAN TARGET
# ============================================================

df = df.dropna(subset=[TARGET]).copy()

df[TARGET] = pd.to_numeric(
    df[TARGET],
    errors="coerce",
)

df = df.dropna(subset=[TARGET]).copy()

df[TARGET] = df[TARGET].astype(int)

# ============================================================
# CLEAN FEATURE VALUES
# ============================================================

for feature in FEATURES:
    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce",
    )

# ============================================================
# HANDLE DOMAIN AGE
# ============================================================

domain_age_missing = df["domain_age_days"].isna().sum()

print(
    f"\nMissing domain_age_days before filling: "
    f"{domain_age_missing}"
)

if domain_age_missing > 0:
    domain_age_median = df["domain_age_days"].median()

    print(
        f"Domain age median used for missing values: "
        f"{domain_age_median}"
    )

    df["domain_age_days"] = df["domain_age_days"].fillna(
        domain_age_median
    )

# ============================================================
# HANDLE OTHER NUMERIC MISSING VALUES
# ============================================================

for feature in FEATURES:
    if df[feature].isna().any():
        median_value = df[feature].median()

        if pd.isna(median_value):
            median_value = 0

        df[feature] = df[feature].fillna(
            median_value
        )

# ============================================================
# BUILD X AND y
# ============================================================

X = df[FEATURES].copy()
y = df[TARGET].copy()

print(f"\nFinal training rows: {len(X)}")
print(f"Number of features: {len(FEATURES)}")

print("\nClass distribution:")
print(y.value_counts().sort_index())

# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y,
)

print("\nTraining rows:", len(X_train))
print("Testing rows:", len(X_test))

# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")
print(f"Number of trees: {N_ESTIMATORS}")

model = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    class_weight=None,
)

model.fit(
    X_train,
    y_train,
)

print("Training completed.")

# ============================================================
# EVALUATE MODEL
# ============================================================

y_pred = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    y_pred,
)

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

print(f"\nAccuracy: {accuracy:.4f}")
print(f"Accuracy percentage: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        digits=4,
    )
)

print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        y_pred,
    )
)

# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = pd.Series(
    model.feature_importances_,
    index=FEATURES,
).sort_values(
    ascending=False
)

print("\nFeature Importance:")
print(importance)

# ============================================================
# SAVE PROCESSED TEST DATA
# ============================================================

test_output = X_test.copy()
test_output[TARGET] = y_test.values

test_output_file = os.path.join(
    PROCESSED_DIR,
    "test.csv",
)

test_output.to_csv(
    test_output_file,
    index=False,
)

print(
    f"\nProcessed test dataset saved to:\n"
    f"{test_output_file}"
)

# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_FILE,
)

print(
    f"\nNew Random Forest model saved to:\n"
    f"{MODEL_FILE}"
)

# ============================================================
# SAVE FEATURE ORDER
# ============================================================

os.makedirs(
    os.path.dirname(FEATURE_ORDER_FILE),
    exist_ok=True,
)

with open(
    FEATURE_ORDER_FILE,
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        FEATURES,
        file,
        indent=2,
    )

print(
    f"\nFeature order saved to:\n"
    f"{FEATURE_ORDER_FILE}"
)

# ============================================================
# FINAL MODEL INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("TRAINING FINISHED")
print("=" * 70)

print(f"\nModel type: {type(model).__name__}")
print(f"Number of trees: {model.n_estimators}")
print(f"Number of features: {model.n_features_in_}")
print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")
print(f"Accuracy: {accuracy * 100:.2f}%")

print("\nFeature order:")
for index, feature in enumerate(FEATURES, start=1):
    print(f"{index:2}. {feature}")

print("\nNew model is ready.")