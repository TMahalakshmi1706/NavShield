# ml/scripts/evaluate.py

from pathlib import Path
import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TEST_PATH = (
    PROJECT_ROOT
    / "ml"
    / "datasets"
    / "processed"
    / "test.csv"
)

MODEL_DIR = PROJECT_ROOT / "ml" / "models"

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


def evaluate_model(name, model, X_test, y_test):

    print("\n" + "=" * 60)
    print(name.upper())
    print("=" * 60)

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")

    print("\nConfusion Matrix:")
    print(matrix)

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing"
            ],
            zero_division=0
        )
    )

    return {
        "model": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
    }


def main():

    print("=" * 60)
    print("PHISHCATCHER MODEL EVALUATION")
    print("=" * 60)

    test_df = pd.read_csv(
        TEST_PATH
    )

    X_test = test_df[FEATURES]
    y_test = test_df[TARGET].astype(int)

    random_forest = joblib.load(
        MODEL_DIR / "random_forest.pkl"
    )

    xgboost = joblib.load(
        MODEL_DIR / "xgboost.pkl"
    )

    results = []

    results.append(
        evaluate_model(
            "Random Forest",
            random_forest,
            X_test,
            y_test
        )
    )

    results.append(
        evaluate_model(
            "XGBoost",
            xgboost,
            X_test,
            y_test
        )
    )

    results_df = pd.DataFrame(
        results
    )

    results_path = (
        PROJECT_ROOT
        / "ml"
        / "models"
        / "evaluation_results.csv"
    )

    results_df.to_csv(
        results_path,
        index=False
    )

    print("\n" + "=" * 60)
    print("COMPARISON")
    print("=" * 60)

    print(
        results_df.to_string(
            index=False
        )
    )

    print(
        f"\nResults saved to:\n{results_path}"
    )


if __name__ == "__main__":
    main()