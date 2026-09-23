# ml/scripts/export_model.py

from pathlib import Path
import shutil
import json


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "ml" / "models"
BACKEND_MODEL_DIR = PROJECT_ROOT / "backend" / "model"

FEATURE_ORDER = [
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


def main():

    print("=" * 60)
    print("PHISHCATCHER MODEL EXPORT")
    print("=" * 60)

    BACKEND_MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    source_model = (
        MODEL_DIR
        / "random_forest.pkl"
    )

    destination_model = (
        BACKEND_MODEL_DIR
        / "random_forest.pkl"
    )

    if not source_model.exists():
        raise FileNotFoundError(
            f"Model not found:\n{source_model}\n\n"
            "Run train.py first."
        )

    shutil.copy2(
        source_model,
        destination_model
    )

    feature_order_path = (
        BACKEND_MODEL_DIR
        / "feature_order.json"
    )

    with open(
        feature_order_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            FEATURE_ORDER,
            file,
            indent=4
        )

    print("\nExported model:")
    print(destination_model)

    print("\nExported feature order:")
    print(feature_order_path)

    print("\nFeature count:")
    print(len(FEATURE_ORDER))

    print("\nModel export complete.")


if __name__ == "__main__":
    main()