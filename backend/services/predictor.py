from __future__ import annotations

import os
from typing import Any

import joblib

from .feature_builder import prepare_features
from .domain_age import get_domain_age_days


BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "random_forest.pkl",
)

_model = None


def load_model():
    global _model

    if _model is not None:
        return _model

    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_FILE}"
        )

    model_size = os.path.getsize(MODEL_FILE)

    if model_size == 0:
        raise ValueError(
            f"Model file is empty: {MODEL_FILE}"
        )

    _model = joblib.load(MODEL_FILE)

    return _model


def _convert_prediction_label(raw_prediction: Any) -> str:
    try:
        value = int(raw_prediction)
    except (TypeError, ValueError):
        value = raw_prediction

    if value == 1:
        return "phishing"

    return "legitimate"


def _get_phishing_probability(
    model: Any,
    vector: list,
) -> float:
    """
    Return the probability of the phishing class.

    The trained dataset uses:
        0 = legitimate
        1 = phishing
    """

    if not hasattr(model, "predict_proba"):
        return 0.0

    probabilities = model.predict_proba([vector])[0]
    classes = list(model.classes_)

    try:
        phishing_index = classes.index(1)
        return float(probabilities[phishing_index])
    except (ValueError, TypeError):
        return 0.0


def _add_domain_age(
    extracted_features: dict,
    url: str | None,
) -> dict:
    """
    Add live domain age to the feature set.

    The Random Forest expects domain_age_days
    as one of its 21 input features.
    """

    features = dict(extracted_features or {})

    if not url:
        return features

    try:
        domain_age = get_domain_age_days(url)

        if domain_age is not None:
            features["domain_age_days"] = float(
                domain_age
            )

    except Exception:
        # Domain-age lookup failure should not stop
        # the rest of the phishing analysis.
        pass

    return features


def predict(
    extracted_features: dict,
    url: str | None = None,
):
    """
    Run the trained Random Forest prediction.

    The URL is used to obtain the live domain age.
    """

    features_with_domain_age = _add_domain_age(
        extracted_features,
        url,
    )

    prepared = prepare_features(
        features_with_domain_age
    )

    vector = prepared["vector"]

    model = load_model()

    raw_prediction = model.predict(
        [vector]
    )[0]

    label = _convert_prediction_label(
        raw_prediction
    )

    phishing_probability = _get_phishing_probability(
        model,
        vector,
    )

    return {
        "prediction": label,
        "probability": phishing_probability,
        "feature_count": len(vector),
        "features": prepared["features"],
    }


def get_model_info():
    model = load_model()

    return {
        "model_type": type(model).__name__,
        "model_file": MODEL_FILE,
        "feature_count": len(
            prepare_features({})["vector"]
        ),
        "supports_probability": hasattr(
            model,
            "predict_proba",
        ),
    }


def reset_model():
    global _model

    _model = None