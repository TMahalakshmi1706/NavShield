"""
PhishCatcher prediction service.

Loads the trained Random Forest model and performs
prediction using the finalized feature vector.
"""

from __future__ import annotations

import os
import pickle
from typing import Any

from .feature_builder import prepare_features


# ---------------------------------------------------------------------
# Model path
# ---------------------------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "backend",
    "model",
    "random_forest.pkl",
)


# ---------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------

_model = None


def load_model():
    """
    Load the trained Random Forest model.

    The model is loaded once and reused for subsequent predictions.
    """

    global _model

    if _model is not None:
        return _model

    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_FILE}"
        )

    with open(
        MODEL_FILE,
        "rb",
    ) as file:
        _model = pickle.load(file)

    return _model


# ---------------------------------------------------------------------
# Prediction helpers
# ---------------------------------------------------------------------

def _convert_prediction_label(
    prediction: Any,
) -> str:
    """
    Convert the model's output into a standardized label.

    The training convention is expected to be:

        0 = legitimate
        1 = phishing
    """

    if isinstance(prediction, str):
        normalized = prediction.strip().lower()

        if normalized in {
            "1",
            "true",
            "phishing",
            "phish",
        }:
            return "phishing"

        if normalized in {
            "0",
            "false",
            "legitimate",
            "legit",
            "benign",
            "safe",
        }:
            return "legitimate"

    try:
        numeric = int(prediction)

        return (
            "phishing"
            if numeric == 1
            else "legitimate"
        )

    except (
        TypeError,
        ValueError,
    ):
        raise ValueError(
            f"Unsupported model prediction: {prediction}"
        )


def _get_probability(
    model,
    vector,
    prediction,
) -> float | None:
    """
    Obtain the probability associated with the predicted class.

    Returns None if the loaded model does not support
    probability prediction.
    """

    if not hasattr(
        model,
        "predict_proba",
    ):
        return None

    try:
        probabilities = model.predict_proba(
            [vector]
        )[0]

        classes = getattr(
            model,
            "classes_",
            None,
        )

        if classes is None:
            return None

        # Find the probability corresponding to
        # the actual predicted class.
        for index, class_value in enumerate(
            classes
        ):
            try:
                if (
                    int(class_value)
                    == int(prediction)
                ):
                    return float(
                        probabilities[index]
                    )
            except (
                TypeError,
                ValueError,
            ):
                if str(class_value) == str(
                    prediction
                ):
                    return float(
                        probabilities[index]
                    )

        return None

    except Exception:
        return None


# ---------------------------------------------------------------------
# Public prediction function
# ---------------------------------------------------------------------

def predict(
    extracted_features: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform phishing prediction.

    Parameters
    ----------
    extracted_features:
        Feature dictionary produced by the extension
        and/or backend feature-building pipeline.

    Returns
    -------
    dict
        Prediction result containing:

        - prediction
        - probability
        - feature_count
        - features
    """

    prepared = prepare_features(
        extracted_features
    )

    vector = prepared["vector"]

    model = load_model()

    raw_prediction = model.predict(
        [vector]
    )[0]

    label = _convert_prediction_label(
        raw_prediction
    )

    probability = _get_probability(
        model,
        vector,
        raw_prediction,
    )

    return {
        "prediction": label,
        "probability": probability,
        "feature_count": len(vector),
        "features": prepared["features"],
    }


# ---------------------------------------------------------------------
# Model information
# ---------------------------------------------------------------------

def get_model_info() -> dict[str, Any]:
    """
    Return basic information about the loaded model.
    """

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


def reset_model() -> None:
    """
    Clear the cached model instance.

    Useful during development if the .pkl file
    is replaced without restarting the backend.
    """

    global _model

    _model = None