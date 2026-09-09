"""
PhishCatcher feature builder.

Purpose
-------
Convert browser-extracted features into the exact feature vector
required by the trained machine-learning model.

The feature names and order here must remain consistent with:

    backend/model/feature_order.json

The builder does not perform model prediction.
"""

from __future__ import annotations

import json
import math
import os
from typing import Any


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

FEATURE_ORDER_FILE = os.path.join(
    BASE_DIR,
    "backend",
    "model",
    "feature_order.json",
)


# ---------------------------------------------------------------------
# Finalized model features
# ---------------------------------------------------------------------

FINAL_FEATURES = [
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


# ---------------------------------------------------------------------
# Feature types
# ---------------------------------------------------------------------

BINARY_FEATURES = {
    "ip_address",
    "tiny_url",
    "at_symbol",
    "redirect_double_slash",
    "https",
    "non_standard_port",
    "prefix_suffix",
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
}


NUMERIC_FEATURES = {
    "url_length",
    "subdomains",
    "homograph_similarity",
    "domain_age_days",
}


# ---------------------------------------------------------------------
# Feature-order loading
# ---------------------------------------------------------------------

def load_feature_order() -> list[str]:
    """
    Load the model feature order from feature_order.json.

    If the file is empty or unavailable, use the finalized
    project feature order defined above.
    """

    if not os.path.exists(FEATURE_ORDER_FILE):
        return FINAL_FEATURES.copy()

    try:
        with open(
            FEATURE_ORDER_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        # Support:
        # ["feature1", "feature2", ...]
        if isinstance(data, list):
            order = data

        # Also support:
        # {"features": ["feature1", ...]}
        elif isinstance(data, dict):
            order = data.get("features", [])

        else:
            order = []

        if not order:
            return FINAL_FEATURES.copy()

        if not all(
            isinstance(feature, str)
            for feature in order
        ):
            raise ValueError(
                "feature_order.json contains invalid feature names."
            )

        return order

    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
    ):
        return FINAL_FEATURES.copy()


# ---------------------------------------------------------------------
# Value conversion
# ---------------------------------------------------------------------

def _to_binary(value: Any) -> int:
    """
    Convert a value into a binary 0/1 representation.
    """

    if isinstance(value, bool):
        return 1 if value else 0

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {
            "true",
            "yes",
            "1",
        }:
            return 1

        return 0

    try:
        return 1 if float(value) != 0 else 0
    except (
        TypeError,
        ValueError,
    ):
        return 0


def _to_numeric(
    value: Any,
    default: float = 0.0,
) -> float:
    """
    Convert a value into a finite numeric value.
    """

    if value is None:
        return default

    if isinstance(value, bool):
        return 1.0 if value else 0.0

    try:
        number = float(value)

        if not math.isfinite(number):
            return default

        return number

    except (
        TypeError,
        ValueError,
    ):
        return default


def _normalize_feature(
    feature_name: str,
    value: Any,
) -> float:
    """
    Normalize a single feature according to its expected type.
    """

    if feature_name in BINARY_FEATURES:
        return _to_binary(value)

    if feature_name in NUMERIC_FEATURES:
        return _to_numeric(value)

    # Safe fallback for an unexpected numeric feature.
    return _to_numeric(value)


# ---------------------------------------------------------------------
# Feature validation
# ---------------------------------------------------------------------

def validate_feature_names(
    feature_order: list[str],
) -> dict[str, Any]:
    """
    Validate the feature-order configuration.
    """

    expected = set(FINAL_FEATURES)
    actual = set(feature_order)

    missing = sorted(
        expected - actual
    )

    unexpected = sorted(
        actual - expected
    )

    return {
        "valid": (
            len(missing) == 0
            and len(unexpected) == 0
            and len(feature_order)
            == len(FINAL_FEATURES)
        ),
        "missing": missing,
        "unexpected": unexpected,
        "count": len(feature_order),
    }


# ---------------------------------------------------------------------
# Feature construction
# ---------------------------------------------------------------------

def build_feature_dict(
    extracted_features: dict[str, Any],
) -> dict[str, float]:
    """
    Convert raw extracted features into normalized model features.

    Only features belonging to the finalized model feature set
    are retained.
    """

    if not isinstance(
        extracted_features,
        dict,
    ):
        raise TypeError(
            "extracted_features must be a dictionary."
        )

    feature_order = load_feature_order()

    result: dict[str, float] = {}

    for feature_name in feature_order:

        value = extracted_features.get(
            feature_name
        )

        result[feature_name] = _normalize_feature(
            feature_name,
            value,
        )

    return result


def build_feature_vector(
    extracted_features: dict[str, Any],
) -> list[float]:
    """
    Build the ordered numeric vector expected by the ML model.
    """

    feature_order = load_feature_order()

    feature_dict = build_feature_dict(
        extracted_features
    )

    vector = [
        feature_dict[feature_name]
        for feature_name in feature_order
    ]

    return vector


# ---------------------------------------------------------------------
# Missing-feature inspection
# ---------------------------------------------------------------------

def get_missing_features(
    extracted_features: dict[str, Any],
) -> list[str]:
    """
    Return finalized model features that were not supplied
    by the browser/backend extraction pipeline.

    domain_age_days may legitimately be unavailable.
    """

    if not isinstance(
        extracted_features,
        dict,
    ):
        return FINAL_FEATURES.copy()

    feature_order = load_feature_order()

    missing = []

    for feature_name in feature_order:

        if feature_name not in extracted_features:
            missing.append(feature_name)

    return missing


# ---------------------------------------------------------------------
# Complete feature-building operation
# ---------------------------------------------------------------------

def prepare_features(
    extracted_features: dict[str, Any],
) -> dict[str, Any]:
    """
    Prepare a complete model-input package.

    Returns:
        {
            "feature_names": [...],
            "features": {...},
            "vector": [...]
        }
    """

    feature_order = load_feature_order()

    validation = validate_feature_names(
        feature_order
    )

    if not validation["valid"]:
        raise ValueError(
            "Invalid feature_order.json configuration: "
            f"{validation}"
        )

    feature_dict = build_feature_dict(
        extracted_features
    )

    vector = [
        feature_dict[name]
        for name in feature_order
    ]

    return {
        "feature_names": feature_order,
        "features": feature_dict,
        "vector": vector,
    }


# ---------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------

def get_feature_count() -> int:
    """
    Return the number of model features.
    """

    return len(load_feature_order())


if __name__ == "__main__":
    print(
        "PhishCatcher feature builder"
    )
    print(
        "Feature count:",
        get_feature_count(),
    )
    print(
        "Feature order:",
        load_feature_order(),
    )