"""
PhishCatcher API schemas.

Defines the data exchanged between the browser extension
and the backend prediction API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    """
    Request sent by the browser extension.

    The extension supplies the current URL and the
    features extracted from the webpage.
    """

    url: str = Field(
        ...,
        description="URL of the webpage being analyzed.",
    )

    features: dict[str, Any] = Field(
        default_factory=dict,
        description="Browser-extracted feature values.",
    )


class PredictionResponse(BaseModel):
    """
    Prediction returned by the backend.
    """

    prediction: str = Field(
        ...,
        description="Classification result: phishing or legitimate.",
    )

    probability: float | None = Field(
        default=None,
        description="Probability associated with the predicted class.",
    )

    feature_count: int = Field(
        ...,
        description="Number of features supplied to the model.",
    )


class HealthResponse(BaseModel):
    """
    Backend health/status response.
    """

    status: str
    model_loaded: bool