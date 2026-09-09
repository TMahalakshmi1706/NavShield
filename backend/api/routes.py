"""
PhishCatcher API routes.

Provides the HTTP endpoints used by the browser extension.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .schemas import (
    HealthResponse,
    PredictionRequest,
    PredictionResponse,
)
from ..services.predictor import (
    get_model_info,
    load_model,
    predict,
)


router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
)
def health_check():
    """
    Check whether the backend and ML model are available.
    """

    try:
        load_model()

        return HealthResponse(
            status="ok",
            model_loaded=True,
        )

    except Exception:
        return HealthResponse(
            status="error",
            model_loaded=False,
        )


@router.post(
    "/predict",
    response_model=PredictionResponse,
)
def predict_phishing(
    request: PredictionRequest,
):
    """
    Analyze a webpage and return the phishing prediction.
    """

    if not request.url.strip():
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty.",
        )

    if not request.features:
        raise HTTPException(
            status_code=400,
            detail="Feature data cannot be empty.",
        )

    try:
        result = predict(
            request.features
        )

        return PredictionResponse(
            prediction=result["prediction"],
            probability=result["probability"],
            feature_count=result["feature_count"],
        )

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {error}",
        )


@router.get("/model-info")
def model_info():
    """
    Return basic information about the loaded ML model.
    """

    try:
        return get_model_info()

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load model information: {error}",
        )