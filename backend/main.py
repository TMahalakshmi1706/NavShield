"""
PhishCatcher FastAPI application.

Entry point for the phishing detection backend.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router


# ---------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------

app = FastAPI(
    title="PhishCatcher API",
    description=(
        "Backend API for real-time phishing website "
        "detection using machine-learning features."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------

app.include_router(
    router,
    prefix="/api",
)


# ---------------------------------------------------------------------
# Root endpoint
# ---------------------------------------------------------------------

@app.get("/")
def root():
    """
    Basic API status endpoint.
    """

    return {
        "name": "PhishCatcher API",
        "version": "1.0.0",
        "status": "running",
    }