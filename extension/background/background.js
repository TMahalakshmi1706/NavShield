(function () {
    "use strict";

    // Load the API service into the background service worker context.
    importScripts("../services/api.js");

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Background =
        globalThis.PhishCatcher.Background || {};

    /**
     * Handle messages from content scripts and popup.
     */
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message || typeof message.action !== "string") {
            return false;
        }

        if (message.action === "predict") {
            handlePrediction(message)
                .then((result) => {
                    sendResponse({
                        success: true,
                        data: result
                    });
                })
                .catch((error) => {
                    sendResponse({
                        success: false,
                        error: error.message || "Prediction request failed."
                    });
                });

            return true;
        }

        if (message.action === "health") {
            handleHealthCheck()
                .then((result) => {
                    sendResponse({
                        success: true,
                        data: result
                    });
                })
                .catch((error) => {
                    sendResponse({
                        success: false,
                        error: error.message || "Backend health check failed."
                    });
                });

            return true;
        }

        if (message.action === "modelInfo") {
            handleModelInfo()
                .then((result) => {
                    sendResponse({
                        success: true,
                        data: result
                    });
                })
                .catch((error) => {
                    sendResponse({
                        success: false,
                        error: error.message || "Model information request failed."
                    });
                });

            return true;
        }

        return false;
    });

    /**
     * Send extracted features to the backend for prediction.
     */
    async function handlePrediction(message) {
        const url = message.url;
        const features = message.features;

        if (typeof url !== "string" || url.trim() === "") {
            throw new Error("Prediction URL is missing.");
        }

        if (!features || typeof features !== "object") {
            throw new Error("Prediction features are missing.");
        }

        return await PhishCatcher.Services.requestPrediction(
            url,
            features
        );
    }

    /**
     * Check whether the backend is available.
     */
    async function handleHealthCheck() {
        return await PhishCatcher.Services.checkBackendHealth();
    }

    /**
     * Get information about the loaded ML model.
     */
    async function handleModelInfo() {
        return await PhishCatcher.Services.getModelInfo();
    }

    /**
     * Basic service-worker startup log.
     */
    console.log("PhishCatcher background service worker started.");
})();