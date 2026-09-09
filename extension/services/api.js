(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Services =
        globalThis.PhishCatcher.Services || {};

    /*
     * Backend configuration.
     *
     * Change this value if your FastAPI server
     * runs on a different host or port.
     */
    const API_BASE_URL = "http://127.0.0.1:8000/api";

    /**
     * Send extracted features to the backend
     * and request a phishing prediction.
     *
     * @param {string} url
     * @param {Object} features
     * @returns {Promise<Object>}
     */
    async function requestPrediction(
        url,
        features
    ) {
        if (
            typeof url !== "string" ||
            url.trim() === ""
        ) {
            throw new Error(
                "A valid URL is required."
            );
        }

        if (
            !features ||
            typeof features !== "object"
        ) {
            throw new Error(
                "Feature data is required."
            );
        }

        const response = await fetch(
            `${API_BASE_URL}/predict`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url,
                    features: features
                })
            }
        );

        if (!response.ok) {
            let message =
                `Backend request failed (${response.status}).`;

            try {
                const errorData =
                    await response.json();

                if (errorData.detail) {
                    message =
                        errorData.detail;
                }
            } catch {
                // Keep the default error message.
            }

            throw new Error(message);
        }

        return await response.json();
    }

    /**
     * Check whether the backend is reachable.
     *
     * @returns {Promise<Object>}
     */
    async function checkBackendHealth() {
        const response = await fetch(
            `${API_BASE_URL}/health`,
            {
                method: "GET"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Backend health check failed (${response.status}).`
            );
        }

        return await response.json();
    }

    /**
     * Retrieve basic model information.
     *
     * @returns {Promise<Object>}
     */
    async function getModelInfo() {
        const response = await fetch(
            `${API_BASE_URL}/model-info`,
            {
                method: "GET"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Model information request failed (${response.status}).`
            );
        }

        return await response.json();
    }

    globalThis.PhishCatcher.Services
        .requestPrediction =
        requestPrediction;

    globalThis.PhishCatcher.Services
        .checkBackendHealth =
        checkBackendHealth;

    globalThis.PhishCatcher.Services
        .getModelInfo =
        getModelInfo;

})();