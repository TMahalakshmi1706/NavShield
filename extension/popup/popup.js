(function () {
    "use strict";

    const statusElement = document.getElementById("status");
    const resultElement = document.getElementById("result");
    const urlElement = document.getElementById("url");
    const probabilityElement = document.getElementById("probability");

    function setStatus(message) {
        if (statusElement) {
            statusElement.textContent = message;
        }
    }

    function displayResult(data) {
        if (!data) {
            setStatus("No prediction received.");
            return;
        }

        if (resultElement) {
            resultElement.textContent =
                data.prediction === "phishing"
                    ? "Phishing"
                    : "Legitimate";
        }

        if (probabilityElement) {
            if (typeof data.probability === "number") {
                probabilityElement.textContent =
                    `${(data.probability * 100).toFixed(2)}%`;
            } else {
                probabilityElement.textContent = "N/A";
            }
        }

        setStatus("Analysis complete.");
    }

    function requestCurrentPagePrediction() {
        setStatus("Analyzing current page...");

        chrome.tabs.query(
            {
                active: true,
                currentWindow: true
            },
            (tabs) => {
                if (chrome.runtime.lastError) {
                    setStatus(chrome.runtime.lastError.message);
                    return;
                }

                const tab = tabs[0];

                if (!tab || !tab.id) {
                    setStatus("Unable to access the current tab.");
                    return;
                }

                if (urlElement) {
                    urlElement.textContent = tab.url || "Unknown URL";
                }

                chrome.tabs.sendMessage(
                    tab.id,
                    {
                        action: "getFeatures"
                    },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            setStatus(
                                "Feature extraction is unavailable on this page."
                            );
                            return;
                        }

                        if (!response || !response.success) {
                            setStatus(
                                response?.error ||
                                "Unable to retrieve page features."
                            );
                            return;
                        }

                        chrome.runtime.sendMessage(
                            {
                                action: "predict",
                                url: response.url,
                                features: response.features
                            },
                            (predictionResponse) => {
                                if (chrome.runtime.lastError) {
                                    setStatus(
                                        chrome.runtime.lastError.message
                                    );
                                    return;
                                }

                                if (
                                    !predictionResponse ||
                                    !predictionResponse.success
                                ) {
                                    setStatus(
                                        predictionResponse?.error ||
                                        "Prediction failed."
                                    );
                                    return;
                                }

                                displayResult(predictionResponse.data);
                            }
                        );
                    }
                );
            }
        );
    }

    document.addEventListener("DOMContentLoaded", () => {
        requestCurrentPagePrediction();
    });
})();