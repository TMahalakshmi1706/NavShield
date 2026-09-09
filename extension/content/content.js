(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Content =
        globalThis.PhishCatcher.Content || {};

    /**
     * Safely execute an extractor.
     */
    function runExtractor(extractor, fallback) {
        try {
            if (typeof extractor !== "function") {
                return fallback;
            }

            return extractor();
        } catch (error) {
            console.error("PhishCatcher extractor error:", error);
            return fallback;
        }
    }

    /**
     * Extract all finalized runtime features.
     */
    function collectFeatures() {
        const urlFeatures = runExtractor(
            PhishCatcher.Extractors.extractURLFeatures,
            {}
        );

        const htmlFeatures = runExtractor(
            PhishCatcher.Extractors.extractHTMLFeatures,
            {}
        );

        const domainFeatures = runExtractor(
            PhishCatcher.Extractors.getDomainFeatures,
            {}
        );

        const entropyFeatures = runExtractor(
            PhishCatcher.Extractors.extractEntropyFeatures,
            {}
        );

        const keywordFeatures = runExtractor(
            PhishCatcher.Extractors.extractKeywordFeatures,
            {}
        );

        return {
            ...urlFeatures,
            ...htmlFeatures,
            ...domainFeatures,
            ...entropyFeatures,
            ...keywordFeatures
        };
    }

    /**
     * Extract features and store the latest result.
     */
    function extractCurrentPageFeatures() {
        const url = window.location.href;

        const features = collectFeatures();

        const result = {
            url: url,
            features: features,
            timestamp: new Date().toISOString()
        };

        globalThis.PhishCatcher.latestFeatures = result;

        return result;
    }

    /**
     * Respond to requests from the popup.
     */
    chrome.runtime.onMessage.addListener(
        (message, sender, sendResponse) => {
            if (!message || message.action !== "getFeatures") {
                return false;
            }

            try {
                const result = extractCurrentPageFeatures();

                sendResponse({
                    success: true,
                    url: result.url,
                    features: result.features,
                    timestamp: result.timestamp
                });
            } catch (error) {
                console.error(
                    "PhishCatcher feature extraction failed:",
                    error
                );

                sendResponse({
                    success: false,
                    error: error.message ||
                        "Feature extraction failed."
                });
            }

            return true;
        }
    );

    /**
     * Extract features when the content script loads.
     */
    const initialResult = extractCurrentPageFeatures();

    /**
     * Notify other extension components that features are ready.
     */
    document.dispatchEvent(
        new CustomEvent("PhishCatcherFeaturesReady", {
            detail: initialResult
        })
    );

    console.log(
        "PhishCatcher features extracted:",
        initialResult.features
    );
})();