(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};

    /**
     * Calculate Shannon entropy for a string.
     *
     * Higher entropy generally means greater character
     * randomness/complexity.
     */
    function calculateEntropy(value) {
        if (
            typeof value !== "string" ||
            value.length === 0
        ) {
            return 0;
        }

        const frequency = new Map();

        for (const character of value) {
            frequency.set(
                character,
                (frequency.get(character) || 0) + 1
            );
        }

        let entropy = 0;
        const length = value.length;

        for (const count of frequency.values()) {
            const probability = count / length;

            entropy -=
                probability *
                Math.log2(probability);
        }

        return entropy;
    }

    /**
     * Safely parse a URL.
     */
    function parseURL(urlString) {
        try {
            return new URL(urlString);
        } catch {
            return null;
        }
    }

    /**
     * Extract entropy features from the URL.
     *
     * Returns:
     * - url_entropy
     * - domain_entropy
     * - path_entropy
     * - query_entropy
     */
    function extractEntropyFeatures(urlString) {
        const parsedURL = parseURL(urlString);

        if (!parsedURL) {
            return {
                url_entropy: 0,
                domain_entropy: 0,
                path_entropy: 0,
                query_entropy: 0
            };
        }

        const hostname = parsedURL.hostname || "";
        const path = parsedURL.pathname || "";
        const query = parsedURL.search || "";

        return {
            url_entropy:
                calculateEntropy(urlString),

            domain_entropy:
                calculateEntropy(hostname),

            path_entropy:
                calculateEntropy(path),

            query_entropy:
                calculateEntropy(query)
        };
    }

    /*
     * Expose the main entropy extractor.
     */
    globalThis.PhishCatcher.Extractors
        .extractEntropyFeatures =
        extractEntropyFeatures;

    /*
     * Expose the entropy calculation helper.
     */
    globalThis.PhishCatcher.Extractors
        .calculateEntropy =
        calculateEntropy;

})();