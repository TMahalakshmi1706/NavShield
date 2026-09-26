(function () {
    "use strict";

    /*
     * =========================================================
     * NavShield Content Script
     * =========================================================
     *
     * Responsibilities:
     * 1. Collect the 21 ML features required by the
     *    Random Forest model.
     * 2. Run typosquatting independently from the ML model.
     * 3. Send the complete page analysis to background.js.
     *
     * IMPORTANT:
     * Typosquatting is NOT included in the ML feature vector.
     */

    const TYPOSQUATTING_THRESHOLD = 0.80;

    const LEGITIMATE_DOMAINS = [
        "google.com",
        "amazon.com",
        "microsoft.com",
        "apple.com",
        "paypal.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "netflix.com"
    ];

    /*
     * =========================================================
     * Extractor access
     * =========================================================
     *
     * All of the project's extractors are exported as:
     *
     * PhishCatcher.Extractors.<function>
     */

    function getExtractors() {
        if (
            globalThis.PhishCatcher &&
            globalThis.PhishCatcher.Extractors
        ) {
            return globalThis.PhishCatcher.Extractors;
        }

        return null;
    }

    /*
     * =========================================================
     * Domain helpers
     * =========================================================
     */

    function getHostname(url) {
        try {
            return new URL(url).hostname.toLowerCase();
        } catch {
            return "";
        }
    }

    function getRegisteredDomain(hostname) {
        if (!hostname) {
            return "";
        }

        const parts =
            hostname
                .split(".")
                .filter(Boolean);

        if (parts.length < 2) {
            return hostname;
        }

        return parts.slice(-2).join(".");
    }

    function getDomainName(registeredDomain) {
        const parts =
            registeredDomain
                .split(".")
                .filter(Boolean);

        if (parts.length < 2) {
            return registeredDomain;
        }

        return parts[parts.length - 2];
    }

    /*
     * =========================================================
     * Levenshtein distance
     * =========================================================
     */

    function levenshtein(a, b) {
        const rows = a.length + 1;
        const cols = b.length + 1;

        const matrix =
            Array.from(
                { length: rows },
                () => new Array(cols).fill(0)
            );

        for (let i = 0; i < rows; i++) {
            matrix[i][0] = i;
        }

        for (let j = 0; j < cols; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i < rows; i++) {
            for (let j = 1; j < cols; j++) {
                const cost =
                    a[i - 1] === b[j - 1]
                        ? 0
                        : 1;

                matrix[i][j] =
                    Math.min(
                        matrix[i - 1][j] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j - 1] + cost
                    );
            }
        }

        return matrix[rows - 1][cols - 1];
    }

    function similarity(a, b) {
        if (!a || !b) {
            return 0;
        }

        const maxLength =
            Math.max(
                a.length,
                b.length
            );

        if (maxLength === 0) {
            return 1;
        }

        return (
            1 -
            levenshtein(a, b) /
                maxLength
        );
    }

    /*
     * =========================================================
     * Look-alike normalization
     * =========================================================
     */

    function normalizeLookalikes(value) {
        return String(value)
            .toLowerCase()
            .replace(/0/g, "o")
            .replace(/1/g, "l")
            .replace(/3/g, "e")
            .replace(/4/g, "a")
            .replace(/5/g, "s")
            .replace(/7/g, "t");
    }

    /*
     * =========================================================
     * Character substitution
     * =========================================================
     */

    function findCharacterSubstitution(
        currentName,
        legitimateName
    ) {
        if (
            !currentName ||
            !legitimateName
        ) {
            return null;
        }

        if (
            currentName.length !==
            legitimateName.length
        ) {
            return null;
        }

        const differences = [];

        for (
            let i = 0;
            i < currentName.length;
            i++
        ) {
            if (
                currentName[i] !==
                legitimateName[i]
            ) {
                differences.push({
                    position: i,
                    current:
                        currentName[i],
                    legitimate:
                        legitimateName[i]
                });
            }
        }

        if (differences.length === 1) {
            return differences[0];
        }

        return null;
    }

    /*
     * =========================================================
     * Typosquatting detector
     * =========================================================
     */

    function detectTyposquatting(url) {
        const hostname =
            getHostname(url);

        if (!hostname) {
            return {
                detected: false,
                score: 0,
                currentDomain: "",
                matchedDomain: null,
                similarity: 0,
                similarityPercentage: 0,
                rawSimilarity: 0,
                characterSubstitution: null,
                reason: "Invalid hostname"
            };
        }

        const currentDomain =
            getRegisteredDomain(hostname);

        /*
         * Never classify an exact legitimate domain
         * as typosquatting.
         */
        if (
            LEGITIMATE_DOMAINS.includes(
                currentDomain
            )
        ) {
            return {
                detected: false,
                score: 0,
                currentDomain,
                matchedDomain: currentDomain,
                similarity: 1,
                similarityPercentage: 100,
                rawSimilarity: 1,
                characterSubstitution: null,
                reason:
                    "Exact legitimate domain"
            };
        }

        const currentName =
            getDomainName(
                currentDomain
            );

        let bestMatch = null;

        for (
            const legitimateDomain
            of LEGITIMATE_DOMAINS
        ) {
            const legitimateName =
                getDomainName(
                    legitimateDomain
                );

            const rawSimilarity =
                similarity(
                    currentName,
                    legitimateName
                );

            const normalizedCurrent =
                normalizeLookalikes(
                    currentName
                );

            const normalizedLegitimate =
                normalizeLookalikes(
                    legitimateName
                );

            const normalizedSimilarity =
                similarity(
                    normalizedCurrent,
                    normalizedLegitimate
                );

            const substitution =
                findCharacterSubstitution(
                    currentName,
                    legitimateName
                );

            const score =
                Math.max(
                    rawSimilarity,
                    normalizedSimilarity,
                    substitution
                        ? 0.90
                        : 0
                );

            if (
                !bestMatch ||
                score > bestMatch.score
            ) {
                bestMatch = {
                    legitimateDomain,
                    rawSimilarity,
                    normalizedSimilarity,
                    substitution,
                    score
                };
            }
        }

        if (!bestMatch) {
            return {
                detected: false,
                score: 0,
                currentDomain,
                matchedDomain: null,
                similarity: 0,
                similarityPercentage: 0,
                rawSimilarity: 0,
                characterSubstitution: null,
                reason:
                    "No legitimate domain match"
            };
        }

        const detected =
            bestMatch.score >=
            TYPOSQUATTING_THRESHOLD;

        let reason =
            "No strong typosquatting similarity";

        if (detected) {
            if (
                bestMatch.substitution
            ) {
                reason =
                    "Single-character substitution";
            } else if (
                bestMatch.normalizedSimilarity >=
                bestMatch.rawSimilarity
            ) {
                reason =
                    "Look-alike domain similarity";
            }
        }

        return {
            detected,
            score:
                bestMatch.score,
            currentDomain,
            matchedDomain:
                bestMatch.legitimateDomain,
            similarity:
                bestMatch.score,
            similarityPercentage:
                Math.round(
                    bestMatch.score * 100
                ),
            rawSimilarity:
                bestMatch.rawSimilarity,
            characterSubstitution:
                bestMatch.substitution,
            reason
        };
    }

    /*
     * =========================================================
     * ML FEATURE COLLECTION
     * =========================================================
     *
     * The Random Forest expects exactly these 21 features:
     *
     * 1.  ip_address
     * 2.  url_length
     * 3.  tiny_url
     * 4.  at_symbol
     * 5.  redirect_double_slash
     * 6.  prefix_suffix
     * 7.  subdomains
     * 8.  https
     * 9.  non_standard_port
     * 10. https_in_domain
     * 11. favicon
     * 12. request_url
     * 13. url_of_anchor
     * 14. links_in_script_link
     * 15. server_form_handler
     * 16. suspicious_inline_js
     * 17. hidden_html_elements
     * 18. unicode_present
     * 19. mixed_script
     * 20. homograph_similarity
     * 21. domain_age_days
     *
     * domain_age_days is added by the backend.
     */

    function collectFeatures(url) {
        const extractors =
            getExtractors();

        if (!extractors) {
            throw new Error(
                "PhishCatcher extractors are not loaded."
            );
        }

        /*
         * -----------------------------------------------------
         * URL features
         * -----------------------------------------------------
         */

        let urlFeatures = {};

        if (
            typeof extractors.extractURLFeatures ===
            "function"
        ) {
            urlFeatures =
                extractors.extractURLFeatures(
                    url
                ) || {};
        }

        /*
         * -----------------------------------------------------
         * HTML features
         * -----------------------------------------------------
         */

        let htmlFeatures = {};

        if (
            typeof extractors.extractHTMLFeatures ===
            "function"
        ) {
            htmlFeatures =
                extractors.extractHTMLFeatures() ||
                {};
        }

        /*
         * -----------------------------------------------------
         * Domain/TLD features
         *
         * tldParser.js exposes getDomainFeatures().
         * These values are useful for the browser pipeline,
         * but only the required ML fields are forwarded below.
         * -----------------------------------------------------
         */

        let domainFeatures = {};

        if (
            typeof extractors.getDomainFeatures ===
            "function"
        ) {
            domainFeatures =
                extractors.getDomainFeatures(
                    url
                ) || {};
        }

        /*
         * -----------------------------------------------------
         * Entropy
         *
         * Use extractEntropyFeatures(url), NOT
         * calculateEntropy() because the latter expects
         * a string and returns one entropy value.
         *
         * Entropy is not part of the current 21-feature
         * Random Forest vector, so it is intentionally not
         * forwarded to the model.
         * -----------------------------------------------------
         */

        let entropyFeatures = {};

        if (
            typeof extractors.extractEntropyFeatures ===
            "function"
        ) {
            entropyFeatures =
                extractors.extractEntropyFeatures(
                    url
                ) || {};
        }

        /*
         * -----------------------------------------------------
         * Keyword features
         *
         * Use extractKeywordFeatures(url), which combines
         * URL and visible page text.
         *
         * These keyword fields are not part of the current
         * 21-feature Random Forest vector, so they are kept
         * separately for future use and are not forwarded
         * to the model.
         * -----------------------------------------------------
         */

        let keywordFeatures = {};

        if (
            typeof extractors.extractKeywordFeatures ===
            "function"
        ) {
            keywordFeatures =
                extractors.extractKeywordFeatures(
                    url
                ) || {};
        }

        /*
         * -----------------------------------------------------
         * Construct ONLY the model's 21 features.
         * -----------------------------------------------------
         */

        const features = {
            ip_address:
                Number(
                    urlFeatures.ip_address ??
                    domainFeatures.is_ip_address ??
                    0
                ),

            url_length:
                Number(
                    urlFeatures.url_length ?? 0
                ),

            tiny_url:
                Number(
                    urlFeatures.tiny_url ?? 0
                ),

            at_symbol:
                Number(
                    urlFeatures.at_symbol ?? 0
                ),

            redirect_double_slash:
                Number(
                    urlFeatures.redirect_double_slash ??
                    0
                ),

            prefix_suffix:
                Number(
                    urlFeatures.prefix_suffix ??
                    domainFeatures.contains_hyphen ??
                    0
                ),

            subdomains:
                Number(
                    urlFeatures.subdomains ??
                    domainFeatures.subdomain_count ??
                    0
                ),

            https:
                Number(
                    urlFeatures.https ?? 0
                ),

            non_standard_port:
                Number(
                    urlFeatures.non_standard_port ??
                    0
                ),

            https_in_domain:
                Number(
                    urlFeatures.https_in_domain ??
                    0
                ),

            favicon:
                Number(
                    htmlFeatures.favicon ?? 0
                ),

            request_url:
                Number(
                    htmlFeatures.request_url ?? 0
                ),

            url_of_anchor:
                Number(
                    htmlFeatures.url_of_anchor ?? 0
                ),

            links_in_script_link:
                Number(
                    htmlFeatures.links_in_script_link ??
                    0
                ),

            server_form_handler:
                Number(
                    htmlFeatures.server_form_handler ??
                    0
                ),

            suspicious_inline_js:
                Number(
                    htmlFeatures.suspicious_inline_js ??
                    0
                ),

            hidden_html_elements:
                Number(
                    htmlFeatures.hidden_html_elements ??
                    0
                ),

            unicode_present:
                Number(
                    urlFeatures.unicode_present ??
                    0
                ),

            mixed_script:
                Number(
                    urlFeatures.mixed_script ??
                    0
                ),

            homograph_similarity:
                Number(
                    urlFeatures.homograph_similarity ??
                    0
                )
        };

        /*
         * Sanity check.
         *
         * domain_age_days is intentionally NOT included
         * here because the backend calculates it from the
         * current URL.
         */

        const expectedFeatures = [
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
            "homograph_similarity"
        ];

        for (
            const featureName
            of expectedFeatures
        ) {
            if (
                !Number.isFinite(
                    features[featureName]
                )
            ) {
                features[featureName] = 0;
            }
        }

        console.log(
            "[NavShield] Extracted ML features:",
            features
        );

        console.log(
            "[NavShield] Additional entropy features:",
            entropyFeatures
        );

        console.log(
            "[NavShield] Additional keyword features:",
            keywordFeatures
        );

        return features;
    }

    /*
     * =========================================================
     * PAGE ANALYSIS
     * =========================================================
     */

    function extractCurrentPageFeatures() {
        const url =
            window.location.href;

        const features =
            collectFeatures(url);

        const typosquatting =
            detectTyposquatting(url);

        return {
            url,

            features,

            security: {
                typosquatting
            },

            timestamp: Date.now()
        };
    }

    /*
     * =========================================================
     * SEND ANALYSIS TO BACKGROUND
     * =========================================================
     */

    function sendPageAnalysis() {
        let analysis;

        try {
            analysis =
                extractCurrentPageFeatures();
        } catch (error) {
            console.error(
                "[NavShield] Page analysis failed:",
                error
            );

            return null;
        }

        /*
         * Do not send an empty feature object.
         */

        if (
            !analysis.features ||
            Object.keys(
                analysis.features
            ).length === 0
        ) {
            console.error(
                "[NavShield] Feature extraction returned no ML features."
            );

            return analysis;
        }

        chrome.runtime.sendMessage(
            {
                action: "pageAnalysis",
                ...analysis
            },
            function () {
                /*
                 * Ignore errors caused by the extension
                 * context being reloaded.
                 */
                if (
                    chrome.runtime.lastError
                ) {
                    return;
                }
            }
        );

        return analysis;
    }

    /*
     * =========================================================
     * MESSAGES FROM POPUP / BACKGROUND
     * =========================================================
     */

    chrome.runtime.onMessage.addListener(
        function (
            message,
            sender,
            sendResponse
        ) {
            if (!message) {
                return;
            }

            if (
                message.action ===
                "getFeatures"
            ) {
                const analysis =
                    sendPageAnalysis();

                sendResponse(
                    analysis
                );

                return true;
            }

            if (
                message.action ===
                "analyzeCurrentPage"
            ) {
                const analysis =
                    sendPageAnalysis();

                sendResponse(
                    analysis
                );

                return true;
            }
        }
    );

    /*
     * =========================================================
     * AUTOMATIC ANALYSIS
     * =========================================================
     *
     * Wait until the DOM is available because the HTML
     * extractor needs the page contents.
     */

    if (
        document.readyState ===
        "loading"
    ) {
        document.addEventListener(
            "DOMContentLoaded",
            function () {
                sendPageAnalysis();
            },
            { once: true }
        );
    } else {
        sendPageAnalysis();
    }

})();