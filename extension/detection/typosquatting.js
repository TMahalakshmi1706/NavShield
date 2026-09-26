(function () {
    "use strict";

    globalThis.PhishCatcher =
        globalThis.PhishCatcher || {};

    globalThis.PhishCatcher.Detection =
        globalThis.PhishCatcher.Detection || {};


    /*
     * =========================================================
     * DOMAIN NORMALIZATION
     * =========================================================
     */

    function normalizeDomain(domain) {

        if (
            typeof domain !== "string"
        ) {
            return "";
        }

        return domain
            .toLowerCase()
            .trim()
            .replace(/^www\./, "");
    }


    /*
     * =========================================================
     * DOMAIN EXTRACTION
     * =========================================================
     */

    function getDomainFromURL(url) {

        if (
            typeof url !== "string" ||
            url.trim() === ""
        ) {
            return "";
        }

        try {

            const parsedURL =
                new URL(url);

            return normalizeDomain(
                parsedURL.hostname
            );

        } catch {

            return "";
        }
    }


    /*
     * =========================================================
     * LEVENSHTEIN DISTANCE
     * =========================================================
     */

    function levenshteinDistance(
        first,
        second
    ) {

        if (first === second) {
            return 0;
        }

        if (!first) {
            return second.length;
        }

        if (!second) {
            return first.length;
        }

        const matrix = [];


        for (
            let i = 0;
            i <= second.length;
            i++
        ) {

            matrix[i] = [i];
        }


        for (
            let j = 0;
            j <= first.length;
            j++
        ) {

            matrix[0][j] = j;
        }


        for (
            let i = 1;
            i <= second.length;
            i++
        ) {

            for (
                let j = 1;
                j <= first.length;
                j++
            ) {

                if (
                    second.charAt(i - 1) ===
                    first.charAt(j - 1)
                ) {

                    matrix[i][j] =
                        matrix[i - 1][j - 1];

                } else {

                    matrix[i][j] =
                        Math.min(

                            matrix[i - 1][j] + 1,

                            matrix[i][j - 1] + 1,

                            matrix[i - 1][j - 1] + 1

                        );
                }
            }
        }


        return matrix[
            second.length
        ][
            first.length
        ];
    }


    /*
     * =========================================================
     * SIMILARITY
     * =========================================================
     */

    function calculateSimilarity(
        first,
        second
    ) {

        first =
            normalizeDomain(first);

        second =
            normalizeDomain(second);


        if (
            !first ||
            !second
        ) {
            return 0;
        }


        if (
            first === second
        ) {
            return 1;
        }


        const distance =
            levenshteinDistance(
                first,
                second
            );


        const maximumLength =
            Math.max(
                first.length,
                second.length
            );


        if (
            maximumLength === 0
        ) {
            return 0;
        }


        return (
            1 -
            (
                distance /
                maximumLength
            )
        );
    }


    /*
     * =========================================================
     * SUSPICIOUS CHARACTER SUBSTITUTIONS
     * =========================================================
     *
     * Examples:
     *
     * amazon -> amaz0n
     * paypal -> paypa1
     * google -> g00gle
     */

    function hasDigitSubstitution(
        domain
    ) {

        if (!domain) {
            return false;
        }


        return /[01345789]/.test(
            domain
        );
    }


    /*
     * =========================================================
     * COMMON CHARACTER SUBSTITUTIONS
     * =========================================================
     */

    function hasCommonCharacterSubstitution(
        domain
    ) {

        if (!domain) {
            return false;
        }


        const suspiciousPatterns = [

            /0/,      // o -> 0
            /1/,      // l/i -> 1
            /3/,      // e -> 3
            /4/,      // a -> 4
            /5/,      // s -> 5
            /7/,      // t -> 7
            /8/,      // b -> 8
            /9/       // g -> 9

        ];


        return suspiciousPatterns.some(
            (pattern) =>
                pattern.test(domain)
        );
    }


    /*
     * =========================================================
     * MAIN TYPOSQUATTING DETECTOR
     * =========================================================
     */

    function detectTyposquatting(
        url,
        legitimateDomains
    ) {

        const currentDomain =
            getDomainFromURL(url);


        if (!currentDomain) {

            return {

                detected: false,

                score: 0,

                currentDomain: "",

                matchedDomain: null,

                similarity: 0,

                similarityPercentage: 0,

                reason: null

            };
        }


        if (
            !Array.isArray(
                legitimateDomains
            )
        ) {

            legitimateDomains = [];
        }


        let bestMatch = null;

        let bestSimilarity = 0;


        /*
         * Compare current domain against
         * every legitimate domain.
         */

        for (
            const legitimateDomain
            of legitimateDomains
        ) {

            const normalizedDomain =
                normalizeDomain(
                    legitimateDomain
                );


            if (!normalizedDomain) {
                continue;
            }


            /*
             * Never flag the legitimate
             * domain itself.
             */

            if (
                currentDomain ===
                normalizedDomain
            ) {

                return {

                    detected: false,

                    score: 0,

                    currentDomain:

                        currentDomain,

                    matchedDomain:

                        normalizedDomain,

                    similarity: 1,

                    similarityPercentage: 100,

                    reason: null

                };
            }


            const similarity =
                calculateSimilarity(
                    currentDomain,
                    normalizedDomain
                );


            if (
                similarity >
                bestSimilarity
            ) {

                bestSimilarity =
                    similarity;

                bestMatch =
                    normalizedDomain;
            }
        }


        /*
         * Initial threshold.
         *
         * 0.80 = 80% similarity.
         */

        const SIMILARITY_THRESHOLD =
            0.80;


        const detected =
            bestMatch !== null &&
            bestSimilarity >=
                SIMILARITY_THRESHOLD;


        const similarityPercentage =
            Math.round(
                bestSimilarity * 100
            );


        let score = 0;

        if (detected) {

            score =
                similarityPercentage;
        }


        let reason = null;


        if (detected) {

            const characterSubstitution =
                hasCommonCharacterSubstitution(
                    currentDomain
                );


            if (
                characterSubstitution
            ) {

                reason =
                    "The domain is highly similar to a legitimate domain and may contain character substitution.";

            } else {

                reason =
                    "The domain is highly similar to a known legitimate domain.";
            }
        }


        return {

            detected:

                detected,

            score:

                score,

            currentDomain:

                currentDomain,

            matchedDomain:

                bestMatch,

            similarity:

                bestSimilarity,

            similarityPercentage:

                similarityPercentage,

            characterSubstitution:

                hasDigitSubstitution(
                    currentDomain
                ),

            reason:

                reason
        };
    }


    /*
     * =========================================================
     * EXPORT
     * =========================================================
     */

    globalThis.PhishCatcher.Detection
        .levenshteinDistance =
        levenshteinDistance;


    globalThis.PhishCatcher.Detection
        .calculateSimilarity =
        calculateSimilarity;


    globalThis.PhishCatcher.Detection
        .detectTyposquatting =
        detectTyposquatting;

})();