(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};

    const KEYWORD_GROUPS = {
        authentication: [
            "login",
            "log in",
            "signin",
            "sign in",
            "username",
            "password",
            "credential",
            "authenticate"
        ],

        verification: [
            "verify",
            "verification",
            "confirm",
            "confirmation",
            "validate",
            "validation"
        ],

        account: [
            "account",
            "profile",
            "member",
            "user",
            "account locked",
            "account suspended"
        ],

        financial: [
            "bank",
            "banking",
            "payment",
            "billing",
            "invoice",
            "credit card",
            "debit card",
            "wallet",
            "transaction",
            "paypal"
        ],

        urgency: [
            "urgent",
            "immediately",
            "action required",
            "act now",
            "expires",
            "expired",
            "limited time",
            "suspended",
            "warning"
        ],

        security: [
            "security alert",
            "security",
            "unauthorized",
            "suspicious activity",
            "fraud",
            "threat",
            "protected"
        ],

        recovery: [
            "reset password",
            "password reset",
            "recover",
            "recovery",
            "unlock",
            "restore access"
        ]
    };

    /**
     * Flatten all keyword groups into one list.
     */
    function getAllKeywords() {
        const keywords = [];

        for (const group of Object.values(KEYWORD_GROUPS)) {
            keywords.push(...group);
        }

        return keywords;
    }

    /**
     * Count keyword occurrences in text.
     */
    function findKeywords(text) {
        if (
            typeof text !== "string" ||
            text.trim() === ""
        ) {
            return [];
        }

        const normalizedText = text.toLowerCase();
        const matches = [];

        for (const keyword of getAllKeywords()) {
            if (normalizedText.includes(keyword)) {
                matches.push(keyword);
            }
        }

        return matches;
    }

    /**
     * Detect keyword groups present in text.
     */
    function detectKeywordGroups(text) {
        const normalizedText =
            typeof text === "string"
                ? text.toLowerCase()
                : "";

        const result = {};

        for (const [group, keywords] of Object.entries(
            KEYWORD_GROUPS
        )) {
            result[`${group}_keyword`] = keywords.some(
                (keyword) =>
                    normalizedText.includes(keyword)
            )
                ? 1
                : 0;
        }

        return result;
    }

    /**
     * Extract suspicious keywords from the URL.
     */
    function extractURLKeywordFeatures(urlString) {
        const urlText =
            typeof urlString === "string"
                ? urlString
                : "";

        const matches = findKeywords(urlText);
        const groups = detectKeywordGroups(urlText);

        return {
            suspicious_keyword:
                matches.length > 0 ? 1 : 0,

            suspicious_keyword_count:
                matches.length,

            ...groups,

            matched_url_keywords:
                matches
        };
    }

    /**
     * Extract visible text from the current webpage.
     *
     * A clone is used so that removing non-visible-content
     * elements does not modify the actual webpage.
     */
    function getVisiblePageText() {
        if (!document.body) {
            return "";
        }

        const bodyClone =
            document.body.cloneNode(true);

        const excludedElements =
            bodyClone.querySelectorAll(
                "script, style, noscript, template, svg, canvas"
            );

        for (const element of excludedElements) {
            element.remove();
        }

        return (
            bodyClone.innerText ||
            bodyClone.textContent ||
            ""
        )
            .replace(/\s+/g, " ")
            .trim();
    }

    /**
     * Extract suspicious keywords from visible page text.
     */
    function extractPageKeywordFeatures() {
        const pageText = getVisiblePageText();

        const matches = findKeywords(pageText);
        const groups = detectKeywordGroups(pageText);

        return {
            suspicious_keyword:
                matches.length > 0 ? 1 : 0,

            suspicious_keyword_count:
                matches.length,

            ...groups,

            matched_page_keywords:
                matches
        };
    }

    /**
     * Extract combined URL + webpage keyword features.
     *
     * This is the function used by content.js.
     */
    function extractKeywordFeatures(urlString) {
        const urlFeatures =
            extractURLKeywordFeatures(
                urlString
            );

        const pageFeatures =
            extractPageKeywordFeatures();

        const combinedKeywords = [
            ...(urlFeatures.matched_url_keywords || []),
            ...(pageFeatures.matched_page_keywords || [])
        ];

        const uniqueKeywords =
            [...new Set(combinedKeywords)];

        const combinedGroups = {};

        for (const group of Object.keys(
            KEYWORD_GROUPS
        )) {
            combinedGroups[`${group}_keyword`] =
                urlFeatures[
                    `${group}_keyword`
                ] ||
                pageFeatures[
                    `${group}_keyword`
                ]
                    ? 1
                    : 0;
        }

        return {
            suspicious_keyword:
                combinedKeywords.length > 0
                    ? 1
                    : 0,

            suspicious_keyword_count:
                combinedKeywords.length,

            ...combinedGroups,

            matched_keywords:
                uniqueKeywords,

            url_keyword_count:
                urlFeatures.suspicious_keyword_count,

            page_keyword_count:
                pageFeatures.suspicious_keyword_count
        };
    }

    globalThis.PhishCatcher.Extractors
        .extractKeywordFeatures =
        extractKeywordFeatures;

    globalThis.PhishCatcher.Extractors
        .extractURLKeywordFeatures =
        extractURLKeywordFeatures;

    globalThis.PhishCatcher.Extractors
        .extractPageKeywordFeatures =
        extractPageKeywordFeatures;

    globalThis.PhishCatcher.Extractors
        .getVisiblePageText =
        getVisiblePageText;

})();