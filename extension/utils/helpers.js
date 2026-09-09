(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Utils =
        globalThis.PhishCatcher.Utils || {};

    /**
     * Check whether a value is a valid finite number.
     */
    function isValidNumber(value) {
        return (
            typeof value === "number" &&
            Number.isFinite(value)
        );
    }

    /**
     * Convert a value to a numeric representation.
     *
     * Returns 0 when the value cannot be converted safely.
     */
    function toNumber(value, defaultValue = 0) {
        if (isValidNumber(value)) {
            return value;
        }

        const converted = Number(value);

        return Number.isFinite(converted)
            ? converted
            : defaultValue;
    }

    /**
     * Convert a value to a binary feature.
     *
     * Accepts:
     * - true / false
     * - 1 / 0
     * - "1" / "0"
     */
    function toBinary(value) {
        if (
            value === true ||
            value === 1 ||
            value === "1"
        ) {
            return 1;
        }

        return 0;
    }

    /**
     * Remove undefined and null values from an object.
     */
    function removeEmptyValues(object) {
        const cleaned = {};

        if (
            !object ||
            typeof object !== "object"
        ) {
            return cleaned;
        }

        for (const [key, value] of Object.entries(object)) {
            if (
                value !== undefined &&
                value !== null
            ) {
                cleaned[key] = value;
            }
        }

        return cleaned;
    }

    /**
     * Create a shallow copy of an object containing only
     * explicitly requested feature names.
     */
    function selectFeatures(
        features,
        featureNames
    ) {
        const selected = {};

        if (
            !features ||
            typeof features !== "object"
        ) {
            return selected;
        }

        if (!Array.isArray(featureNames)) {
            return selected;
        }

        for (const featureName of featureNames) {
            if (
                Object.prototype.hasOwnProperty.call(
                    features,
                    featureName
                )
            ) {
                selected[featureName] =
                    features[featureName];
            }
        }

        return selected;
    }

    /**
     * Validate that all required feature names exist.
     */
    function validateFeatures(
        features,
        requiredFeatures
    ) {
        const missing = [];

        if (
            !features ||
            typeof features !== "object"
        ) {
            return {
                valid: false,
                missing: requiredFeatures || []
            };
        }

        if (!Array.isArray(requiredFeatures)) {
            return {
                valid: true,
                missing: []
            };
        }

        for (const featureName of requiredFeatures) {
            if (
                !Object.prototype.hasOwnProperty.call(
                    features,
                    featureName
                )
            ) {
                missing.push(featureName);
            }
        }

        return {
            valid: missing.length === 0,
            missing: missing
        };
    }

    /**
     * Safely obtain the current page URL.
     */
    function getCurrentURL() {
        try {
            return window.location.href;
        } catch {
            return "";
        }
    }

    /**
     * Safely obtain the current hostname.
     */
    function getCurrentHostname() {
        try {
            return window.location.hostname;
        } catch {
            return "";
        }
    }

    /**
     * Check whether the current page is a browser-internal
     * page that should not be analysed.
     */
    function isRestrictedPage() {
        const url = getCurrentURL();

        const restrictedProtocols = [
            "chrome:",
            "chrome-extension:",
            "edge:",
            "about:",
            "moz-extension:",
            "file:"
        ];

        return restrictedProtocols.some(
            (protocol) =>
                url.startsWith(protocol)
        );
    }

    /**
     * Return a timestamp suitable for logging and
     * feature-analysis events.
     */
    function getTimestamp() {
        return Date.now();
    }

    /**
     * Safely clone a feature object.
     */
    function cloneFeatures(features) {
        if (
            !features ||
            typeof features !== "object"
        ) {
            return {};
        }

        try {
            return JSON.parse(
                JSON.stringify(features)
            );
        } catch {
            return {};
        }
    }

    /**
     * Create a standardized extraction result.
     */
    function createExtractionResult(
        url,
        features,
        errors = []
    ) {
        return {
            url: url || "",
            timestamp: getTimestamp(),
            success: errors.length === 0,
            errors: Array.isArray(errors)
                ? errors
                : [],
            features: cloneFeatures(features)
        };
    }

    globalThis.PhishCatcher.Utils.isValidNumber =
        isValidNumber;

    globalThis.PhishCatcher.Utils.toNumber =
        toNumber;

    globalThis.PhishCatcher.Utils.toBinary =
        toBinary;

    globalThis.PhishCatcher.Utils.removeEmptyValues =
        removeEmptyValues;

    globalThis.PhishCatcher.Utils.selectFeatures =
        selectFeatures;

    globalThis.PhishCatcher.Utils.validateFeatures =
        validateFeatures;

    globalThis.PhishCatcher.Utils.getCurrentURL =
        getCurrentURL;

    globalThis.PhishCatcher.Utils.getCurrentHostname =
        getCurrentHostname;

    globalThis.PhishCatcher.Utils.isRestrictedPage =
        isRestrictedPage;

    globalThis.PhishCatcher.Utils.getTimestamp =
        getTimestamp;

    globalThis.PhishCatcher.Utils.cloneFeatures =
        cloneFeatures;

    globalThis.PhishCatcher.Utils.createExtractionResult =
        createExtractionResult;

})();