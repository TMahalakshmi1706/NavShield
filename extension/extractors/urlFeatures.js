(function () {
    "use strict";

    globalThis.PhishCatcher =
        globalThis.PhishCatcher || {};

    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};


    /*
     * =========================================================
     * BASIC URL HELPERS
     * =========================================================
     */

    function isIPv4(hostname) {
        const parts = hostname.split(".");

        if (parts.length !== 4) {
            return false;
        }

        return parts.every((part) => {
            if (!/^\d+$/.test(part)) {
                return false;
            }

            const value = Number(part);

            return value >= 0 && value <= 255;
        });
    }


    function isIPv6(hostname) {
        return hostname.includes(":");
    }


    function isIPAddress(hostname) {
        return (
            isIPv4(hostname) ||
            isIPv6(hostname)
        );
    }


    function isTinyURL(hostname) {
        const tinyURLHosts = [
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorturl.at"
        ];

        return tinyURLHosts.includes(
            hostname.toLowerCase()
        );
    }


    function hasAtSymbol(urlString) {
        return urlString.includes("@");
    }


    function hasRedirectDoubleSlash(urlString) {
        const protocolEnd =
            urlString.indexOf("://");

        if (protocolEnd === -1) {
            return false;
        }

        const remainder =
            urlString.substring(
                protocolEnd + 3
            );

        return remainder.includes("//");
    }


    function usesHTTPS(parsedURL) {
        return (
            parsedURL.protocol.toLowerCase() ===
            "https:"
        );
    }


    function hasNonStandardPort(parsedURL) {
        const port = parsedURL.port;

        if (!port) {
            return false;
        }

        if (
            parsedURL.protocol.toLowerCase() ===
            "https:"
        ) {
            return Number(port) !== 443;
        }

        if (
            parsedURL.protocol.toLowerCase() ===
            "http:"
        ) {
            return Number(port) !== 80;
        }

        return true;
    }


    function hasPrefixSuffix(hostname) {
        const registeredPart =
            hostname.split(".")[0];

        return (
            registeredPart.startsWith("-") ||
            registeredPart.endsWith("-") ||
            registeredPart.includes("-")
        );
    }


    function countSubdomains(hostname) {
        if (!hostname) {
            return 0;
        }

        if (isIPAddress(hostname)) {
            return 0;
        }

        const labels =
            hostname
                .split(".")
                .filter(Boolean);

        if (labels.length <= 2) {
            return 0;
        }

        return labels.length - 2;
    }


    function hasHTTPSInDomain(hostname) {
        return hostname
            .toLowerCase()
            .includes("https");
    }


    /*
     * =========================================================
     * RAW HOSTNAME EXTRACTION
     * =========================================================
     *
     * IMPORTANT:
     *
     * new URL("https://раypal.com/")
     *
     * becomes:
     *
     * xn--ypal-43d9g.com
     *
     * Therefore Unicode detection must happen BEFORE
     * browser URL normalization.
     */

    function getRawHostname(urlString) {

        if (
            typeof urlString !== "string" ||
            urlString.trim() === ""
        ) {
            return "";
        }

        const value =
            urlString.trim();


        /*
         * Extract everything after:
         *
         * scheme://
         *
         * and before:
         *
         * / ? #
         */

        const match =
            value.match(
                /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]+)/
            );


        if (!match) {
            return "";
        }


        let authority =
            match[1];


        /*
         * Remove username/password if present.
         *
         * Example:
         *
         * user:password@example.com
         */

        const atIndex =
            authority.lastIndexOf("@");

        if (atIndex !== -1) {
            authority =
                authority.substring(
                    atIndex + 1
                );
        }


        /*
         * Remove port.
         */

        if (
            authority.startsWith("[")
        ) {
            /*
             * IPv6
             *
             * [::1]:8080
             */

            const closingBracket =
                authority.indexOf("]");

            if (
                closingBracket !== -1
            ) {
                authority =
                    authority.substring(
                        0,
                        closingBracket + 1
                    );
            }

        } else {

            const colonIndex =
                authority.lastIndexOf(":");

            if (
                colonIndex !== -1 &&
                /^\d+$/.test(
                    authority.substring(
                        colonIndex + 1
                    )
                )
            ) {
                authority =
                    authority.substring(
                        0,
                        colonIndex
                    );
            }
        }


        return authority.toLowerCase();
    }


    /*
     * =========================================================
     * UNICODE FEATURES
     * =========================================================
     */

    function hasUnicode(hostname) {

        if (
            typeof hostname !== "string" ||
            hostname === ""
        ) {
            return false;
        }

        return Array.from(
            hostname
        ).some(
            (character) =>
                character.codePointAt(0) > 127
        );
    }


    function getCharacterScript(character) {

        const codePoint =
            character.codePointAt(0);


        /*
         * Latin
         */

        if (
            (
                codePoint >= 0x0041 &&
                codePoint <= 0x005A
            ) ||
            (
                codePoint >= 0x0061 &&
                codePoint <= 0x007A
            )
        ) {
            return "Latin";
        }


        /*
         * Greek
         */

        if (
            codePoint >= 0x0370 &&
            codePoint <= 0x03FF
        ) {
            return "Greek";
        }


        /*
         * Cyrillic
         */

        if (
            codePoint >= 0x0400 &&
            codePoint <= 0x04FF
        ) {
            return "Cyrillic";
        }


        /*
         * Hebrew
         */

        if (
            codePoint >= 0x0590 &&
            codePoint <= 0x05FF
        ) {
            return "Hebrew";
        }


        /*
         * Arabic
         */

        if (
            codePoint >= 0x0600 &&
            codePoint <= 0x06FF
        ) {
            return "Arabic";
        }


        /*
         * Devanagari
         */

        if (
            codePoint >= 0x0900 &&
            codePoint <= 0x097F
        ) {
            return "Devanagari";
        }


        /*
         * CJK
         */

        if (
            (
                codePoint >= 0x3040 &&
                codePoint <= 0x30FF
            ) ||
            (
                codePoint >= 0x3400 &&
                codePoint <= 0x4DBF
            ) ||
            (
                codePoint >= 0x4E00 &&
                codePoint <= 0x9FFF
            ) ||
            (
                codePoint >= 0xAC00 &&
                codePoint <= 0xD7AF
            )
        ) {
            return "CJK";
        }


        /*
         * Other Unicode scripts
         */

        if (codePoint > 127) {
            return "Other";
        }


        return null;
    }


    function hasMixedScript(hostname) {

        const scripts =
            new Set();


        for (
            const character of hostname
        ) {

            const script =
                getCharacterScript(
                    character
                );

            if (script) {
                scripts.add(script);
            }
        }


        return scripts.size > 1;
    }


    /*
     * =========================================================
     * HOMOGRAPH SIMILARITY
     * =========================================================
     */

    function calculateHomographSimilarity(
        hostname
    ) {

        if (
            !hasUnicode(hostname)
        ) {
            return 0;
        }


        try {

            const normalized =
                hostname.normalize("NFKC");


            if (
                normalized === hostname
            ) {
                return 0;
            }


            let matches = 0;


            const length =
                Math.max(
                    hostname.length,
                    normalized.length
                );


            if (length === 0) {
                return 0;
            }


            const minLength =
                Math.min(
                    hostname.length,
                    normalized.length
                );


            for (
                let i = 0;
                i < minLength;
                i++
            ) {

                if (
                    hostname[i] ===
                    normalized[i]
                ) {
                    matches++;
                }
            }


            return matches / length;

        } catch {

            return 0;
        }
    }


    /*
     * =========================================================
     * MAIN URL FEATURE EXTRACTION
     * =========================================================
     */

    function extractURLFeatures(
        urlString
    ) {

        const features = {

            ip_address: 0,

            url_length: 0,

            tiny_url: 0,

            at_symbol: 0,

            redirect_double_slash: 0,

            https: 0,

            non_standard_port: 0,

            prefix_suffix: 0,

            subdomains: 0,

            https_in_domain: 0,

            unicode_present: 0,

            mixed_script: 0,

            homograph_similarity: 0
        };


        /*
         * Invalid input
         */

        if (
            typeof urlString !== "string" ||
            urlString.trim() === ""
        ) {
            return features;
        }


        const normalizedURL =
            urlString.trim();


        /*
         * =====================================================
         * RAW HOSTNAME
         * =====================================================
         *
         * This MUST happen before new URL().
         */

        const rawHostname =
            getRawHostname(
                normalizedURL
            );


        /*
         * =====================================================
         * NORMAL URL FEATURES
         * =====================================================
         */

        features.url_length =
            normalizedURL.length;


        features.at_symbol =
            hasAtSymbol(
                normalizedURL
            )
                ? 1
                : 0;


        features.redirect_double_slash =
            hasRedirectDoubleSlash(
                normalizedURL
            )
                ? 1
                : 0;


        let parsedURL;


        try {

            parsedURL =
                new URL(
                    normalizedURL
                );

        } catch {

            /*
             * Even if URL parsing fails,
             * Unicode information from the raw
             * hostname is still useful.
             */

            features.unicode_present =
                hasUnicode(
                    rawHostname
                )
                    ? 1
                    : 0;

            features.mixed_script =
                hasMixedScript(
                    rawHostname
                )
                    ? 1
                    : 0;

            features.homograph_similarity =
                calculateHomographSimilarity(
                    rawHostname
                );

            return features;
        }


        /*
         * Browser-normalized hostname.
         *
         * Normal URL features use this value.
         */

        const hostname =
            parsedURL.hostname.toLowerCase();


        features.ip_address =
            isIPAddress(
                hostname
            )
                ? 1
                : 0;


        features.tiny_url =
            isTinyURL(
                hostname
            )
                ? 1
                : 0;


        features.https =
            usesHTTPS(
                parsedURL
            )
                ? 1
                : 0;


        features.non_standard_port =
            hasNonStandardPort(
                parsedURL
            )
                ? 1
                : 0;


        features.prefix_suffix =
            hasPrefixSuffix(
                hostname
            )
                ? 1
                : 0;


        features.subdomains =
            countSubdomains(
                hostname
            );


        features.https_in_domain =
            hasHTTPSInDomain(
                hostname
            )
                ? 1
                : 0;


        /*
         * =====================================================
         * UNICODE FEATURES
         * =====================================================
         *
         * VERY IMPORTANT:
         *
         * Do NOT use:
         *
         *     hostname
         *
         * here.
         *
         * hostname may already be:
         *
         *     xn--ypal-43d9g.com
         *
         * Instead use:
         *
         *     rawHostname
         *
         */

        features.unicode_present =
            hasUnicode(
                rawHostname
            )
                ? 1
                : 0;


        features.mixed_script =
            hasMixedScript(
                rawHostname
            )
                ? 1
                : 0;


        features.homograph_similarity =
            calculateHomographSimilarity(
                rawHostname
            );


        /*
         * =====================================================
         * DEBUG INFORMATION
         * =====================================================
         */

        console.log(
            "PhishCatcher URL:",
            normalizedURL
        );

        console.log(
            "PhishCatcher raw hostname:",
            rawHostname
        );

        console.log(
            "PhishCatcher normalized hostname:",
            hostname
        );

        console.log(
            "PhishCatcher Unicode features:",
            {
                unicode_present:
                    features.unicode_present,

                mixed_script:
                    features.mixed_script,

                homograph_similarity:
                    features.homograph_similarity
            }
        );


        return features;
    }


    /*
     * =========================================================
     * EXPORT
     * =========================================================
     */

    globalThis.PhishCatcher
        .Extractors
        .extractURLFeatures =
        extractURLFeatures;

})();