(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};

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
        if (!hostname) {
            return false;
        }

        return isIPv4(hostname) || isIPv6(hostname);
    }

    function isTinyURL(hostname) {
        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "bit.do",
            "cutt.ly",
            "shorturl.at",
            "rebrand.ly",
            "tiny.cc",
            "lnkd.in",
            "rb.gy",
            "surl.li",
            "clck.ru"
        ];

        const normalized = hostname.toLowerCase();

        return shorteners.some(
            (domain) =>
                normalized === domain ||
                normalized.endsWith("." + domain)
        );
    }

    function hasAtSymbol(url) {
        return url.includes("@");
    }

    function hasRedirectDoubleSlash(url) {
        const protocolEnd = url.indexOf("://");

        if (protocolEnd === -1) {
            return false;
        }

        const remainder = url.substring(protocolEnd + 3);

        return remainder.includes("//");
    }

    function usesHTTPS(parsedURL) {
        return parsedURL.protocol.toLowerCase() === "https:";
    }

    function hasNonStandardPort(parsedURL) {
        const port = parsedURL.port;

        if (!port) {
            return false;
        }

        const protocol = parsedURL.protocol.toLowerCase();

        if (protocol === "http:" && port === "80") {
            return false;
        }

        if (protocol === "https:" && port === "443") {
            return false;
        }

        return true;
    }

    function hasPrefixSuffix(hostname) {
        const labels = hostname.split(".").filter(Boolean);

        if (labels.length < 2) {
            return false;
        }

        const domainLabel = labels[labels.length - 2];

        return domainLabel.includes("-");
    }

    function countSubdomains(hostname) {
        const labels = hostname.split(".").filter(Boolean);

        if (labels.length <= 2) {
            return 0;
        }

        return labels.length - 2;
    }

    function hasHTTPSInDomain(hostname) {
        return hostname.toLowerCase().includes("https");
    }

    function hasUnicode(hostname) {
        return Array.from(hostname).some(
            (character) => character.charCodeAt(0) > 127
        );
    }

    function getCharacterScript(character) {
        const codePoint = character.codePointAt(0);

        if (
            (codePoint >= 0x0041 && codePoint <= 0x005a) ||
            (codePoint >= 0x0061 && codePoint <= 0x007a)
        ) {
            return "Latin";
        }

        if (codePoint >= 0x0370 && codePoint <= 0x03ff) {
            return "Greek";
        }

        if (codePoint >= 0x0400 && codePoint <= 0x04ff) {
            return "Cyrillic";
        }

        if (codePoint >= 0x0590 && codePoint <= 0x05ff) {
            return "Hebrew";
        }

        if (codePoint >= 0x0600 && codePoint <= 0x06ff) {
            return "Arabic";
        }

        if (codePoint >= 0x0900 && codePoint <= 0x097f) {
            return "Devanagari";
        }

        if (
            (codePoint >= 0x3040 && codePoint <= 0x30ff) ||
            (codePoint >= 0x3400 && codePoint <= 0x4dbf) ||
            (codePoint >= 0x4e00 && codePoint <= 0x9fff) ||
            (codePoint >= 0xac00 && codePoint <= 0xd7af)
        ) {
            return "CJK";
        }

        if (codePoint > 127) {
            return "Other";
        }

        return null;
    }

    function hasMixedScript(hostname) {
        const scripts = new Set();

        for (const character of hostname) {
            const script = getCharacterScript(character);

            if (script) {
                scripts.add(script);
            }
        }

        return scripts.size > 1;
    }

    function calculateHomographSimilarity(hostname) {
        if (!hasUnicode(hostname)) {
            return 0;
        }

        try {
            const normalized = hostname.normalize("NFKC");

            if (normalized === hostname) {
                return 0;
            }

            let matches = 0;
            const length = Math.max(
                hostname.length,
                normalized.length
            );

            if (length === 0) {
                return 0;
            }

            const minLength = Math.min(
                hostname.length,
                normalized.length
            );

            for (let i = 0; i < minLength; i++) {
                if (hostname[i] === normalized[i]) {
                    matches++;
                }
            }

            return matches / length;
        } catch {
            return 0;
        }
    }

    function extractURLFeatures(urlString) {
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

        if (
            typeof urlString !== "string" ||
            urlString.trim() === ""
        ) {
            return features;
        }

        const normalizedURL = urlString.trim();

        features.url_length = normalizedURL.length;
        features.at_symbol = hasAtSymbol(normalizedURL) ? 1 : 0;
        features.redirect_double_slash =
            hasRedirectDoubleSlash(normalizedURL) ? 1 : 0;

        let parsedURL;

        try {
            parsedURL = new URL(normalizedURL);
        } catch {
            return features;
        }

        const hostname = parsedURL.hostname.toLowerCase();

        features.ip_address =
            isIPAddress(hostname) ? 1 : 0;

        features.tiny_url =
            isTinyURL(hostname) ? 1 : 0;

        features.https =
            usesHTTPS(parsedURL) ? 1 : 0;

        features.non_standard_port =
            hasNonStandardPort(parsedURL) ? 1 : 0;

        features.prefix_suffix =
            hasPrefixSuffix(hostname) ? 1 : 0;

        features.subdomains =
            countSubdomains(hostname);

        features.https_in_domain =
            hasHTTPSInDomain(hostname) ? 1 : 0;

        features.unicode_present =
            hasUnicode(hostname) ? 1 : 0;

        features.mixed_script =
            hasMixedScript(hostname) ? 1 : 0;

        features.homograph_similarity =
            calculateHomographSimilarity(hostname);

        return features;
    }

    globalThis.PhishCatcher.Extractors.extractURLFeatures =
        extractURLFeatures;

})();