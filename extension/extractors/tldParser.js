(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};

    /**
     * Parse a URL safely.
     */
    function parseURL(urlString) {
        try {
            return new URL(urlString);
        } catch {
            return null;
        }
    }

    /**
     * Return the hostname without the surrounding IPv6 brackets.
     */
    function getHostname(urlString) {
        const parsedURL = parseURL(urlString);

        if (!parsedURL) {
            return "";
        }

        return parsedURL.hostname
            .replace(/^\[/, "")
            .replace(/\]$/, "")
            .toLowerCase();
    }

    /**
     * Basic IP-address detection.
     */
    function isIPAddress(hostname) {
        if (!hostname) {
            return false;
        }

        // IPv6
        if (hostname.includes(":")) {
            return true;
        }

        // IPv4
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

    /**
     * Detect Unicode characters in a hostname.
     */
    function hasUnicode(hostname) {
        return Array.from(hostname).some(
            (character) =>
                character.codePointAt(0) > 127
        );
    }

    /**
     * Basic TLD extraction.
     *
     * Note:
     * This is intentionally lightweight. A Public Suffix List
     * implementation can be introduced later if required by
     * the finalized deployment architecture.
     */
    function getTLD(hostname) {
        if (!hostname || isIPAddress(hostname)) {
            return "";
        }

        const labels = hostname
            .split(".")
            .filter(Boolean);

        if (labels.length < 2) {
            return "";
        }

        return labels[labels.length - 1];
    }

    /**
     * Basic registered-domain extraction.
     *
     * Example:
     * login.example.com
     * → example.com
     */
    function getRegisteredDomain(hostname) {
        if (!hostname) {
            return "";
        }

        if (isIPAddress(hostname)) {
            return hostname;
        }

        const labels = hostname
            .split(".")
            .filter(Boolean);

        if (labels.length < 2) {
            return hostname;
        }

        return labels.slice(-2).join(".");
    }

    /**
     * Extract the subdomain portion.
     *
     * Example:
     * login.account.example.com
     * → login.account
     */
    function getSubdomain(hostname) {
        if (!hostname || isIPAddress(hostname)) {
            return "";
        }

        const labels = hostname
            .split(".")
            .filter(Boolean);

        if (labels.length <= 2) {
            return "";
        }

        return labels.slice(0, -2).join(".");
    }

    /**
     * Count subdomain labels.
     */
    function getSubdomainCount(hostname) {
        if (!hostname || isIPAddress(hostname)) {
            return 0;
        }

        const labels = hostname
            .split(".")
            .filter(Boolean);

        if (labels.length <= 2) {
            return 0;
        }

        return labels.length - 2;
    }

    /**
     * Detect hyphens in the registered-domain label.
     */
    function containsHyphen(hostname) {
        if (!hostname || isIPAddress(hostname)) {
            return false;
        }

        const registeredDomain =
            getRegisteredDomain(hostname);

        const labels = registeredDomain.split(".");

        if (labels.length < 2) {
            return false;
        }

        return labels[0].includes("-");
    }

    /**
     * Extract all domain-related information needed
     * by the browser-side feature pipeline.
     */
    function getDomainFeatures(urlString) {
        const parsedURL = parseURL(urlString);

        if (!parsedURL) {
            return {
                hostname: "",
                registered_domain: "",
                subdomain: "",
                subdomain_count: 0,
                tld: "",
                is_ip_address: 0,
                unicode_present: 0,
                contains_hyphen: 0,
                protocol: "",
                port: 0
            };
        }

        const hostname = getHostname(urlString);

        return {
            hostname: hostname,

            registered_domain:
                getRegisteredDomain(hostname),

            subdomain:
                getSubdomain(hostname),

            subdomain_count:
                getSubdomainCount(hostname),

            tld:
                getTLD(hostname),

            is_ip_address:
                isIPAddress(hostname) ? 1 : 0,

            unicode_present:
                hasUnicode(hostname) ? 1 : 0,

            contains_hyphen:
                containsHyphen(hostname) ? 1 : 0,

            protocol:
                parsedURL.protocol.replace(":", ""),

            port:
                parsedURL.port
                    ? Number(parsedURL.port)
                    : 0
        };
    }

    /*
     * Expose the complete domain parser.
     */
    globalThis.PhishCatcher.Extractors.getDomainFeatures =
        getDomainFeatures;

    /*
     * Expose individual helpers as well.
     */
    globalThis.PhishCatcher.Extractors.getHostname =
        getHostname;

    globalThis.PhishCatcher.Extractors.getRegisteredDomain =
        getRegisteredDomain;

    globalThis.PhishCatcher.Extractors.getTLD =
        getTLD;

    globalThis.PhishCatcher.Extractors.getSubdomain =
        getSubdomain;

})();