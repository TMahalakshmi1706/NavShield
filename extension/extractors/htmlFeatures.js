(function () {
    "use strict";

    globalThis.PhishCatcher = globalThis.PhishCatcher || {};
    globalThis.PhishCatcher.Extractors =
        globalThis.PhishCatcher.Extractors || {};

    function normalizeURL(url) {
        try {
            return new URL(url, window.location.href);
        } catch {
            return null;
        }
    }

    function isExternalURL(url) {
        const parsed = normalizeURL(url);

        if (!parsed) {
            return false;
        }

        return parsed.origin !== window.location.origin;
    }

    function isEmptyOrSuspiciousAnchor(anchor) {
        const href = anchor.getAttribute("href");

        if (
            href === null ||
            href.trim() === "" ||
            href.trim() === "#"
        ) {
            return true;
        }

        const normalized = normalizeURL(href);

        if (!normalized) {
            return true;
        }

        return false;
    }

    function detectFaviconMismatch() {
        const faviconLinks = document.querySelectorAll(
            'link[rel~="icon"], link[rel="shortcut icon"]'
        );

        if (faviconLinks.length === 0) {
            return 0;
        }

        for (const link of faviconLinks) {
            const href = link.getAttribute("href");

            if (!href) {
                continue;
            }

            if (isExternalURL(href)) {
                return 1;
            }
        }

        return 0;
    }

    function detectExternalResources() {
        const selectors = [
            "img[src]",
            "script[src]",
            "link[href]",
            "iframe[src]",
            "video[src]",
            "audio[src]",
            "source[src]",
            "object[data]",
            "embed[src]"
        ];

        let externalCount = 0;

        for (const selector of selectors) {
            const elements = document.querySelectorAll(selector);

            for (const element of elements) {
                const attribute =
                    element.getAttribute("src") ||
                    element.getAttribute("href") ||
                    element.getAttribute("data");

                if (!attribute) {
                    continue;
                }

                if (isExternalURL(attribute)) {
                    externalCount++;
                }
            }
        }

        return externalCount;
    }

    function detectAnchorFeature() {
        const anchors = document.querySelectorAll("a");

        if (anchors.length === 0) {
            return 0;
        }

        for (const anchor of anchors) {
            const href = anchor.getAttribute("href");

            if (isEmptyOrSuspiciousAnchor(anchor)) {
                return 1;
            }

            if (href && isExternalURL(href)) {
                return 1;
            }
        }

        return 0;
    }

    function detectExternalScripts() {
        const scripts = document.querySelectorAll(
            "script[src]"
        );

        for (const script of scripts) {
            const src = script.getAttribute("src");

            if (src && isExternalURL(src)) {
                return 1;
            }
        }

        return 0;
    }

    function detectExternalFormHandler() {
        const forms = document.querySelectorAll("form");

        for (const form of forms) {
            const action = form.getAttribute("action");

            if (!action) {
                continue;
            }

            if (isExternalURL(action)) {
                return 1;
            }
        }

        return 0;
    }

    function detectSuspiciousInlineJavaScript() {
        const suspiciousPatterns = [
            /\beval\s*\(/i,
            /\bdocument\.write\s*\(/i,
            /\bwindow\.location\s*=/i,
            /\blocation\.href\s*=/i,
            /\blocation\.replace\s*\(/i,
            /\blocation\.assign\s*\(/i,
            /\bString\.fromCharCode\s*\(/i,
            /\bfromCharCode\s*\(/i,
            /\batob\s*\(/i,
            /\bunescape\s*\(/i
        ];

        const scripts = document.querySelectorAll(
            "script:not([src])"
        );

        for (const script of scripts) {
            const code = script.textContent || "";

            for (const pattern of suspiciousPatterns) {
                if (pattern.test(code)) {
                    return 1;
                }
            }
        }

        return 0;
    }

    function detectHiddenHTMLElements() {
        const elements = document.querySelectorAll(
            "body *"
        );

        for (const element of elements) {
            const tagName = element.tagName.toLowerCase();

            if (
                tagName === "script" ||
                tagName === "style" ||
                tagName === "meta" ||
                tagName === "link" ||
                tagName === "title"
            ) {
                continue;
            }

            if (element.hasAttribute("hidden")) {
                return 1;
            }

            const style = window.getComputedStyle(element);

            if (
                style.display === "none" ||
                style.visibility === "hidden" ||
                style.opacity === "0"
            ) {
                return 1;
            }
        }

        return 0;
    }

    function extractHTMLFeatures() {
        const externalResourceCount =
            detectExternalResources();

        const forms = document.querySelectorAll("form");

        const passwordFields =
            document.querySelectorAll(
                'input[type="password"]'
            );

        return {
            favicon: detectFaviconMismatch(),

            request_url:
                externalResourceCount > 0 ? 1 : 0,

            url_of_anchor:
                detectAnchorFeature(),

            links_in_script_link:
                detectExternalScripts(),

            server_form_handler:
                detectExternalFormHandler(),

            suspicious_inline_js:
                detectSuspiciousInlineJavaScript(),

            hidden_html_elements:
                detectHiddenHTMLElements(),

            external_link_count:
                externalResourceCount,

            form_count:
                forms.length,

            password_field_count:
                passwordFields.length
        };
    }

    globalThis.PhishCatcher.Extractors.extractHTMLFeatures =
        extractHTMLFeatures;

})();