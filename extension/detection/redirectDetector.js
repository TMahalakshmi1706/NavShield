(function () {
    "use strict";


    // =========================================================
    // REDIRECT DETECTOR
    // =========================================================

    const navigationHistory =
        new Map();


    // =========================================================
    // URL HELPERS
    // =========================================================

    function isBrowserInternalUrl(url) {

        if (!url) {
            return false;
        }


        return (
            url.startsWith("chrome://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("edge://") ||
            url.startsWith("about:") ||
            url.startsWith("brave://") ||
            url.startsWith("opera://")
        );
    }


    function isWebUrl(url) {

        if (!url) {
            return false;
        }


        return (
            url.startsWith("http://") ||
            url.startsWith("https://")
        );
    }


    // =========================================================
    // START NAVIGATION
    // =========================================================

    function startNavigation(
        tabId,
        url
    ) {

        if (
            !Number.isInteger(tabId)
        ) {
            return;
        }


        navigationHistory.set(
            tabId,
            {
                lastUrl:
                    url || null,

                urls: [],

                redirects: [],

                startedAt:
                    Date.now()
            }
        );
    }


    // =========================================================
    // RECORD NAVIGATION
    // =========================================================

    function recordNavigation(
        tabId,
        url,
        transitionQualifiers = []
    ) {

        if (
            !Number.isInteger(tabId) ||
            !url
        ) {
            return;
        }


        let history =
            navigationHistory.get(
                tabId
            );


        if (!history) {

            history = {
                lastUrl: null,
                urls: [],
                redirects: [],
                startedAt: Date.now()
            };


            navigationHistory.set(
                tabId,
                history
            );
        }


        const previousUrl =
            history.lastUrl;


        history.lastUrl =
            url;


        /*
         * Browser-internal → web navigation
         * is normal browser navigation.
         */
        if (
            previousUrl &&
            isBrowserInternalUrl(
                previousUrl
            ) &&
            isWebUrl(url)
        ) {

            history.urls = [
                url
            ];

            return;
        }


        if (
            isBrowserInternalUrl(url)
        ) {
            return;
        }


        if (
            !isWebUrl(url)
        ) {
            return;
        }


        if (
            history.urls.length === 0 ||
            history.urls[
                history.urls.length - 1
            ] !== url
        ) {

            history.urls.push(
                url
            );
        }


        const qualifiers =
            Array.isArray(
                transitionQualifiers
            )
                ? transitionQualifiers
                : [];


        const serverRedirect =
            qualifiers.includes(
                "server_redirect"
            );


        const clientRedirect =
            qualifiers.includes(
                "client_redirect"
            );


        /*
         * Only record an actual browser
         * redirect transition.
         *
         * A normal hyperlink click is NOT
         * considered a redirect.
         */
        if (
            previousUrl &&
            previousUrl !== url &&
            (
                serverRedirect ||
                clientRedirect
            )
        ) {

            history.redirects.push({

                from:
                    previousUrl,

                to:
                    url,

                type:
                    serverRedirect
                        ? "server_redirect"
                        : "client_redirect",

                timestamp:
                    Date.now()

            });
        }
    }


    // =========================================================
    // GET RESULT
    // =========================================================

    function getRedirectResult(
        tabId
    ) {

        const history =
            navigationHistory.get(
                tabId
            );


        if (!history) {

            return {

                detected: false,

                count: 0,

                chain: [],

                redirects: []

            };
        }


        const redirects =
            Array.isArray(
                history.redirects
            )
                ? history.redirects
                : [];


        return {

            detected:
                redirects.length > 0,

            count:
                redirects.length,

            chain:
                redirects.map(
                    (redirect) => ({

                        from:
                            redirect.from,

                        to:
                            redirect.to

                    })
                ),

            redirects

        };
    }


    // =========================================================
    // CLEAR TAB
    // =========================================================

    function clearTab(
        tabId
    ) {

        navigationHistory.delete(
            tabId
        );
    }


    // =========================================================
    // EXPOSE API
    // =========================================================

    globalThis.PhishCatcher =
        globalThis.PhishCatcher || {};


    const redirectAPI = {

        startNavigation,

        recordNavigation,

        getRedirectResult,

        clearTab

    };


    globalThis.PhishCatcher.RedirectDetector =
        redirectAPI;


    globalThis.PhishCatcher.Redirect =
        redirectAPI;


})();