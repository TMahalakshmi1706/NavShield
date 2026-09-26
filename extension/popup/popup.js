(function () {
    "use strict";

    const statusElement =
        document.getElementById("status");

    const resultElement =
        document.getElementById("result");

    const urlElement =
        document.getElementById("url");

    const probabilityElement =
        document.getElementById("probability");

    const typosquattingElement =
        document.getElementById(
            "typosquatting"
        );

    const redirectElement =
        document.getElementById(
            "redirect"
        );

    const redirectChainElement =
        document.getElementById(
            "redirect-chain"
        );


    // =======================================================
    // UI HELPERS
    // =======================================================

    function setText(
        element,
        value
    ) {
        if (element) {
            element.textContent =
                value;
        }
    }


    function setStatus(message) {
        setText(
            statusElement,
            message
        );
    }


    // =======================================================
    // CURRENT TAB
    // =======================================================

    function getCurrentTab() {
        return new Promise(
            function (resolve) {
                chrome.tabs.query(
                    {
                        active: true,
                        currentWindow: true
                    },
                    function (tabs) {
                        if (
                            chrome.runtime
                                .lastError
                        ) {
                            resolve(null);
                            return;
                        }

                        resolve(
                            tabs &&
                            tabs.length
                                ? tabs[0]
                                : null
                        );
                    }
                );
            }
        );
    }


    // =======================================================
    // GET CURRENT ANALYSIS
    // =======================================================

    function getCurrentAnalysis(
        tabId
    ) {
        return new Promise(
            function (resolve) {
                chrome.runtime.sendMessage(
                    {
                        action:
                            "getCurrentAnalysis",

                        tabId:
                            tabId
                    },
                    function (response) {
                        if (
                            chrome.runtime
                                .lastError
                        ) {
                            resolve(null);
                            return;
                        }

                        if (
                            response &&
                            response.ok
                        ) {
                            resolve(
                                response.analysis ||
                                null
                            );

                            return;
                        }

                        resolve(null);
                    }
                );
            }
        );
    }


    // =======================================================
    // GET REDIRECT INFORMATION
    // =======================================================

    function getRedirectInfo(
        tabId
    ) {
        return new Promise(
            function (resolve) {
                chrome.runtime.sendMessage(
                    {
                        action:
                            "getRedirectInfo",

                        tabId:
                            tabId
                    },
                    function (response) {
                        if (
                            chrome.runtime
                                .lastError
                        ) {
                            resolve(null);
                            return;
                        }

                        resolve(
                            response || null
                        );
                    }
                );
            }
        );
    }


    // =======================================================
    // DISPLAY FINAL RESULT
    // =======================================================

    function displayFinalResult(
        analysis
    ) {
        if (!analysis) {
            setText(
                resultElement,
                "Unavailable"
            );

            return;
        }

        const finalPrediction =
            analysis.finalPrediction ||
            analysis.prediction;

        const finalValue =
            finalPrediction &&
            finalPrediction.prediction
                ? String(
                    finalPrediction.prediction
                ).toLowerCase()
                : "";

        if (
            finalValue ===
            "phishing"
        ) {
            setText(
                resultElement,
                "Phishing"
            );

            return;
        }

        if (
            finalValue ===
            "legitimate"
        ) {
            setText(
                resultElement,
                "Legitimate"
            );

            return;
        }

        setText(
            resultElement,
            "Unknown"
        );
    }


    // =======================================================
    // DISPLAY ML PROBABILITY
    // =======================================================

    function displayMLProbability(
        analysis
    ) {
        if (!analysis) {
            setText(
                probabilityElement,
                "Unavailable"
            );

            return;
        }

        const prediction =
            analysis.prediction;

        if (
            prediction &&
            typeof prediction.probability ===
                "number"
        ) {
            setText(
                probabilityElement,
                (
                    prediction.probability *
                    100
                ).toFixed(2) +
                "%"
            );

            return;
        }

        setText(
            probabilityElement,
            "Unavailable"
        );
    }


    // =======================================================
    // DISPLAY TYPOSQUATTING
    // =======================================================

    function displayTyposquatting(
        analysis
    ) {
        if (!analysis) {
            setText(
                typosquattingElement,
                "Unavailable"
            );

            return;
        }

        const typo =
            analysis.security &&
            analysis.security.typosquatting
                ? analysis.security.typosquatting
                : null;

        if (
            typo &&
            typo.detected === true
        ) {
            const percentage =
                typeof typo.similarityPercentage ===
                    "number"
                    ? typo.similarityPercentage
                    : Math.round(
                        (
                            typo.score ||
                            0
                        ) * 100
                    );

            let text =
                "Detected (" +
                percentage +
                "%)";

            if (
                typo.matchedDomain
            ) {
                text +=
                    " - resembles " +
                    typo.matchedDomain;
            }

            setText(
                typosquattingElement,
                text
            );

            return;
        }

        setText(
            typosquattingElement,
            "Not detected"
        );
    }


    // =======================================================
    // DISPLAY REDIRECTS
    // =======================================================

    function displayRedirects(
        redirectInfo
    ) {
        if (!redirectInfo) {
            setText(
                redirectElement,
                "Unavailable"
            );

            setText(
                redirectChainElement,
                "Unavailable"
            );

            return;
        }

        const redirects =
            Array.isArray(
                redirectInfo.redirects
            )
                ? redirectInfo.redirects
                : [];

        if (
            redirects.length === 0
        ) {
            setText(
                redirectElement,
                "None"
            );

            setText(
                redirectChainElement,
                "None"
            );

            return;
        }

        setText(
            redirectElement,
            "Detected (" +
            redirects.length +
            ")"
        );

        const chain =
            redirects
                .map(function (item) {
                    return (
                        item.from +
                        " → " +
                        item.to
                    );
                })
                .join("\n");

        setText(
            redirectChainElement,
            chain
        );
    }


    // =======================================================
    // WAIT FOR CURRENT PAGE ANALYSIS
    // =======================================================

    async function waitForCurrentAnalysis(
        tabId,
        currentUrl
    ) {
        /*
         * Wait for the background to receive and finish
         * processing the content-script analysis for the
         * CURRENT URL.
         */

        for (
            let attempt = 0;
            attempt < 12;
            attempt++
        ) {
            const analysis =
                await getCurrentAnalysis(
                    tabId
                );

            if (
                analysis &&
                analysis.url ===
                    currentUrl
            ) {
                return analysis;
            }

            await new Promise(
                function (resolve) {
                    setTimeout(
                        resolve,
                        250
                    );
                }
            );
        }

        return null;
    }


    // =======================================================
    // ASK CONTENT SCRIPT TO ANALYZE CURRENT PAGE
    // =======================================================

    function requestPageAnalysis(
        tabId
    ) {
        return new Promise(
            function (resolve) {
                chrome.tabs.sendMessage(
                    tabId,
                    {
                        action:
                            "analyzeCurrentPage"
                    },
                    function (response) {
                        if (
                            chrome.runtime
                                .lastError
                        ) {
                            resolve(null);
                            return;
                        }

                        resolve(
                            response || null
                        );
                    }
                );
            }
        );
    }


    // =======================================================
    // MAIN
    // =======================================================

    async function initialize() {
        setStatus(
            "Analyzing..."
        );

        const tab =
            await getCurrentTab();

        if (
            !tab ||
            !tab.id ||
            !tab.url
        ) {
            setStatus(
                "No active page"
            );

            return;
        }

        const tabId =
            tab.id;

        const currentUrl =
            tab.url;

        setText(
            urlElement,
            currentUrl
        );


        // ---------------------------------------------------
        // Browser internal pages
        // ---------------------------------------------------

        if (
            currentUrl.startsWith(
                "chrome://"
            ) ||
            currentUrl.startsWith(
                "chrome-extension://"
            ) ||
            currentUrl.startsWith(
                "edge://"
            ) ||
            currentUrl.startsWith(
                "about:"
            )
        ) {
            setStatus(
                "Page cannot be analyzed"
            );

            setText(
                resultElement,
                "Unavailable"
            );

            setText(
                probabilityElement,
                "Unavailable"
            );

            setText(
                typosquattingElement,
                "Unavailable"
            );

            setText(
                redirectElement,
                "Unavailable"
            );

            return;
        }


        // ---------------------------------------------------
        // First try the stored analysis.
        // ---------------------------------------------------

        let analysis =
            await getCurrentAnalysis(
                tabId
            );


        /*
         * Only accept the stored result if it belongs
         * to the current URL.
         */
        if (
            analysis &&
            analysis.url !==
                currentUrl
        ) {
            analysis = null;
        }


        // ---------------------------------------------------
        // If no current result exists, ask content.js.
        // ---------------------------------------------------

        if (!analysis) {
            await requestPageAnalysis(
                tabId
            );

            /*
             * content.js sends the page analysis to the
             * background asynchronously. Wait for the
             * background to finish ML prediction.
             */
            analysis =
                await waitForCurrentAnalysis(
                    tabId,
                    currentUrl
                );
        }


        // ---------------------------------------------------
        // Display final analysis.
        // ---------------------------------------------------

        displayFinalResult(
            analysis
        );

        displayMLProbability(
            analysis
        );

        displayTyposquatting(
            analysis
        );


        // ---------------------------------------------------
        // Redirect information.
        // ---------------------------------------------------

        const redirectInfo =
            await getRedirectInfo(
                tabId
            );

        displayRedirects(
            redirectInfo
        );


        // ---------------------------------------------------
        // Final status.
        // ---------------------------------------------------

        if (analysis) {
            setStatus(
                "Analysis complete"
            );
        } else {
            setStatus(
                "Analysis unavailable"
            );
        }
    }


    // =======================================================
    // START
    // =======================================================

    document.addEventListener(
        "DOMContentLoaded",
        function () {
            initialize();
        }
    );

})();