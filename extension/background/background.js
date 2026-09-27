"use strict";

/*
 * ============================================================
 * NavShield Background Service Worker
 * ============================================================
 *
 * Responsibilities:
 * 1. Track redirects.
 * 2. Integrate redirectDetector.js.
 * 3. Receive page features from content.js.
 * 4. Request ML prediction from the backend.
 * 5. Detect typosquatting independently.
 * 6. Combine ML + typosquatting results.
 * 7. Store the final analysis for popup.js.
 * 8. Provide backend health/model information.
 * 9. Allow phishing pages to be closed from the extension.
 *
 * Security rule:
 *
 *   Typosquatting detected
 *          ->
 *   FINAL = PHISHING
 *
 * Redirect alone does NOT mean phishing.
 * The destination page is analyzed separately.
 * ============================================================
 */


/* ============================================================
 * EXTENSION SERVICES
 * ============================================================ */

importScripts(
    "../services/api.js",
    "../detection/redirectDetector.js"
);


/*
 * Ensure the global namespace exists.
 */
globalThis.PhishCatcher =
    globalThis.PhishCatcher || {};

globalThis.PhishCatcher.Background =
    globalThis.PhishCatcher.Background || {};


/* ============================================================
 * CONFIGURATION
 * ============================================================ */

const API_BASE_URL =
    "http://127.0.0.1:8000/api";

const TYPOSQUATTING_THRESHOLD = 0.80;


/*
 * Domains treated as legitimate reference domains
 * for typosquatting detection.
 */
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


/* ============================================================
 * STATE
 * ============================================================ */

/*
 * Existing navigation state used by popup.js
 * and getRedirectInfo.
 */
const navigationState = new Map();


/*
 * Stores the latest complete analysis for every tab.
 *
 * Structure:
 *
 * tabAnalysis = {
 *     [tabId]: {
 *         url,
 *         features,
 *         security,
 *         prediction,
 *         finalPrediction,
 *         timestamp
 *     }
 * }
 */
const tabAnalysis = new Map();


/* ============================================================
 * URL HELPERS
 * ============================================================ */

function isWebUrl(url) {

    if (typeof url !== "string") {
        return false;
    }

    return (
        url.startsWith("http://") ||
        url.startsWith("https://")
    );
}


function isBrowserInternalUrl(url) {

    if (
        typeof url !== "string" ||
        url.length === 0
    ) {
        return true;
    }

    return (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("devtools://") ||
        url.startsWith("view-source:")
    );
}


/* ============================================================
 * NAVIGATION STATE
 * ============================================================ */

function getNavigationState(tabId) {

    let state =
        navigationState.get(tabId);

    if (!state) {

        state = {
            currentUrl: null,
            redirects: [],
            pending: null
        };

        navigationState.set(
            tabId,
            state
        );
    }

    return state;
}


/* ============================================================
 * REDIRECT TRACKING
 * ============================================================ */

/*
 * Start tracking a new top-level navigation.
 *
 * Both the existing redirect history and the new
 * redirectDetector module are updated.
 */
chrome.webNavigation.onBeforeNavigate.addListener(
    function (details) {

        if (details.frameId !== 0) {
            return;
        }


        /*
         * A new navigation invalidates the previous
         * analysis for this tab.
         */
        tabAnalysis.delete(
            details.tabId
        );


        /*
         * Existing navigation tracking.
         */
        const state =
            getNavigationState(
                details.tabId
            );

        state.pending = {
            from:
                state.currentUrl,

            to:
                details.url,

            timestamp:
                Date.now()
        };


        /*
         * New redirectDetector integration.
         */
        try {

            if (
                globalThis.PhishCatcher &&
                PhishCatcher.Redirect &&
                typeof PhishCatcher.Redirect
                    .startNavigation === "function"
            ) {

                PhishCatcher.Redirect.startNavigation(
                    details.tabId,
                    details.url
                );

            }

        } catch (error) {

            console.warn(
                "[NavShield] Redirect detector start failed:",
                error
            );
        }
    }
);


/*
 * Record completed navigation.
 *
 * Existing redirect history is maintained for popup.js.
 * redirectDetector.js is also notified.
 */
chrome.webNavigation.onCommitted.addListener(
    function (details) {

        if (details.frameId !== 0) {
            return;
        }


        const state =
            getNavigationState(
                details.tabId
            );


        const qualifiers =
            Array.isArray(
                details.transitionQualifiers
            )
                ? details.transitionQualifiers
                : [];


        const serverRedirect =
            qualifiers.includes(
                "server_redirect"
            );


        const clientRedirect =
            qualifiers.includes(
                "client_redirect"
            );


        const isRedirect =
            serverRedirect ||
            clientRedirect;


        /*
         * Preserve existing redirect history.
         */
        if (isRedirect) {

            const from =
                state.pending &&
                state.pending.from
                    ? state.pending.from
                    : state.currentUrl;


            const to =
                details.url;


            if (
                from &&
                to &&
                from !== to
            ) {

                state.redirects.push({

                    from:
                        from,

                    to:
                        to,

                    type:
                        serverRedirect
                            ? "server_redirect"
                            : "client_redirect",

                    timestamp:
                        Date.now()
                });
            }

        } else {

            /*
             * A normal navigation starts a fresh
             * redirect chain.
             */
            state.redirects = [];
        }


        state.currentUrl =
            details.url;

        state.pending = null;


        /*
         * New redirectDetector integration.
         */
        try {

            if (
                globalThis.PhishCatcher &&
                PhishCatcher.Redirect &&
                typeof PhishCatcher.Redirect
                    .recordNavigation === "function"
            ) {

                PhishCatcher.Redirect.recordNavigation(
                    details.tabId,
                    details.url,
                    qualifiers
                );


                const result =
                    PhishCatcher.Redirect
                        .getRedirectResult(
                            details.tabId
                        );


                console.log(
                    "[NavShield] Redirect detector result:",
                    result
                );
            }

        } catch (error) {

            console.warn(
                "[NavShield] Redirect detector failed:",
                error
            );
        }
    }
);


/*
 * Clear pending navigation when navigation fails.
 */
chrome.webNavigation.onErrorOccurred.addListener(
    function (details) {

        if (details.frameId !== 0) {
            return;
        }


        const state =
            getNavigationState(
                details.tabId
            );


        state.pending = null;
    }
);


/*
 * Clean up state when a tab is closed.
 */
chrome.tabs.onRemoved.addListener(
    function (tabId) {

        navigationState.delete(
            tabId
        );


        tabAnalysis.delete(
            tabId
        );


        try {

            if (
                globalThis.PhishCatcher &&
                PhishCatcher.Redirect &&
                typeof PhishCatcher.Redirect
                    .clearTab === "function"
            ) {

                PhishCatcher.Redirect.clearTab(
                    tabId
                );
            }

        } catch (error) {

            console.warn(
                "[NavShield] Failed to clear redirect state:",
                error
            );
        }
    }
);


/* ============================================================
 * LEVENSHTEIN DISTANCE
 * ============================================================ */

function levenshtein(a, b) {

    const rows =
        a.length + 1;

    const columns =
        b.length + 1;


    const matrix =
        Array.from(
            { length: rows },
            function () {

                return new Array(
                    columns
                ).fill(0);

            }
        );


    for (
        let i = 0;
        i < rows;
        i++
    ) {

        matrix[i][0] =
            i;
    }


    for (
        let j = 0;
        j < columns;
        j++
    ) {

        matrix[0][j] =
            j;
    }


    for (
        let i = 1;
        i < rows;
        i++
    ) {

        for (
            let j = 1;
            j < columns;
            j++
        ) {

            const cost =
                a[i - 1] === b[j - 1]
                    ? 0
                    : 1;


            matrix[i][j] =
                Math.min(

                    matrix[i - 1][j] + 1,

                    matrix[i][j - 1] + 1,

                    matrix[i - 1][j - 1] +
                        cost

                );
        }
    }


    return matrix[
        rows - 1
    ][
        columns - 1
    ];
}


/* ============================================================
 * STRING SIMILARITY
 * ============================================================ */

function similarity(a, b) {

    if (!a || !b) {
        return 0;
    }


    const maximum =
        Math.max(
            a.length,
            b.length
        );


    if (maximum === 0) {
        return 1;
    }


    const distance =
        levenshtein(
            a,
            b
        );


    return (
        1 -
        distance / maximum
    );
}


/* ============================================================
 * LOOK-ALIKE NORMALIZATION
 * ============================================================ */

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


/* ============================================================
 * DOMAIN EXTRACTION
 * ============================================================ */

function getHostname(url) {

    try {

        return new URL(
            url
        ).hostname.toLowerCase();

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


    return parts
        .slice(-2)
        .join(".");
}


function getDomainName(
    registeredDomain
) {

    const parts =
        registeredDomain
            .split(".")
            .filter(Boolean);


    if (parts.length < 2) {
        return registeredDomain;
    }


    return parts[
        parts.length - 2
    ];
}


/* ============================================================
 * SINGLE CHARACTER SUBSTITUTION
 * ============================================================ */

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


    let difference =
        null;


    for (
        let i = 0;
        i < currentName.length;
        i++
    ) {

        if (
            currentName[i] !==
            legitimateName[i]
        ) {

            if (difference) {
                return null;
            }


            difference = {

                position:
                    i,

                current:
                    currentName[i],

                legitimate:
                    legitimateName[i]

            };
        }
    }


    return difference;
}


/* ============================================================
 * TYPOSQUATTING DETECTION
 * ============================================================ */

function detectTyposquatting(url) {

    const hostname =
        getHostname(url);


    if (!hostname) {

        return {

            detected:
                false,

            score:
                0,

            currentDomain:
                "",

            matchedDomain:
                null,

            similarity:
                0,

            similarityPercentage:
                0,

            reason:
                "Invalid hostname"

        };
    }


    const currentDomain =
        getRegisteredDomain(
            hostname
        );


    /*
     * Exact legitimate domains are NOT phishing.
     */
    if (
        LEGITIMATE_DOMAINS.includes(
            currentDomain
        )
    ) {

        return {

            detected:
                false,

            score:
                0,

            currentDomain:
                currentDomain,

            matchedDomain:
                currentDomain,

            similarity:
                1,

            similarityPercentage:
                100,

            reason:
                "Exact legitimate domain"

        };
    }


    const currentName =
        getDomainName(
            currentDomain
        );


    let bestMatch =
        null;


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


        let score =
            Math.max(
                rawSimilarity,
                normalizedSimilarity
            );


        /*
         * Strong single-character substitution.
         */
        if (substitution) {

            score =
                Math.max(
                    score,
                    0.90
                );
        }


        if (
            !bestMatch ||
            score >
                bestMatch.score
        ) {

            bestMatch = {

                domain:
                    legitimateDomain,

                score:
                    score,

                rawSimilarity:
                    rawSimilarity,

                normalizedSimilarity:
                    normalizedSimilarity,

                substitution:
                    substitution

            };
        }
    }


    if (!bestMatch) {

        return {

            detected:
                false,

            score:
                0,

            currentDomain:
                currentDomain,

            matchedDomain:
                null,

            similarity:
                0,

            similarityPercentage:
                0,

            reason:
                "No match"

        };
    }


    const detected =
        bestMatch.score >=
        TYPOSQUATTING_THRESHOLD;


    let reason =
        "No strong similarity";


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
                "Look-alike character similarity";

        } else {

            reason =
                "High domain similarity";
        }
    }


    return {

        detected:
            detected,

        score:
            bestMatch.score,

        currentDomain:
            currentDomain,

        matchedDomain:
            bestMatch.domain,

        similarity:
            bestMatch.score,

        similarityPercentage:
            Math.round(
                bestMatch.score * 100
            ),

        rawSimilarity:
            bestMatch.rawSimilarity,

        normalizedSimilarity:
            bestMatch.normalizedSimilarity,

        characterSubstitution:
            bestMatch.substitution,

        reason:
            reason
    };
}


/* ============================================================
 * BACKEND ML PREDICTION
 * ============================================================ */

/*
 * Direct FastAPI implementation retained from your version.
 *
 * This acts as a fallback when the newer Services layer
 * is unavailable.
 */
async function requestMLPrediction(
    url,
    features
) {

    const response =
        await fetch(
            `${API_BASE_URL}/predict`,
            {

                method:
                    "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body:
                    JSON.stringify({

                        url:
                            url,

                        features:
                            features || {}

                    })
            }
        );


    if (!response.ok) {

        let message =
            `Backend request failed (${response.status}).`;


        try {

            const data =
                await response.json();


            if (
                data &&
                data.detail
            ) {

                message =
                    data.detail;
            }

        } catch {

            /*
             * Keep default error message.
             */
        }


        throw new Error(
            message
        );
    }


    return await response.json();
}


/*
 * Use the newer Services API when available.
 * Otherwise use the original direct FastAPI call.
 */
async function requestPrediction(
    url,
    features
) {

    try {

        if (
            globalThis.PhishCatcher &&
            PhishCatcher.Services &&
            typeof PhishCatcher.Services
                .requestPrediction === "function"
        ) {

            return await PhishCatcher.Services
                .requestPrediction(
                    url,
                    features
                );
        }

    } catch (error) {

        /*
         * Do not immediately hide a genuine backend error.
         *
         * Re-throwing here preserves the behavior of the
         * Services implementation.
         */
        throw error;
    }


    return await requestMLPrediction(
        url,
        features
    );
}


/* ============================================================
 * FINAL SECURITY DECISION
 * ============================================================ */

/*
 * Combines ML prediction and typosquatting detection.
 *
 * IMPORTANT:
 *
 * If typosquatting is detected,
 * final prediction becomes phishing.
 */
function createFinalPrediction(
    mlPrediction,
    typosquatting
) {

    const ml =
        mlPrediction || {
            prediction:
                "legitimate",

            probability:
                0
        };


    if (
        typosquatting &&
        typosquatting.detected === true
    ) {

        /*
         * Friend's implementation uses the ML probability
         * while changing the final class to phishing.
         *
         * This preserves that behavior.
         */
        return {

            prediction:
                "phishing",

            probability:
                typeof ml.probability ===
                "number"
                    ? ml.probability
                    : 0,

            reason:
                "typosquatting_override",

            source:
                "typosquatting",

            mlPrediction:
                ml.prediction,

            typosquatting:
                typosquatting
        };
    }


    /*
     * Preserve the ML result for non-typosquatting pages.
     */
    return {

        ...ml,

        prediction:
            ml.prediction,

        probability:
            typeof ml.probability ===
            "number"
                ? ml.probability
                : 0,

        reason:
            "machine_learning",

        source:
            ml.source ||
            "machine-learning",

        mlPrediction:
            ml.prediction
    };
}


/* ============================================================
 * PAGE ANALYSIS
 * ============================================================ */

async function handlePageAnalysis(
    message,
    sender
) {

    /*
     * Determine tab ID.
     *
     * sender.tab is preferred because pageAnalysis
     * normally originates from content.js.
     *
     * message.tabId is retained as a fallback.
     */
    const tabId =
        sender &&
        sender.tab &&
        typeof sender.tab.id === "number"
            ? sender.tab.id
            : (
                typeof message.tabId === "number"
                    ? message.tabId
                    : null
            );


    if (
        tabId === null ||
        tabId === undefined
    ) {

        throw new Error(
            "No valid tab ID."
        );
    }


    /*
     * Determine URL.
     */
    const url =
        typeof message.url === "string" &&
        message.url.trim() !== ""
            ? message.url
            : (
                sender &&
                sender.tab &&
                typeof sender.tab.url === "string"
                    ? sender.tab.url
                    : ""
            );


    /*
     * Do not analyze browser internal pages.
     */
    if (
        isBrowserInternalUrl(url) ||
        !isWebUrl(url)
    ) {

        throw new Error(
            "Unsupported page URL."
        );
    }


    const features =
        message.features;


    if (
        !features ||
        typeof features !== "object" ||
        Object.keys(features).length === 0
    ) {

        throw new Error(
            "Feature data cannot be empty."
        );
    }


    /*
     * --------------------------------------------------------
     * TYPOSQUATTING DETECTION
     * --------------------------------------------------------
     *
     * Performed independently of the ML model.
     */
    let typosquattingResult;


    try {

        /*
         * If a dedicated Typosquatting service exists,
         * use it first.
         *
         * Otherwise use the existing inline detector.
         */
        if (
            globalThis.PhishCatcher &&
            PhishCatcher.Typosquatting &&
            typeof PhishCatcher.Typosquatting
                .detect === "function"
        ) {

            typosquattingResult =
                PhishCatcher.Typosquatting.detect(
                    url
                );

        } else {

            typosquattingResult =
                detectTyposquatting(
                    url
                );
        }

    } catch (error) {

        console.warn(
            "[NavShield] Typosquatting detection failed. Falling back to built-in detector:",
            error
        );


        typosquattingResult =
            detectTyposquatting(
                url
            );
    }


    /*
     * --------------------------------------------------------
     * SECURITY INFORMATION
     * --------------------------------------------------------
     */
    const security = {

        typosquatting:
            typosquattingResult

    };


    /*
     * --------------------------------------------------------
     * ML PREDICTION
     * --------------------------------------------------------
     */
    let mlPrediction;


    try {

        mlPrediction =
            await requestPrediction(
                url,
                features
            );

    } catch (error) {

        console.error(
            "[NavShield] ML prediction failed:",
            error
        );


        throw new Error(
            error &&
            error.message
                ? error.message
                : "ML prediction failed."
        );
    }


    /*
     * --------------------------------------------------------
     * FINAL PREDICTION
     * --------------------------------------------------------
     */
    const finalPrediction =
        createFinalPrediction(
            mlPrediction,
            typosquattingResult
        );


    /*
     * --------------------------------------------------------
     * COMPLETE ANALYSIS OBJECT
     * --------------------------------------------------------
     */
    const analysis = {

        url:
            url,

        features:
            features,

        security:
            security,

        prediction:
            mlPrediction,

        finalPrediction:
            finalPrediction,

        timestamp:
            Date.now()
    };


    /*
     * --------------------------------------------------------
     * STORE ANALYSIS
     * --------------------------------------------------------
     */
    tabAnalysis.set(
        tabId,
        analysis
    );


    console.log(
        "[NavShield] Analysis stored for tab:",
        tabId,
        analysis
    );


    return {

        ok:
            true,

        analysis:
            analysis
    };
}


/* ============================================================
 * BACKEND HEALTH
 * ============================================================ */

async function handleHealthCheck() {

    /*
     * Prefer the newer service implementation.
     */
    if (
        globalThis.PhishCatcher &&
        PhishCatcher.Services &&
        typeof PhishCatcher.Services
            .checkBackendHealth === "function"
    ) {

        return await PhishCatcher.Services
            .checkBackendHealth();
    }


    /*
     * Fallback to direct FastAPI call.
     */
    const response =
        await fetch(
            `${API_BASE_URL}/health`
        );


    if (!response.ok) {

        throw new Error(
            `Backend health check failed (${response.status}).`
        );
    }


    return await response.json();
}


/* ============================================================
 * MODEL INFORMATION
 * ============================================================ */

async function handleModelInfo() {

    /*
     * Prefer the newer service implementation.
     */
    if (
        globalThis.PhishCatcher &&
        PhishCatcher.Services &&
        typeof PhishCatcher.Services
            .getModelInfo === "function"
    ) {

        return await PhishCatcher.Services
            .getModelInfo();
    }


    /*
     * Fallback to direct FastAPI call.
     */
    const response =
        await fetch(
            `${API_BASE_URL}/model-info`
        );


    if (!response.ok) {

        throw new Error(
            `Model information request failed (${response.status}).`
        );
    }


    return await response.json();
}


/* ============================================================
 * MESSAGE HANDLING
 * ============================================================ */

chrome.runtime.onMessage.addListener(
    function (
        message,
        sender,
        sendResponse
    ) {

        if (
            !message ||
            typeof message.action !== "string"
        ) {

            return false;
        }


        /* ====================================================
         * PAGE ANALYSIS
         * ==================================================== */

        if (
            message.action ===
            "pageAnalysis"
        ) {

            handlePageAnalysis(
                message,
                sender
            )
                .then(
                    function (result) {

                        console.log(
                            "[NavShield] Page analysis completed:",
                            result
                        );


                        sendResponse(
                            result
                        );
                    }
                )
                .catch(
                    function (error) {

                        console.error(
                            "[NavShield] Page analysis failed:",
                            error
                        );


                        sendResponse({

                            ok:
                                false,

                            error:
                                error &&
                                error.message
                                    ? error.message
                                    : "Page analysis failed."

                        });
                    }
                );


            /*
             * Required because response is asynchronous.
             */
            return true;
        }


        /* ====================================================
         * GET CURRENT ANALYSIS
         * ==================================================== */

        if (
            message.action ===
            "getCurrentAnalysis"
        ) {

            try {

                /*
                 * Support both:
                 *
                 * 1. sender.tab.id
                 * 2. explicitly supplied message.tabId
                 *
                 * This keeps compatibility with both versions.
                 */
                const tabId =
                    sender &&
                    sender.tab &&
                    typeof sender.tab.id === "number"
                        ? sender.tab.id
                        : (
                            Number.isInteger(
                                message.tabId
                            )
                                ? message.tabId
                                : null
                        );


                if (
                    tabId === null
                ) {

                    throw new Error(
                        "Tab ID is missing."
                    );
                }


                const analysis =
                    tabAnalysis.get(
                        tabId
                    );


                sendResponse({

                    ok:
                        true,

                    analysis:
                        analysis || null

                });

            } catch (error) {

                sendResponse({

                    ok:
                        false,

                    analysis:
                        null,

                    error:
                        error.message ||
                        "Unable to get current analysis."

                });
            }


            return true;
        }


        /* ====================================================
         * DIRECT ML PREDICTION
         * ==================================================== */

        if (
            message.action ===
            "predict"
        ) {

            requestPrediction(
                message.url || "",
                message.features || {}
            )
                .then(
                    function (prediction) {

                        /*
                         * Return both common response styles
                         * so existing popup/UI code is less
                         * likely to break.
                         */
                        sendResponse({

                            success:
                                true,

                            ok:
                                true,

                            data:
                                prediction,

                            prediction:
                                prediction

                        });
                    }
                )
                .catch(
                    function (error) {

                        sendResponse({

                            success:
                                false,

                            ok:
                                false,

                            error:
                                error &&
                                error.message
                                    ? error.message
                                    : "Prediction failed."

                        });
                    }
                );


            return true;
        }


        /* ====================================================
         * BACKEND HEALTH
         * ==================================================== */

        if (
            message.action ===
            "health"
        ) {

            handleHealthCheck()
                .then(
                    function (result) {

                        sendResponse({

                            success:
                                true,

                            ok:
                                true,

                            data:
                                result,

                            result:
                                result

                        });
                    }
                )
                .catch(
                    function (error) {

                        sendResponse({

                            success:
                                false,

                            ok:
                                false,

                            error:
                                error &&
                                error.message
                                    ? error.message
                                    : "Backend health check failed."

                        });
                    }
                );


            return true;
        }


        /* ====================================================
         * MODEL INFORMATION
         * ==================================================== */

        if (
            message.action ===
            "modelInfo"
        ) {

            handleModelInfo()
                .then(
                    function (result) {

                        sendResponse({

                            success:
                                true,

                            ok:
                                true,

                            data:
                                result,

                            result:
                                result

                        });
                    }
                )
                .catch(
                    function (error) {

                        sendResponse({

                            success:
                                false,

                            ok:
                                false,

                            error:
                                error &&
                                error.message
                                    ? error.message
                                    : "Model information request failed."

                        });
                    }
                );


            return true;
        }


        /* ====================================================
         * REDIRECT INFORMATION
         * ==================================================== */

        if (
            message.action ===
            "getRedirectInfo"
        ) {

            const tabId =
                Number.isInteger(
                    message.tabId
                )
                    ? message.tabId
                    : (
                        sender &&
                        sender.tab &&
                        Number.isInteger(
                            sender.tab.id
                        )
                            ? sender.tab.id
                            : null
                    );


            if (
                tabId === null
            ) {

                sendResponse({

                    ok:
                        false,

                    redirects:
                        [],

                    count:
                        0

                });


                return true;
            }


            /*
             * Preserve the original popup-compatible
             * redirect history.
             */
            const state =
                navigationState.get(
                    tabId
                );


            const redirects =
                state &&
                Array.isArray(
                    state.redirects
                )
                    ? state.redirects
                    : [];


            sendResponse({

                ok:
                    true,

                redirects:
                    redirects,

                count:
                    redirects.length

            });


            return true;
        }


        /* ====================================================
         * REDIRECT DETECTOR INFORMATION
         * ==================================================== */

        if (
            message.action ===
            "getRedirectDetectorInfo"
        ) {

            try {

                const tabId =
                    sender &&
                    sender.tab &&
                    typeof sender.tab.id === "number"
                        ? sender.tab.id
                        : (
                            Number.isInteger(
                                message.tabId
                            )
                                ? message.tabId
                                : null
                        );


                if (
                    tabId === null
                ) {

                    throw new Error(
                        "Tab ID is missing."
                    );
                }


                if (
                    globalThis.PhishCatcher &&
                    PhishCatcher.Redirect &&
                    typeof PhishCatcher.Redirect
                        .getRedirectResult === "function"
                ) {

                    const result =
                        PhishCatcher.Redirect
                            .getRedirectResult(
                                tabId
                            );


                    sendResponse({

                        success:
                            true,

                        ok:
                            true,

                        data:
                            result

                    });

                } else {

                    sendResponse({

                        success:
                            true,

                        ok:
                            true,

                        data:
                            null

                    });
                }

            } catch (error) {

                sendResponse({

                    success:
                        false,

                    ok:
                        false,

                    error:
                        error.message ||
                        "Unable to get redirect detector information."

                });
            }


            return true;
        }


        /* ====================================================
         * EXIT PHISHING PAGE
         * ==================================================== */

        if (
            message.action ===
            "exitPhishingPage"
        ) {

            const tabId =
                sender &&
                sender.tab &&
                typeof sender.tab.id === "number"
                    ? sender.tab.id
                    : (
                        Number.isInteger(
                            message.tabId
                        )
                            ? message.tabId
                            : null
                    );


            if (
                typeof tabId === "number"
            ) {

                chrome.tabs.remove(
                    tabId
                )
                    .catch(
                        function (error) {

                            console.warn(
                                "[NavShield] Unable to close phishing tab:",
                                error
                            );
                        }
                    );
            }


            return false;
        }


        /*
         * Unknown action.
         */
        return false;
    }
);


/* ============================================================
 * SERVICE WORKER STARTUP
 * ============================================================ */

console.log(
    "[NavShield] Background service worker started."
);