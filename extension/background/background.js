"use strict";

/*
 * ============================================================
 * NavShield Background Service Worker
 * ============================================================
 *
 * Responsibilities:
 * 1. Track redirects.
 * 2. Receive page features from content.js.
 * 3. Call FastAPI directly.
 * 4. Detect typosquatting independently.
 * 5. Make the final security decision.
 * 6. Store the result for popup.js.
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
 * CONFIGURATION
 * ============================================================ */

const API_BASE_URL =
    "http://127.0.0.1:8000/api";

const TYPOSQUATTING_THRESHOLD = 0.80;

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

const navigationState = new Map();
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

chrome.webNavigation.onBeforeNavigate.addListener(
    function (details) {
        if (details.frameId !== 0) {
            return;
        }

        const state =
            getNavigationState(
                details.tabId
            );

        state.pending = {
            from: state.currentUrl,
            to: details.url,
            timestamp: Date.now()
        };
    }
);


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

        if (isRedirect) {
            const from =
                state.pending &&
                state.pending.from
                    ? state.pending.from
                    : state.currentUrl;

            const to = details.url;

            if (
                from &&
                to &&
                from !== to
            ) {
                state.redirects.push({
                    from: from,
                    to: to,
                    type:
                        serverRedirect
                            ? "server_redirect"
                            : "client_redirect",
                    timestamp: Date.now()
                });
            }
        } else {
            state.redirects = [];
        }

        state.currentUrl =
            details.url;

        state.pending = null;
    }
);


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


chrome.tabs.onRemoved.addListener(
    function (tabId) {
        navigationState.delete(tabId);
        tabAnalysis.delete(tabId);
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
        matrix[i][0] = i;
    }

    for (
        let j = 0;
        j < columns;
        j++
    ) {
        matrix[0][j] = j;
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
                a[i - 1] ===
                b[j - 1]
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


function getDomainName(registeredDomain) {
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

    let difference = null;

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
                position: i,
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
            detected: false,
            score: 0,
            currentDomain: "",
            matchedDomain: null,
            similarity: 0,
            similarityPercentage: 0,
            reason: "Invalid hostname"
        };
    }

    const currentDomain =
        getRegisteredDomain(
            hostname
        );

    if (
        LEGITIMATE_DOMAINS.includes(
            currentDomain
        )
    ) {
        return {
            detected: false,
            score: 0,
            currentDomain:
                currentDomain,
            matchedDomain:
                currentDomain,
            similarity: 1,
            similarityPercentage: 100,
            reason:
                "Exact legitimate domain"
        };
    }

    const currentName =
        getDomainName(
            currentDomain
        );

    let bestMatch = null;

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
            detected: false,
            score: 0,
            currentDomain:
                currentDomain,
            matchedDomain: null,
            similarity: 0,
            similarityPercentage: 0,
            reason: "No match"
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

async function requestMLPrediction(
    url,
    features
) {
    const response =
        await fetch(
            `${API_BASE_URL}/predict`,
            {
                method: "POST",

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
            // Keep default message.
        }

        throw new Error(
            message
        );
    }

    return await response.json();
}


/* ============================================================
 * FINAL SECURITY DECISION
 * ============================================================ */

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

            mlPrediction:
                ml.prediction
        };
    }

    return {
        prediction:
            ml.prediction,

        probability:
            typeof ml.probability ===
            "number"
                ? ml.probability
                : 0,

        reason:
            "machine_learning",

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
    const tabId =
        sender &&
        sender.tab
            ? sender.tab.id
            : null;

    if (
        tabId === null ||
        tabId === undefined
    ) {
        return {
            ok: false,
            error:
                "No valid tab ID."
        };
    }

    const url =
        message.url ||
        (
            sender.tab &&
            sender.tab.url
                ? sender.tab.url
                : ""
        );

    if (
        isBrowserInternalUrl(url) ||
        !isWebUrl(url)
    ) {
        return {
            ok: false,
            error:
                "Unsupported page URL."
        };
    }

    const features =
        message.features || {};

    if (
        !features ||
        Object.keys(features).length === 0
    ) {
        console.error(
            "[NavShield] Received empty ML feature set."
        );

        return {
            ok: false,
            error:
                "Feature data cannot be empty."
        };
    }

    const typosquatting =
        detectTyposquatting(
            url
        );

    const security = {
        typosquatting:
            typosquatting
    };

    let mlPrediction;

    try {
        mlPrediction =
            await requestMLPrediction(
                url,
                features
            );
    } catch (error) {
        console.error(
            "[NavShield] ML prediction failed:",
            error
        );

        return {
            ok: false,
            error:
                error &&
                error.message
                    ? error.message
                    : "ML prediction failed."
        };
    }

    const finalPrediction =
        createFinalPrediction(
            mlPrediction,
            typosquatting
        );

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

    tabAnalysis.set(
        tabId,
        analysis
    );

    return {
        ok: true,
        analysis:
            analysis
    };
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
        if (!message) {
            return;
        }


        /* ----------------------------------------------------
         * PAGE ANALYSIS
         * ---------------------------------------------------- */

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
                        sendResponse(
                            result
                        );
                    }
                )
                .catch(
                    function (error) {
                        console.error(
                            "[NavShield] Page analysis error:",
                            error
                        );

                        sendResponse(
                            {
                                ok: false,
                                error:
                                    error &&
                                    error.message
                                        ? error.message
                                        : "Page analysis failed."
                            }
                        );
                    }
                );

            return true;
        }


        /* ----------------------------------------------------
         * CURRENT ANALYSIS
         *
         * IMPORTANT:
         * Popup sends tabId explicitly.
         * ---------------------------------------------------- */

        if (
            message.action ===
            "getCurrentAnalysis"
        ) {
            const tabId =
                Number.isInteger(
                    message.tabId
                )
                    ? message.tabId
                    : null;

            if (
                tabId === null
            ) {
                sendResponse(
                    {
                        ok: false,
                        analysis: null
                    }
                );

                return true;
            }

            sendResponse(
                {
                    ok: true,

                    analysis:
                        tabAnalysis.get(
                            tabId
                        ) || null
                }
            );

            return true;
        }


        /* ----------------------------------------------------
         * DIRECT PREDICTION
         * ---------------------------------------------------- */

        if (
            message.action ===
            "predict"
        ) {
            requestMLPrediction(
                message.url || "",
                message.features || {}
            )
                .then(
                    function (prediction) {
                        sendResponse(
                            {
                                ok: true,
                                prediction:
                                    prediction
                            }
                        );
                    }
                )
                .catch(
                    function (error) {
                        sendResponse(
                            {
                                ok: false,
                                error:
                                    error &&
                                    error.message
                                        ? error.message
                                        : "Prediction failed."
                            }
                        );
                    }
                );

            return true;
        }


        /* ----------------------------------------------------
         * BACKEND HEALTH
         * ---------------------------------------------------- */

        if (
            message.action ===
            "health"
        ) {
            fetch(
                `${API_BASE_URL}/health`
            )
                .then(
                    async function (
                        response
                    ) {
                        if (
                            !response.ok
                        ) {
                            throw new Error(
                                `Backend health check failed (${response.status}).`
                            );
                        }

                        return await response.json();
                    }
                )
                .then(
                    function (result) {
                        sendResponse(
                            {
                                ok: true,
                                result:
                                    result
                            }
                        );
                    }
                )
                .catch(
                    function (error) {
                        sendResponse(
                            {
                                ok: false,
                                error:
                                    error.message
                            }
                        );
                    }
                );

            return true;
        }


        /* ----------------------------------------------------
         * MODEL INFORMATION
         * ---------------------------------------------------- */

        if (
            message.action ===
            "modelInfo"
        ) {
            fetch(
                `${API_BASE_URL}/model-info`
            )
                .then(
                    async function (
                        response
                    ) {
                        if (
                            !response.ok
                        ) {
                            throw new Error(
                                `Model information request failed (${response.status}).`
                            );
                        }

                        return await response.json();
                    }
                )
                .then(
                    function (result) {
                        sendResponse(
                            {
                                ok: true,
                                result:
                                    result
                            }
                        );
                    }
                )
                .catch(
                    function (error) {
                        sendResponse(
                            {
                                ok: false,
                                error:
                                    error.message
                            }
                        );
                    }
                );

            return true;
        }


        /* ----------------------------------------------------
         * REDIRECT INFORMATION
         * ---------------------------------------------------- */

        if (
            message.action ===
            "getRedirectInfo"
        ) {
            const tabId =
                Number.isInteger(
                    message.tabId
                )
                    ? message.tabId
                    : null;

            if (
                tabId === null
            ) {
                sendResponse(
                    {
                        ok: false,
                        redirects: [],
                        count: 0
                    }
                );

                return true;
            }

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

            sendResponse(
                {
                    ok: true,

                    redirects:
                        redirects,

                    count:
                        redirects.length
                }
            );

            return true;
        }
    }
);