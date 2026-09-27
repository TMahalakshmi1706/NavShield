(function () {
    "use strict";

    /*
     * =========================================================
     * NavShield Content Script
     * =========================================================
     *
     * Responsibilities:
     *
     * 1. Collect the ML features required by the
     *    Random Forest model.
     *
     * 2. Collect additional domain, entropy and
     *    keyword information.
     *
     * 3. Perform local typosquatting analysis.
     *
     * 4. Send the complete page analysis to background.js.
     *
     * 5. Receive the final security decision from
     *    background.js.
     *
     * 6. Automatically display a phishing warning when
     *    the final decision is phishing.
     *
     * IMPORTANT:
     *
     * Typosquatting is NOT included in the ML feature vector.
     * The final security decision is made by background.js.
     * =========================================================
     */


    /* =========================================================
     * CONFIGURATION
     * ========================================================= */

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


    /* =========================================================
     * PHISHING WARNING OVERLAY STATE
     * ========================================================= */

    let navShieldOverlay = null;


    /* =========================================================
     * HTML ESCAPING
     * ========================================================= */

    function escapeHTML(value) {

        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    /* =========================================================
     * WARNING OVERLAY STYLES
     * ========================================================= */

    function injectNavShieldStyles() {

        if (
            document.getElementById(
                "navshield-warning-styles"
            )
        ) {
            return;
        }


        const style =
            document.createElement("style");


        style.id =
            "navshield-warning-styles";


        const backgroundImage =
            chrome.runtime.getURL(
                "assets/navshield-danger-bg.png"
            );


        style.textContent = `

            /* =================================================
               FULL SCREEN NAVSHIELD WARNING
               ================================================= */

            #navshield-warning-overlay {

                position: fixed;

                inset: 0;

                width: 100vw;
                height: 100vh;

                z-index: 2147483647;

                display: flex;

                align-items: center;
                justify-content: center;

                padding: 28px;

                box-sizing: border-box;

                overflow: auto;

                background-image:
                    linear-gradient(
                        rgba(5, 0, 0, 0.68),
                        rgba(5, 0, 0, 0.78)
                    ),
                    url("${backgroundImage}");

                background-size: cover;

                background-position: center;

                background-repeat: no-repeat;

                backdrop-filter:
                    blur(10px);

                -webkit-backdrop-filter:
                    blur(10px);

                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;

                color:
                    #ffffff;
            }


            /* =================================================
               DARK RED VIGNETTE
               ================================================= */

            #navshield-warning-overlay::before {

                content: "";

                position: absolute;

                inset: 0;

                pointer-events: none;

                background:
                    radial-gradient(
                        circle at center,
                        transparent 20%,
                        rgba(0, 0, 0, 0.42) 75%,
                        rgba(0, 0, 0, 0.78) 100%
                    );
            }


            /* =================================================
               WARNING CARD
               ================================================= */

            #navshield-warning-card {

                position: relative;

                z-index: 2;

                width:
                    min(650px, 100%);

                max-height:
                    calc(100vh - 56px);

                overflow-y:
                    auto;

                box-sizing:
                    border-box;

                padding:
                    38px 42px 34px;

                border-radius:
                    18px;

                background:
                    linear-gradient(
                        145deg,
                        rgba(12, 12, 12, 0.96),
                        rgba(20, 20, 20, 0.94)
                    );

                border:
                    2px solid
                    rgba(239, 68, 68, 0.85);

                box-shadow:
                    0 0 0 1px
                    rgba(255, 0, 0, 0.15),

                    0 0 35px
                    rgba(220, 38, 38, 0.35),

                    0 25px 80px
                    rgba(0, 0, 0, 0.85);

                text-align:
                    center;

                animation:
                    navshield-card-in
                    0.3s ease-out;
            }


            @keyframes navshield-card-in {

                from {
                    opacity: 0;
                    transform: scale(0.96);
                }

                to {
                    opacity: 1;
                    transform: scale(1);
                }
            }


            /* =================================================
               WARNING ICON
               ================================================= */

            .navshield-warning-icon {

                width:
                    70px;

                height:
                    70px;

                margin:
                    0 auto 16px;

                display:
                    flex;

                align-items:
                    center;

                justify-content:
                    center;

                filter:
                    drop-shadow(
                        0 0 12px
                        rgba(255, 0, 0, 0.75)
                    );

                animation:
                    navshield-icon-pulse
                    1s ease-in-out infinite;
            }


            @keyframes navshield-icon-pulse {

                0%,
                100% {
                    transform: scale(1);
                }

                50% {
                    transform: scale(1.08);
                }
            }


            /* =================================================
               WARNING TITLE
               ================================================= */

            #navshield-warning-title {

                margin:
                    0 0 15px;

                color:
                    #ff3030;

                font-size:
                    clamp(25px, 4vw, 36px);

                font-weight:
                    900;

                letter-spacing:
                    0.5px;

                line-height:
                    1.15;

                text-transform:
                    uppercase;

                text-shadow:
                    0 0 10px
                    rgba(255, 0, 0, 0.55),

                    0 0 25px
                    rgba(255, 0, 0, 0.25);

                animation:
                    navshield-danger-blink
                    1s steps(1, end)
                    infinite;
            }


            @keyframes navshield-danger-blink {

                0%,
                45% {
                    opacity: 1;
                }

                50%,
                100% {
                    opacity: 0.35;
                }
            }


            /* =================================================
               DESCRIPTION
               ================================================= */

            .navshield-warning-description {

                max-width:
                    520px;

                margin:
                    0 auto 18px;

                color:
                    #d6d6d6;

                font-size:
                    16px;

                line-height:
                    1.55;
            }


            /* =================================================
               QUESTION
               ================================================= */

            .navshield-warning-question {

                margin:
                    0 0 22px;

                color:
                    #ffffff;

                font-size:
                    18px;

                font-weight:
                    700;
            }


            /* =================================================
               REASONS
               ================================================= */

            .navshield-reasons-container {

                margin:
                    0 0 20px;

                padding:
                    17px 20px;

                border-radius:
                    10px;

                background:
                    rgba(255, 255, 255, 0.045);

                border:
                    1px solid
                    rgba(255, 255, 255, 0.10);

                text-align:
                    left;
            }


            .navshield-reasons-container h3 {

                margin:
                    0 0 10px;

                color:
                    #ff5252;

                font-size:
                    14px;

                font-weight:
                    800;

                letter-spacing:
                    0.5px;

                text-transform:
                    uppercase;
            }


            .navshield-reasons {

                margin:
                    0;

                padding-left:
                    21px;

                color:
                    #dddddd;

                font-size:
                    14px;

                line-height:
                    1.6;
            }


            .navshield-reasons li {

                margin-bottom:
                    4px;
            }


            /* =================================================
               SECURITY MESSAGE
               ================================================= */

            .navshield-warning-message {

                margin:
                    20px 0;

                padding:
                    14px 16px;

                border-radius:
                    9px;

                background:
                    rgba(127, 29, 29, 0.32);

                border:
                    1px solid
                    rgba(239, 68, 68, 0.38);

                color:
                    #f5baba;

                font-size:
                    13px;

                line-height:
                    1.45;

                display:
                    flex;

                align-items:
                    center;

                justify-content:
                    center;

                gap:
                    9px;

                text-align:
                    left;
            }


            .navshield-warning-message svg {

                flex-shrink:
                    0;

                filter:
                    drop-shadow(
                        0 0 6px
                        rgba(255, 0, 0, 0.55)
                    );
            }


            /* =================================================
               BUTTONS
               ================================================= */

            .navshield-action-buttons {

                display:
                    flex;

                gap:
                    12px;

                margin-top:
                    24px;
            }


            .navshield-action-buttons button {

                flex:
                    1;

                min-height:
                    50px;

                padding:
                    13px 18px;

                border-radius:
                    9px;

                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;

                font-size:
                    15px;

                font-weight:
                    700;

                cursor:
                    pointer;

                transition:
                    all 0.15s ease;
            }


            /* =================================================
               EXIT BUTTON
               ================================================= */

            #navshield-exit-button {

                background:
                    #b91c1c;

                border:
                    1px solid
                    #ef4444;

                color:
                    #ffffff;

                box-shadow:
                    0 0 12px
                    rgba(220, 38, 38, 0.20);
            }


            #navshield-exit-button:hover {

                background:
                    #dc2626;

                box-shadow:
                    0 0 20px
                    rgba(239, 68, 68, 0.45);

                transform:
                    translateY(-1px);
            }


            /* =================================================
               CONTINUE BUTTON
               ================================================= */

            #navshield-continue-button {

                background:
                    #252525;

                border:
                    1px solid
                    #555555;

                color:
                    #eeeeee;
            }


            #navshield-continue-button:hover {

                background:
                    #353535;

                border-color:
                    #777777;

                transform:
                    translateY(-1px);
            }


            /* =================================================
               FOCUS
               ================================================= */

            .navshield-action-buttons button:focus {

                outline:
                    2px solid
                    #ffffff;

                outline-offset:
                    3px;
            }


            /* =================================================
               MOBILE
               ================================================= */

            @media (max-width: 600px) {

                #navshield-warning-overlay {

                    padding:
                        14px;
                }


                #navshield-warning-card {

                    padding:
                        28px 22px 24px;

                    border-radius:
                        14px;
                }


                .navshield-action-buttons {

                    flex-direction:
                        column;
                }


                .navshield-action-buttons button {

                    width:
                        100%;
                }
            }
        `;


        document.head.appendChild(
            style
        );
    }


    /* =========================================================
     * CREATE PHISHING WARNING OVERLAY
     * ========================================================= */

    function createPhishingOverlay(
        probability,
        reasons
    ) {

        removePhishingOverlay();

        injectNavShieldStyles();


        navShieldOverlay =
            document.createElement("div");


        navShieldOverlay.id =
            "navshield-warning-overlay";


        const reasonList =
            Array.isArray(reasons) &&
            reasons.length > 0
                ? reasons
                : [
                    "Suspicious website characteristics detected"
                ];


        const reasonsHTML =
            reasonList
                .map(
                    function (reason) {
                        return `
                            <li>
                                ${escapeHTML(reason)}
                            </li>
                        `;
                    }
                )
                .join("");


        const probabilityValue =
            Number(probability);


        const probabilityText =
            Number.isFinite(
                probabilityValue
            )
                ? `${Math.round(
                    probabilityValue * 100
                )}%`
                : "High";


        navShieldOverlay.innerHTML = `

            <div
                id="navshield-warning-card"
                role="alertdialog"
                aria-modal="true"
                aria-labelledby="navshield-warning-title"
            >

                <!-- WARNING ICON -->

                <div
                    class="navshield-warning-icon"
                    aria-hidden="true"
                >

                    <svg
                        width="64"
                        height="64"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                    >

                        <path
                            d="M12 3L22 20H2L12 3Z"
                            fill="#DC2626"
                            stroke="#FF4B4B"
                            stroke-width="1.4"
                            stroke-linejoin="round"
                        />

                        <path
                            d="M12 8V13"
                            stroke="#ffffff"
                            stroke-width="2"
                            stroke-linecap="round"
                        />

                        <circle
                            cx="12"
                            cy="16.5"
                            r="1"
                            fill="#ffffff"
                        />

                    </svg>

                </div>


                <!-- TITLE -->

                <h1
                    id="navshield-warning-title"
                >
                    DANGEROUS WEBSITE DETECTED
                </h1>


                <!-- DESCRIPTION -->

                <p
                    class="navshield-warning-description"
                >
                    NavShield has detected characteristics
                    commonly associated with phishing or
                    fraudulent websites.
                </p>


                
                <!-- PROBABILITY -->
                <!--

                <p
                    class="navshield-warning-question"
                    style="margin-bottom: 12px;"
                >
                    Detection Confidence:
                    ${escapeHTML(
                        probabilityText
                    )}
                </p>
                -->
                


                <!-- QUESTION -->

                <p
                    class="navshield-warning-question"
                >
                    Are you sure you want to continue?
                </p>


                <!-- REASONS -->

                <div
                    class="navshield-reasons-container"
                >

                    <h3>
                        Why this warning?
                    </h3>

                    <ul
                        class="navshield-reasons"
                    >
                        ${reasonsHTML}
                    </ul>

                </div>


                <!-- SECURITY MESSAGE -->

                <div
                    class="navshield-warning-message"
                >

                    <svg
                        width="18"
                        height="18"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        aria-hidden="true"
                    >

                        <path
                            d="M12 3L22 20H2L12 3Z"
                            fill="#DC2626"
                            stroke="#FF4B4B"
                            stroke-width="1.5"
                            stroke-linejoin="round"
                        />

                        <path
                            d="M12 8V13"
                            stroke="#ffffff"
                            stroke-width="2"
                            stroke-linecap="round"
                        />

                        <circle
                            cx="12"
                            cy="16.5"
                            r="1"
                            fill="#ffffff"
                        />

                    </svg>

                    <span>
                        Do not enter passwords, payment details,
                        or other sensitive information on this site.
                    </span>

                </div>


                <!-- BUTTONS -->

                <div
                    class="navshield-action-buttons"
                >

                    <button
                        id="navshield-exit-button"
                        type="button"
                    >
                        Exit
                    </button>


                    <button
                        id="navshield-continue-button"
                        type="button"
                    >
                        Continue to Website
                    </button>

                </div>

            </div>
        `;


        document.documentElement.appendChild(
            navShieldOverlay
        );


        /* =====================================================
         * CONTINUE
         * ===================================================== */

        const continueButton =
            document.getElementById(
                "navshield-continue-button"
            );


        if (continueButton) {

            continueButton.addEventListener(
                "click",
                function () {

                    removePhishingOverlay();

                }
            );
        }


        /* =====================================================
         * EXIT
         * ===================================================== */

        const exitButton =
            document.getElementById(
                "navshield-exit-button"
            );


        if (exitButton) {

            exitButton.addEventListener(
                "click",
                function () {

                    chrome.runtime.sendMessage({
                        action:
                            "exitPhishingPage"
                    });

                }
            );
        }


        /*
         * Default focus is on Exit.
         */
        if (exitButton) {

            exitButton.focus();

        }
    }


    /* =========================================================
     * REMOVE PHISHING OVERLAY
     * ========================================================= */

    function removePhishingOverlay() {

        if (navShieldOverlay) {

            navShieldOverlay.remove();

            navShieldOverlay = null;
        }
    }


    /* =========================================================
     * GENERATE WARNING REASONS
     * ========================================================= */

    function generateWarningReasons(
        analysis
    ) {

        const reasons = [];


        const features =
            analysis?.features || {};


        const security =
            analysis?.security || {};


        /* -----------------------------------------------------
         * TYPOSQUATTING
         * ----------------------------------------------------- */

        const typosquatting =
            security.typosquatting;


        if (
            typosquatting &&
            typosquatting.detected
        ) {

            const matchedDomain =
                typosquatting.matchedDomain;


            if (matchedDomain) {

                reasons.push(
                    `Domain closely resembles ${matchedDomain}`
                );

            } else {

                reasons.push(
                    "Suspicious look-alike domain"
                );
            }
        }


        /* -----------------------------------------------------
         * URL STRUCTURE
         * ----------------------------------------------------- */

        if (
            Number(features.url_length) > 75 ||
            Number(features.at_symbol) === 1 ||
            Number(features.prefix_suffix) === 1 ||
            Number(features.subdomains) > 2
        ) {

            reasons.push(
                "Suspicious URL structure"
            );
        }


        /* -----------------------------------------------------
         * FORM HANDLING
         * ----------------------------------------------------- */

        if (
            Number(features.server_form_handler) === 1
        ) {

            reasons.push(
                "Suspicious form submission"
            );
        }


        /* -----------------------------------------------------
         * JAVASCRIPT
         * ----------------------------------------------------- */

        if (
            Number(features.suspicious_inline_js) === 1
        ) {

            reasons.push(
                "Suspicious JavaScript"
            );
        }


        /* -----------------------------------------------------
         * HIDDEN HTML
         * ----------------------------------------------------- */

        if (
            Number(features.hidden_html_elements) === 1
        ) {

            reasons.push(
                "Hidden HTML elements detected"
            );
        }


        /* -----------------------------------------------------
         * UNICODE / MIXED SCRIPT / HOMOGRAPH
         * ----------------------------------------------------- */

        if (
            Number(features.unicode_present) === 1 ||
            Number(features.mixed_script) === 1 ||
            Number(features.homograph_similarity) > 0
        ) {

            reasons.push(
                "Suspicious character or homograph usage"
            );
        }


        /* -----------------------------------------------------
         * EXTERNAL RESOURCES
         * ----------------------------------------------------- */

        if (
            Number(features.request_url) === 1 ||
            Number(features.url_of_anchor) === 1 ||
            Number(features.links_in_script_link) === 1
        ) {

            reasons.push(
                "External resource or link references detected"
            );
        }


        /* -----------------------------------------------------
         * FALLBACK
         * ----------------------------------------------------- */

        if (reasons.length === 0) {

            reasons.push(
                "Multiple suspicious website characteristics detected"
            );
        }


        /*
         * Remove duplicates.
         */
        return [
            ...new Set(reasons)
        ];
    }


    /* =========================================================
     * HANDLE AUTOMATIC ANALYSIS RESULT
     * ========================================================= */

    function handleAutomaticAnalysisResult(
        result
    ) {

        if (!result) {
            return;
        }


        /*
         * background.js returns:
         *
         * {
         *     ok,
         *     analysis
         * }
         */

        if (!result.ok) {

            console.log(
                "[NavShield] Automatic analysis failed:",
                result.error
            );


            /*
             * FAIL OPEN
             *
             * Do not interrupt normal browsing when
             * the backend is unavailable.
             */
            return;
        }


        const analysis =
            result.analysis || {};


        /*
         * Final security decision is made by
         * background.js.
         */
        const prediction =
            analysis.finalPrediction || {};


        const isPhishing =
            prediction.prediction ===
            "phishing";


        /*
         * Legitimate website:
         *
         * No visible warning.
         */
        if (!isPhishing) {

            return;
        }


        const probability =
            prediction.probability ?? 0;


        const reasons =
            generateWarningReasons(
                analysis
            );


        console.log(
            "[NavShield] Phishing website detected:",
            {
                probability,
                reasons
            }
        );


        createPhishingOverlay(
            probability,
            reasons
        );
    }


    /* =========================================================
     * EXTRACTOR ACCESS
     * =========================================================
     *
     * All project extractors are exported through:
     *
     * PhishCatcher.Extractors.<function>
     */

    function getExtractors() {

        if (
            globalThis.PhishCatcher &&
            globalThis.PhishCatcher.Extractors
        ) {

            return globalThis.PhishCatcher.Extractors;
        }


        return null;
    }


    /* =========================================================
     * DOMAIN HELPERS
     * ========================================================= */

    function getHostname(url) {

        try {

            return new URL(
                url
            ).hostname.toLowerCase();

        } catch {

            return "";
        }
    }


    function getRegisteredDomain(
        hostname
    ) {

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


    /* =========================================================
     * LEVENSHTEIN DISTANCE
     * ========================================================= */

    function levenshtein(
        a,
        b
    ) {

        const rows =
            a.length + 1;


        const cols =
            b.length + 1;


        const matrix =
            Array.from(
                { length: rows },
                function () {

                    return new Array(
                        cols
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
            j < cols;
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
                j < cols;
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
            cols - 1
        ];
    }


    function similarity(
        a,
        b
    ) {

        if (!a || !b) {

            return 0;
        }


        const maxLength =
            Math.max(
                a.length,
                b.length
            );


        if (maxLength === 0) {

            return 1;
        }


        return (
            1 -
            levenshtein(
                a,
                b
            ) /
            maxLength
        );
    }


    /* =========================================================
     * LOOK-ALIKE NORMALIZATION
     * ========================================================= */

    function normalizeLookalikes(
        value
    ) {

        return String(value)
            .toLowerCase()
            .replace(/0/g, "o")
            .replace(/1/g, "l")
            .replace(/3/g, "e")
            .replace(/4/g, "a")
            .replace(/5/g, "s")
            .replace(/7/g, "t");
    }


    /* =========================================================
     * CHARACTER SUBSTITUTION
     * ========================================================= */

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


        const differences = [];


        for (
            let i = 0;
            i < currentName.length;
            i++
        ) {

            if (
                currentName[i] !==
                legitimateName[i]
            ) {

                differences.push({

                    position:
                        i,

                    current:
                        currentName[i],

                    legitimate:
                        legitimateName[i]

                });
            }
        }


        if (
            differences.length === 1
        ) {

            return differences[0];
        }


        return null;
    }


    /* =========================================================
     * TYPOSQUATTING DETECTION
     * ========================================================= */

    function detectTyposquatting(
        url
    ) {

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

                rawSimilarity:
                    0,

                characterSubstitution:
                    null,

                reason:
                    "Invalid hostname"

            };
        }


        const currentDomain =
            getRegisteredDomain(
                hostname
            );


        /*
         * Never classify an exact legitimate
         * domain as typosquatting.
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

                rawSimilarity:
                    1,

                characterSubstitution:
                    null,

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


            const score =
                Math.max(

                    rawSimilarity,

                    normalizedSimilarity,

                    substitution
                        ? 0.90
                        : 0

                );


            if (
                !bestMatch ||
                score >
                    bestMatch.score
            ) {

                bestMatch = {

                    legitimateDomain:
                        legitimateDomain,

                    rawSimilarity:
                        rawSimilarity,

                    normalizedSimilarity:
                        normalizedSimilarity,

                    substitution:
                        substitution,

                    score:
                        score

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

                rawSimilarity:
                    0,

                characterSubstitution:
                    null,

                reason:
                    "No legitimate domain match"

            };
        }


        const detected =
            bestMatch.score >=
            TYPOSQUATTING_THRESHOLD;


        let reason =
            "No strong typosquatting similarity";


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
                    "Look-alike domain similarity";
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
                bestMatch.legitimateDomain,

            similarity:
                bestMatch.score,

            similarityPercentage:
                Math.round(
                    bestMatch.score * 100
                ),

            rawSimilarity:
                bestMatch.rawSimilarity,

            characterSubstitution:
                bestMatch.substitution,

            reason:
                reason
        };
    }


    /* =========================================================
     * ML FEATURE COLLECTION
     * =========================================================
     *
     * The current Random Forest expects the following
     * browser-generated features.
     *
     * domain_age_days is added by the backend.
     */

    function collectFeatures(
        url
    ) {

        const extractors =
            getExtractors();


        if (!extractors) {

            throw new Error(
                "PhishCatcher extractors are not loaded."
            );
        }


        /* -----------------------------------------------------
         * URL FEATURES
         * ----------------------------------------------------- */

        let urlFeatures = {};


        if (
            typeof extractors.extractURLFeatures ===
            "function"
        ) {

            urlFeatures =
                extractors.extractURLFeatures(
                    url
                ) || {};
        }


        /* -----------------------------------------------------
         * HTML FEATURES
         * ----------------------------------------------------- */

        let htmlFeatures = {};


        if (
            typeof extractors.extractHTMLFeatures ===
            "function"
        ) {

            htmlFeatures =
                extractors.extractHTMLFeatures() ||
                {};
        }


        /* -----------------------------------------------------
         * DOMAIN FEATURES
         * ----------------------------------------------------- */

        let domainFeatures = {};


        if (
            typeof extractors.getDomainFeatures ===
            "function"
        ) {

            domainFeatures =
                extractors.getDomainFeatures(
                    url
                ) || {};
        }


        /* -----------------------------------------------------
         * ENTROPY FEATURES
         * ----------------------------------------------------- */

        let entropyFeatures = {};


        if (
            typeof extractors.extractEntropyFeatures ===
            "function"
        ) {

            entropyFeatures =
                extractors.extractEntropyFeatures(
                    url
                ) || {};
        }


        /* -----------------------------------------------------
         * KEYWORD FEATURES
         * ----------------------------------------------------- */

        let keywordFeatures = {};


        if (
            typeof extractors.extractKeywordFeatures ===
            "function"
        ) {

            keywordFeatures =
                extractors.extractKeywordFeatures(
                    url
                ) || {};
        }


        /* -----------------------------------------------------
         * MODEL FEATURE VECTOR
         * ----------------------------------------------------- */

        const features = {

            ip_address:
                Number(
                    urlFeatures.ip_address ??
                    domainFeatures.is_ip_address ??
                    0
                ),


            url_length:
                Number(
                    urlFeatures.url_length ??
                    0
                ),


            tiny_url:
                Number(
                    urlFeatures.tiny_url ??
                    0
                ),


            at_symbol:
                Number(
                    urlFeatures.at_symbol ??
                    0
                ),


            redirect_double_slash:
                Number(
                    urlFeatures.redirect_double_slash ??
                    0
                ),


            prefix_suffix:
                Number(
                    urlFeatures.prefix_suffix ??
                    domainFeatures.contains_hyphen ??
                    0
                ),


            subdomains:
                Number(
                    urlFeatures.subdomains ??
                    domainFeatures.subdomain_count ??
                    0
                ),


            https:
                Number(
                    urlFeatures.https ??
                    0
                ),


            non_standard_port:
                Number(
                    urlFeatures.non_standard_port ??
                    0
                ),


            https_in_domain:
                Number(
                    urlFeatures.https_in_domain ??
                    0
                ),


            favicon:
                Number(
                    htmlFeatures.favicon ??
                    0
                ),


            request_url:
                Number(
                    htmlFeatures.request_url ??
                    0
                ),


            url_of_anchor:
                Number(
                    htmlFeatures.url_of_anchor ??
                    0
                ),


            links_in_script_link:
                Number(
                    htmlFeatures.links_in_script_link ??
                    0
                ),


            server_form_handler:
                Number(
                    htmlFeatures.server_form_handler ??
                    0
                ),


            suspicious_inline_js:
                Number(
                    htmlFeatures.suspicious_inline_js ??
                    0
                ),


            hidden_html_elements:
                Number(
                    htmlFeatures.hidden_html_elements ??
                    0
                ),


            unicode_present:
                Number(
                    urlFeatures.unicode_present ??
                    0
                ),


            mixed_script:
                Number(
                    urlFeatures.mixed_script ??
                    0
                ),


            homograph_similarity:
                Number(
                    urlFeatures.homograph_similarity ??
                    0
                )
        };


        /* -----------------------------------------------------
         * SANITY CHECK
         * ----------------------------------------------------- */

        const expectedFeatures = [

            "ip_address",

            "url_length",

            "tiny_url",

            "at_symbol",

            "redirect_double_slash",

            "prefix_suffix",

            "subdomains",

            "https",

            "non_standard_port",

            "https_in_domain",

            "favicon",

            "request_url",

            "url_of_anchor",

            "links_in_script_link",

            "server_form_handler",

            "suspicious_inline_js",

            "hidden_html_elements",

            "unicode_present",

            "mixed_script",

            "homograph_similarity"

        ];


        for (
            const featureName
            of expectedFeatures
        ) {

            if (
                !Number.isFinite(
                    features[featureName]
                )
            ) {

                features[featureName] =
                    0;
            }
        }


        console.log(
            "[NavShield] Extracted ML features:",
            features
        );


        console.log(
            "[NavShield] Additional entropy features:",
            entropyFeatures
        );


        console.log(
            "[NavShield] Additional keyword features:",
            keywordFeatures
        );


        return features;
    }


    /* =========================================================
     * CURRENT PAGE ANALYSIS
     * ========================================================= */

    function extractCurrentPageFeatures() {

        const url =
            window.location.href;


        const features =
            collectFeatures(
                url
            );


        const typosquatting =
            detectTyposquatting(
                url
            );


        return {

            url:

                url,

            features:

                features,

            security: {

                typosquatting:
                    typosquatting

            },

            timestamp:
                Date.now()
        };
    }


    /* =========================================================
     * SEND ANALYSIS TO BACKGROUND
     * ========================================================= */

    function sendPageAnalysis() {

        let analysis;


        try {

            analysis =
                extractCurrentPageFeatures();

        } catch (error) {

            console.error(
                "[NavShield] Page analysis failed:",
                error
            );

            return null;
        }


        /*
         * Do not send an empty feature object.
         */

        if (
            !analysis.features ||
            Object.keys(
                analysis.features
            ).length === 0
        ) {

            console.error(
                "[NavShield] Feature extraction returned no ML features."
            );


            return analysis;
        }


        /*
         * -----------------------------------------------------
         * SEND TO BACKGROUND
         * -----------------------------------------------------
         *
         * IMPORTANT:
         *
         * The callback is required here so that the
         * automatic phishing warning can use the final
         * decision returned by background.js.
         */

        chrome.runtime.sendMessage(

            {

                action:
                    "pageAnalysis",

                ...analysis

            },

            function (result) {

                /*
                 * Ignore errors caused by the extension
                 * context being reloaded.
                 */

                if (
                    chrome.runtime.lastError
                ) {

                    console.warn(
                        "[NavShield] Runtime message error:",
                        chrome.runtime.lastError.message
                    );

                    return;
                }


                console.log(
                    "[NavShield] Automatic analysis response:",
                    result
                );


                /*
                 * Process final ML + security decision.
                 */

                handleAutomaticAnalysisResult(
                    result
                );
            }
        );


        return analysis;
    }


    /* =========================================================
     * MESSAGES FROM POPUP
     * ========================================================= */

    chrome.runtime.onMessage.addListener(
        function (
            message,
            sender,
            sendResponse
        ) {

            if (!message) {
                return;
            }


            /*
             * -------------------------------------------------
             * GET FEATURES
             * -------------------------------------------------
             */

            if (
                message.action ===
                "getFeatures"
            ) {

                const analysis =
                    sendPageAnalysis();


                sendResponse(
                    analysis
                );


                return true;
            }


            /*
             * -------------------------------------------------
             * ANALYZE CURRENT PAGE
             * -------------------------------------------------
             */

            if (
                message.action ===
                "analyzeCurrentPage"
            ) {

                const analysis =
                    sendPageAnalysis();


                sendResponse(
                    analysis
                );


                return true;
            }
        }
    );


    /* =========================================================
     * AUTOMATIC PAGE ANALYSIS
     * =========================================================
     *
     * Wait until the DOM is available because the HTML
     * extractor requires page contents.
     */

    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            function () {

                sendPageAnalysis();

            },
            {
                once:
                    true
            }
        );

    } else {

        sendPageAnalysis();
    }


})();