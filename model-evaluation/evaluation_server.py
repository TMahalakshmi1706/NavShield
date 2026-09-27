from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXTENSION_DIR = PROJECT_ROOT / "extension"

MODEL_EVALUATION_DIR = (
    PROJECT_ROOT / "model-evaluation"
)

INDEX_FILE = (
    MODEL_EVALUATION_DIR / "index.html"
)

# Background image used by the evaluation landing page
IMAGE_FILE = PROJECT_ROOT / "image.jpg"

EVALUATION_FILE = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "evaluation_results.csv"
)


# ============================================================
# USE THE EXISTING NAVSHIELD PYTHON PREDICTION PIPELINE
# ============================================================

sys.path.insert(
    0,
    str(PROJECT_ROOT)
)

from backend.services.predictor import (
    load_model,
    predict,
)

from backend.services.feature_builder import (
    load_feature_order,
)


# ============================================================
# EXACT EXISTING EXTENSION EXTRACTORS
# ============================================================

EXTRACTOR_FILES = [

    EXTENSION_DIR
    / "extractors"
    / "urlFeatures.js",

    EXTENSION_DIR
    / "extractors"
    / "htmlFeatures.js",

    EXTENSION_DIR
    / "extractors"
    / "tldParser.js",

    EXTENSION_DIR
    / "extractors"
    / "entropy.js",

    EXTENSION_DIR
    / "extractors"
    / "keywordDetector.js",
]


# ============================================================
# EXACT 21-FEATURE COMPOSITION USED BY
# extension/content/content.js
#
# The extractor implementations themselves are NOT rewritten.
# The actual JS files from extension/extractors are executed.
# ============================================================

FEATURE_EXTRACTION_SCRIPT = r"""
(url) => {

    const extractors =
        globalThis.PhishCatcher &&
        globalThis.PhishCatcher.Extractors;

    if (!extractors) {
        throw new Error(
            "NavShield extractors were not loaded."
        );
    }


    /*
     * --------------------------------------------------------
     * URL FEATURES
     * --------------------------------------------------------
     */

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


    /*
     * --------------------------------------------------------
     * HTML FEATURES
     * --------------------------------------------------------
     */

    let htmlFeatures = {};

    if (
        typeof extractors.extractHTMLFeatures ===
        "function"
    ) {
        htmlFeatures =
            extractors.extractHTMLFeatures() || {};
    }


    /*
     * --------------------------------------------------------
     * DOMAIN / TLD FEATURES
     * --------------------------------------------------------
     */

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


    /*
     * --------------------------------------------------------
     * ENTROPY
     *
     * Entropy is part of the extension's analysis,
     * but is NOT one of the Random Forest's 21 features.
     * --------------------------------------------------------
     */

    if (
        typeof extractors.extractEntropyFeatures ===
        "function"
    ) {
        extractors.extractEntropyFeatures(
            url
        );
    }


    /*
     * --------------------------------------------------------
     * KEYWORD FEATURES
     *
     * These are also part of the extension's analysis,
     * but are NOT part of the current 21-feature model.
     * --------------------------------------------------------
     */

    if (
        typeof extractors.extractKeywordFeatures ===
        "function"
    ) {
        extractors.extractKeywordFeatures(
            url
        );
    }


    /*
     * --------------------------------------------------------
     * EXACT MODEL FEATURE CONSTRUCTION
     *
     * This follows collectFeatures() in:
     *
     * extension/content/content.js
     * --------------------------------------------------------
     */

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


    /*
     * --------------------------------------------------------
     * EXACT SAME SANITY CHECK AS content.js
     * --------------------------------------------------------
     */

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
            features[featureName] = 0;
        }
    }


    return features;
}
"""


# ============================================================
# VERIFY ALL REQUIRED EXISTING EXTRACTOR FILES
# ============================================================

def verify_extractor_files():

    missing = [
        str(path)
        for path in EXTRACTOR_FILES
        if not path.exists()
    ]

    if missing:

        raise FileNotFoundError(
            "Required NavShield extractor file(s) "
            "were not found:\n"
            + "\n".join(missing)
        )


# ============================================================
# LOAD THE EXISTING JS EXTRACTORS INTO CHROMIUM
#
# add_init_script() is important:
# the scripts must be installed BEFORE the webpage loads.
# ============================================================

def install_existing_extractors(context):

    verify_extractor_files()

    for extractor_file in EXTRACTOR_FILES:

        source = extractor_file.read_text(
            encoding="utf-8"
        )

        context.add_init_script(
            script=source
        )


# ============================================================
# EXTRACT FEATURES FROM A REAL WEBPAGE
# USING THE EXISTING NAVSHIELD JS EXTRACTORS
# ============================================================

def extract_features_with_browser(url):

    with sync_playwright() as playwright:

        browser = playwright.chromium.launch(
            headless=True
        )

        try:

            context = browser.new_context(
                ignore_https_errors=True
            )

            install_existing_extractors(
                context
            )

            page = context.new_page()

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30000
            )

            try:

                page.wait_for_load_state(
                    "networkidle",
                    timeout=10000
                )

            except PlaywrightTimeoutError:

                # Some real websites continuously make
                # network requests. DOM content is already
                # available, so continue.

                pass


            # Give dynamic DOM content a short time to settle.

            page.wait_for_timeout(
                500
            )


            # The browser extension analyzes the URL of the
            # page currently displayed. If the supplied URL
            # redirected, page.url is therefore the correct
            # final URL to analyze.

            final_url = page.url


            features = page.evaluate(
                FEATURE_EXTRACTION_SCRIPT,
                final_url
            )


            return {
                "url": final_url,
                "features": features,
            }


        finally:

            browser.close()


# ============================================================
# MODEL INFORMATION
# ============================================================

def get_model_information():

    model = load_model()

    feature_order = load_feature_order()

    accuracy = None

    if EVALUATION_FILE.exists():

        results = pd.read_csv(
            EVALUATION_FILE
        )

        random_forest = results[
            results["model"]
            .astype(str)
            .str.lower()
            .eq("random forest")
        ]

        if not random_forest.empty:

            accuracy = float(
                random_forest.iloc[0][
                    "accuracy"
                ]
            )


    return {

        "model_type":
            type(model).__name__,

        "estimators":
            int(
                getattr(
                    model,
                    "n_estimators",
                    0
                )
            ),

        "features":
            len(feature_order),

        "accuracy":
            accuracy,

    }


# ============================================================
# COMPLETE URL EVALUATION
# ============================================================

def evaluate_url(url):

    extracted = (
        extract_features_with_browser(
            url
        )
    )

    final_url = extracted[
        "url"
    ]

    extracted_features = extracted[
        "features"
    ]


    # --------------------------------------------------------
    # Safety check:
    # the browser-side extractor must produce the exact
    # 20 non-domain-age features expected by content.js.
    # --------------------------------------------------------

    expected_browser_features = [

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
        "homograph_similarity",
    ]


    missing_features = [
        name
        for name in expected_browser_features
        if name not in extracted_features
    ]


    if missing_features:

        raise ValueError(
            "Feature extraction did not produce "
            "all required model features. Missing: "
            + ", ".join(missing_features)
        )


    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Use the EXISTING predictor.py.
    #
    # predictor.py:
    #   1. Adds live domain_age_days.
    #   2. Uses the existing feature_order.json.
    #   3. Loads ml/models/random_forest.pkl.
    #   4. Runs model.predict().
    #   5. Calculates probability for class 1.
    # --------------------------------------------------------

    result = predict(
        extracted_features,
        final_url
    )


    return {

        "url":
            final_url,

        "prediction":
            result["prediction"],

        "probability":
            result["probability"],

        "feature_count":
            result["feature_count"],

    }


# ============================================================
# HTTP HANDLER
# ============================================================

class EvaluationHandler(
    BaseHTTPRequestHandler
):


    def send_json(
        self,
        data,
        status=200
    ):

        body = json.dumps(
            data
        ).encode("utf-8")


        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.send_header(
            "Access-Control-Allow-Origin",
            "*"
        )

        self.end_headers()

        self.wfile.write(
            body
        )


    def do_GET(self):

        # ----------------------------------------------------
        # INDEX PAGE
        # ----------------------------------------------------

        if self.path == "/":

            if not INDEX_FILE.exists():

                self.send_error(
                    404,
                    "index.html not found"
                )

                return


            body = INDEX_FILE.read_bytes()


            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(len(body))
            )

            self.end_headers()

            self.wfile.write(
                body
            )

            return


        # ----------------------------------------------------
        # BACKGROUND IMAGE
        # ----------------------------------------------------

        if self.path == "/image.jpg":

            if not IMAGE_FILE.exists():

                self.send_error(
                    404,
                    "image.jpg not found"
                )

                return


            body = IMAGE_FILE.read_bytes()


            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                "image/jpeg"
            )

            self.send_header(
                "Content-Length",
                str(len(body))
            )

            self.end_headers()

            self.wfile.write(
                body
            )

            return


        # ----------------------------------------------------
        # MODEL INFORMATION
        # ----------------------------------------------------

        if self.path == "/api/model-info":

            try:

                self.send_json(
                    get_model_information()
                )

            except Exception as error:

                self.send_json(
                    {
                        "error":
                            str(error)
                    },
                    500
                )

            return


        # ----------------------------------------------------
        # UNKNOWN GET REQUEST
        # ----------------------------------------------------

        self.send_error(
            404,
            "Not found"
        )


    def do_POST(self):

        if self.path != "/api/predict":

            self.send_error(
                404,
                "Not found"
            )

            return


        try:

            content_length = int(
                self.headers.get(
                    "Content-Length",
                    0
                )
            )


            body = self.rfile.read(
                content_length
            )


            data = json.loads(
                body.decode(
                    "utf-8"
                )
            )


            url = str(
                data.get(
                    "url",
                    ""
                )
            ).strip()


            if not url:

                self.send_json(
                    {
                        "error":
                            "Please enter a URL."
                    },
                    400
                )

                return


            if not (
                url.startswith("http://")
                or
                url.startswith("https://")
            ):

                url = (
                    "https://"
                    + url
                )


            result = evaluate_url(
                url
            )


            self.send_json(
                result
            )


        except PlaywrightTimeoutError:

            self.send_json(
                {
                    "error":
                        "The webpage took too long to load."
                },
                408
            )


        except Exception as error:

            self.send_json(
                {
                    "error":
                        f"Prediction failed: {error}"
                },
                500
            )


    def log_message(
        self,
        format,
        *args
    ):

        print(
            "[NavShield Model Evaluation] "
            + (
                format % args
            )
        )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "=============================================="
    )

    print(
        "       NavShield Model Evaluation"
    )

    print(
        "=============================================="
    )


    # --------------------------------------------------------
    # Verify required files
    # --------------------------------------------------------

    verify_extractor_files()


    if not INDEX_FILE.exists():

        raise FileNotFoundError(
            f"index.html not found: {INDEX_FILE}"
        )


    if not IMAGE_FILE.exists():

        raise FileNotFoundError(
            f"image.jpg not found: {IMAGE_FILE}"
        )


    # --------------------------------------------------------
    # Load model information
    # --------------------------------------------------------

    model = load_model()

    feature_order = load_feature_order()


    print(
        "Model:      "
        + type(model).__name__
    )


    print(
        "Model file: "
        + str(
            PROJECT_ROOT
            / "ml"
            / "models"
            / "random_forest.pkl"
        )
    )


    print(
        "Estimators: "
        + str(
            getattr(
                model,
                "n_estimators",
                0
            )
        )
    )


    print(
        "Features:   "
        + str(
            len(feature_order)
        )
    )


    # --------------------------------------------------------
    # Display accuracy
    # --------------------------------------------------------

    if EVALUATION_FILE.exists():

        results = pd.read_csv(
            EVALUATION_FILE
        )

        random_forest = results[
            results["model"]
            .astype(str)
            .str.lower()
            .eq("random forest")
        ]

        if not random_forest.empty:

            accuracy = float(
                random_forest.iloc[0][
                    "accuracy"
                ]
            )

            print(
                "Accuracy:   "
                + f"{accuracy * 100:.2f}%"
            )


    print()

    print(
        "Background: "
        + str(IMAGE_FILE)
    )

    print()

    print(
        "Open:"
    )

    print(
        "http://127.0.0.1:8080/"
    )

    print()

    print(
        "Press Ctrl+C to stop."
    )

    print(
        "=============================================="
    )

    print()


    # --------------------------------------------------------
    # Start HTTP server
    # --------------------------------------------------------

    server = HTTPServer(
        (
            "127.0.0.1",
            8080
        ),
        EvaluationHandler
    )


    server.serve_forever()