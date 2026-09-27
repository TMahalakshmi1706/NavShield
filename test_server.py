from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import os


TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test")


class NavShieldTestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0].lower()
        path = urlparse(self.path).path

        # ---------------------------------------------------------
        # Fake Google typosquatting website
        # http://g00gle.com/
        # ---------------------------------------------------------
        if host == "g00gle.com":
            self.serve_html("google-test.html")
            return

        # ---------------------------------------------------------
        # Fake PayPal typosquatting website
        # http://paypa1.test/
        # ---------------------------------------------------------
        if host == "paypa1.test":
            self.serve_html("paypal-test.html")
            return

        # ---------------------------------------------------------
        # Localhost root
        # http://127.0.0.1/
        # ---------------------------------------------------------
        if host in ("127.0.0.1", "localhost") and path == "/":
            self.serve_html("index.html")
            return

        # ---------------------------------------------------------
        # Separate redirect test
        # http://127.0.0.1/redirect-test.html
        # ---------------------------------------------------------
        if path == "/redirect-test.html":
            self.serve_html("redirect-test.html")
            return

        # ---------------------------------------------------------
        # Any other request
        # Do NOT show a directory listing.
        # ---------------------------------------------------------
        self.send_error(404, "Test page not found")

    def serve_html(self, filename):
        filepath = os.path.join(TEST_DIR, filename)

        if not os.path.isfile(filepath):
            self.send_error(
                404,
                f"Test page not found: {filename}"
            )
            return

        try:
            with open(filepath, "rb") as file:
                content = file.read()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )
            self.send_header(
                "Content-Length",
                str(len(content))
            )
            self.send_header(
                "Cache-Control",
                "no-cache, no-store, must-revalidate"
            )
            self.end_headers()

            self.wfile.write(content)

        except OSError:
            self.send_error(
                500,
                "Unable to read test page"
            )

    def log_message(self, format, *args):
        print(
            f"[NavShield Test Server] "
            f"{self.address_string()} - {format % args}"
        )


class NavShieldHTTPServer(HTTPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = NavShieldHTTPServer(
        ("127.0.0.1", 80),
        NavShieldTestHandler
    )

    print()
    print("==============================================")
    print("       NavShield Local Test Server")
    print("==============================================")
    print("Server:      http://127.0.0.1/")
    print()
    print("g00gle.com   -> google-test.html")
    print("paypa1.test  -> paypal-test.html")
    print()
    print("/redirect-test.html -> redirect-test.html")
    print()
    print("Directory listings are disabled.")
    print("Press Ctrl+C to stop.")
    print("==============================================")
    print()

    server.serve_forever()
    