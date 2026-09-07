from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from headerhound.client import ScanClient


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax")
        self.send_header("Set-Cookie", "theme=dark; Secure; SameSite=Lax")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def test_client_follows_bounded_redirects() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        response = ScanClient(min_interval=0, allow_private=True).fetch(
            f"http://127.0.0.1:{port}/redirect"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert response.status_code == 200
    assert response.redirects == (f"http://127.0.0.1:{port}/redirect",)
    assert response.headers["content-security-policy"] == "default-src 'self'"
    assert len(response.cookies) == 2
    assert "secret" not in response.headers.values()
