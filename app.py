#!/usr/bin/env python3
"""Commercial-style PoC generator web shell for red-team validation workflows.

This app serves a polished dashboard where a user can paste a raw HTTP request,
select a template, set redirect behavior, and generate a finished HTML PoC.
"""

from __future__ import annotations

import json
import os
import re
import socket
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict

from csrf_generator import generate_html_poc, parse_raw_http

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
GENERATED_DIR = BASE_DIR / "generated"
INDEX_HTML = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")
GENERATED_DIR.mkdir(exist_ok=True)


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.lower()).strip("-")
    return cleaned or "poc"


class PoCRequestHandler(BaseHTTPRequestHandler):
    server_version = "RequestForge/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._send_html(INDEX_HTML)
            return

        if parsed.path.startswith("/preview"):
            filename = urllib.parse.parse_qs(parsed.query).get("file", [""])[0]
            if not filename:
                self._send_json({"status": "error", "message": "Missing file parameter"}, code=400)
                return
            target = GENERATED_DIR / filename
            if not target.exists() or not target.is_file():
                self._send_json({"status": "error", "message": "File not found"}, code=404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(target.read_bytes())
            return

        self._send_json({"status": "error", "message": "Not found"}, code=404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/generate":
            self._send_json({"status": "error", "message": "Invalid route"}, code=404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        data = {key: values[0] if len(values) == 1 else values for key, values in form.items()}

        request_text = data.get("request", "").strip()
        redirect_url = data.get("redirect_url", "about:blank").strip() or "about:blank"
        template_name = data.get("template", "stealth").strip() or "stealth"
        title = data.get("title", "Request Validation").strip() or "Request Validation"

        if not request_text:
            self._send_json({"status": "error", "message": "Request payload is required"}, code=400)
            return

        try:
            method, url, params, payload_type, _headers = parse_raw_http(request_text)
            html = generate_html_poc(
                method=method,
                url=url,
                params=params,
                payload_type=payload_type,
                redirect_url=redirect_url,
                title=title,
                template_name=template_name,
            )
        except Exception as exc:  # pragma: no cover - product guardrail
            self._send_json({"status": "error", "message": f"Parsing failed: {exc}"}, code=400)
            return

        output_name = f"{slugify(title)}-{slugify(method)}-{len(list(GENERATED_DIR.iterdir())) + 1}.html"
        output_path = GENERATED_DIR / output_name
        output_path.write_text(html, encoding="utf-8")

        self._send_json(
            {
                "status": "ok",
                "file": output_name,
                "path": str(output_path),
                "preview_url": f"/preview?file={urllib.parse.quote(output_name)}",
                "method": method,
                "payload_type": payload_type,
                "target_url": url,
            }
        )

    def _send_html(self, html: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _send_json(self, payload: Dict[str, str], code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def find_available_port(host: str, start_port: int, end_port: int = 8100) -> int:
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    raise OSError(f"No free port available between {start_port} and {end_port}")


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    requested_port = int(os.environ.get("PORT", "8000"))
    port = find_available_port(host, requested_port)
    server = ThreadingHTTPServer((host, port), PoCRequestHandler)
    print(f"[+] Starting RequestForge dashboard on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
