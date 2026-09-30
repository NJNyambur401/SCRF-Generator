# RequestForge

RequestForge is an enterprise-style workflow for generating browser-based request validation payloads from raw HTTP traffic. It combines a clean dashboard experience with a Python backend that parses requests, identifies payload structures, and exports polished validation pages for authorized testing workflows.

## What it includes

- Raw HTTP request parsing for GET, POST, and JSON payloads
- Theme-based HTML PoC generation for different delivery styles
- Fast local dashboard served via a Python web shell
- One-click generation flow with redirect controls and title customization
- Exported HTML output for quick distribution or review

## Run the dashboard

```bash
python3 app.py
```

Then open the local dashboard:

```text
http://127.0.0.1:8000
```

## CLI generation mode

You can still use the original generator directly:

```bash
python3 csrf_generator.py --help
```

Example:

```bash
python3 csrf_generator.py \
  --request-file request.txt \
  --redirect-url about:blank \
  --output poc.html \
  --template stealth
```

## Example request input

```http
POST /api/session HTTP/1.1
Host: secure-portal.internal
Content-Type: application/json

{"user_id":"2451","action":"update_profile"}
```

The generator identifies the request method, recognizes the payload type, builds the validation page, and saves the generated HTML locally.

## Product note

This project is intended for authorized security testing, red-team exercises, and defensive research in environments where explicit permission is in place. Keep testing scoped, documented, and aligned with your engagement boundaries.
