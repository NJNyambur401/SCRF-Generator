import unittest

import csrf_generator


class RedTeamGeneratorTests(unittest.TestCase):
    def test_parse_get_request(self):
        raw = """GET /profile?user=customer-2451&role=admin HTTP/1.1
Host: secure-portal.internal

"""
        method, url, params, payload_type, headers = csrf_generator.parse_raw_http(raw)
        self.assertEqual(method, "GET")
        self.assertEqual(url, "https://secure-portal.internal/profile")
        self.assertEqual(params["user"], "customer-2451")
        self.assertEqual(params["role"], "admin")
        self.assertEqual(payload_type, "URL_ENCODED")
        self.assertIn("host", headers)

    def test_parse_json_post_request(self):
        raw = """POST /api/session HTTP/1.1
Host: secure-portal.internal
Content-Type: application/json

{"user_id":"2451","action":"update_profile"}
"""
        method, url, params, payload_type, headers = csrf_generator.parse_raw_http(raw)
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://secure-portal.internal/api/session")
        self.assertEqual(params["user_id"], "2451")
        self.assertEqual(params["action"], "update_profile")
        self.assertEqual(payload_type, "JSON")

    def test_generate_html_poc_contains_auto_submit(self):
        html = csrf_generator.generate_html_poc(
            method="POST",
            url="https://secure-portal.internal/api/session",
            params={"user_id": "2451", "action": "update_profile"},
            payload_type="JSON",
            redirect_url="about:blank",
            title="Request Validation",
            template_name="stealth",
        )
        self.assertIn("https://secure-portal.internal/api/session", html)
        self.assertIn("fetch", html.lower())
        self.assertIn("about:blank", html)


if __name__ == "__main__":
    unittest.main()
