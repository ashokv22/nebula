import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from lens import parser, router


TIMESTAMP_NS = "1791887394971000000"
REQUEST_ID = "pH8NUNKM"
USERNAME = "super_admin"


def log_line(level: str, message: str, *, legacy: bool) -> str:
    level = f"\x1b[1;32m{level}\x1b[0;39m"
    prefix = "2026-10-13 10:29:54.971 "
    if legacy:
        prefix += "[worker-1] "
    prefix += f"{level} [{REQUEST_ID},{USERNAME}] "
    if legacy:
        prefix += "[123] "
    return f"{prefix}--- x.y.Logger : {message}"


class LogbackFormatTests(unittest.TestCase):
    def test_parser_supports_old_and_new_colored_formats(self):
        for legacy in (True, False):
            with self.subTest(legacy=legacy):
                entry = parser.parse_entry(
                    TIMESTAMP_NS,
                    log_line("INFO", "REQ START | method=POST | uri=/api/test", legacy=legacy),
                )

                self.assertEqual(entry["level"], "INFO")
                self.assertEqual(entry["request_id"], REQUEST_ID)
                self.assertEqual(entry["user"], USERNAME)
                self.assertEqual(entry["logger"], "x.y.Logger")
                self.assertEqual(entry["message"], "REQ START | method=POST | uri=/api/test")
                self.assertEqual(entry["thread"], "worker-1" if legacy else None)
                self.assertEqual(entry["pid"], "123" if legacy else None)
                self.assertNotIn("\x1b", entry["raw"])
                self.assertTrue(parser.request_entry_matches(entry, REQUEST_ID))
                self.assertFalse(parser.request_entry_matches(entry, "different"))

    def test_request_timeline_includes_new_format_entries(self):
        entry = parser.parse_entry(
            TIMESTAMP_NS, log_line("INFO", "REQ START | method=POST | uri=/api/test", legacy=False)
        )
        with patch("lens.router.loki_query", new=AsyncMock(return_value=[entry])):
            response = asyncio.run(router.request_timeline(REQUEST_ID))

        self.assertEqual(response["count"], 1)
        self.assertEqual(response["timeline"][0]["request_id"], REQUEST_ID)
        self.assertIsNone(response["timeline"][0]["thread"])
        self.assertIsNone(response["timeline"][0]["pid"])

    def test_user_activity_includes_new_format_entries(self):
        entry = parser.parse_entry(
            TIMESTAMP_NS, log_line("INFO", "REQ START | method=POST | uri=/api/test", legacy=False)
        )
        with patch("lens.router.loki_query", new=AsyncMock(return_value=[entry])):
            response = asyncio.run(router.user_activity(USERNAME))

        self.assertEqual(response["summary"]["totalRequests"], 1)
        self.assertEqual(response["requests"][0]["requestId"], REQUEST_ID)
        self.assertEqual(response["requests"][0]["uri"], "/api/test")

    def test_recent_errors_includes_new_format_entries(self):
        entry = parser.parse_entry(
            TIMESTAMP_NS, log_line("ERROR", "Request failed", legacy=False)
        )
        with patch(
            "lens.router.loki_query",
            new=AsyncMock(side_effect=[[entry], [entry]]),
        ):
            response = asyncio.run(router.recent_errors())

        self.assertEqual(response["count"], 1)
        self.assertEqual(response["errors"][0]["request_id"], REQUEST_ID)
        self.assertEqual(response["errors"][0]["user"], USERNAME)

    def test_malformed_entries_do_not_match_ids_in_message_content(self):
        malformed = parser.parse_entry(
            TIMESTAMP_NS,
            f"2026-10-13 10:29:54.971 ERROR unrelated : message mentions [{REQUEST_ID},{USERNAME}]",
        )

        self.assertIsNone(malformed["request_id"])
        self.assertIsNone(malformed["pid"])
        self.assertFalse(parser.request_entry_matches(malformed, REQUEST_ID))
        self.assertFalse(parser.request_entry_matches({"raw": "malformed"}, REQUEST_ID))


if __name__ == "__main__":
    unittest.main()
