import asyncio
import hashlib
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from lens import router
from lens.submissions import list_submissions


class LeadSubmissionTests(unittest.TestCase):
    def entry(self, timestamp, message):
        return {"timestamp": timestamp, "message": message}

    def test_list_returns_matching_metadata_newest_first(self):
        older_payload = '{\n  "partnerLoanId": "lead-123",\n  "amount": 10\n}'
        newer_payload = '{"partnerLoanId":"lead-123","amount":20}'
        entries = [
            self.entry(
                "2026-10-13T10:29:54.971000+00:00",
                "[FeignKeilodofinClient#saveLoan] " + older_payload,
            ),
            self.entry(
                "2026-10-14T10:29:54.971000+00:00",
                "[FeignKeilodofinClient#saveLoan]\n" + newer_payload,
            ),
            self.entry(
                "2026-10-15T10:29:54.971000+00:00",
                '[FeignKeilodofinClient#saveLoan] {"partnerLoanId":"lead-1234"}',
            ),
            self.entry(
                "2026-10-16T10:29:54.971000+00:00",
                "[FeignKeilodofinClient#saveLoan] {malformed JSON}",
            ),
        ]
        with patch("lens.submissions.loki_query", new=AsyncMock(return_value=entries)) as loki:
            response = asyncio.run(list_submissions("lead-123", 7, "prod"))

        self.assertEqual(response["count"], 2)
        self.assertEqual(
            [item["timestamp"] for item in response["submissions"]],
            ["2026-10-14T10:29:54.971000+00:00", "2026-10-13T10:29:54.971000+00:00"],
        )
        self.assertTrue(
            all(set(item) == {"submission_id", "timestamp", "payload_size"}
                for item in response["submissions"])
        )
        self.assertIn('{env="prod",app="prod"}', loki.await_args.args[0])
        self.assertIn("[FeignKeilodofinClient#saveLoan]", loki.await_args.args[0])
        self.assertEqual(loki.await_args.args[1:3], (7 * 24 * 60, 5000))

    def test_preview_and_download_return_exact_payload(self):
        payload = '{\n  "partnerLoanId": "lead-123",\n  "amount": 10\n}'
        timestamp = "2026-10-13T10:29:54.971000+00:00"
        timestamp_us = int(
            (datetime.fromisoformat(timestamp).astimezone(timezone.utc)
             - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000
        )
        submission_id = f"{timestamp_us}-{hashlib.sha256(payload.encode()).hexdigest()}"
        entries = [self.entry(
            timestamp, "[FeignKeilodofinClient#saveLoan] " + payload,
        )]

        with patch("lens.submissions.loki_query", new=AsyncMock(return_value=entries)) as loki:
            preview = asyncio.run(router.lead_submission_payload(
                "lead-123", submission_id, environment="uat",
            ))
        self.assertEqual(preview["payload"], {"partnerLoanId": "lead-123", "amount": 10})
        self.assertEqual(preview["payload_size"], len(payload.encode()))
        start = loki.await_args.kwargs["window_start"]
        end = loki.await_args.kwargs["window_end"]
        self.assertLessEqual((end - start).total_seconds(), 5)

        with patch("lens.submissions.loki_query", new=AsyncMock(return_value=entries)):
            download = asyncio.run(router.lead_submission_payload(
                "lead-123", submission_id, download=True,
            ))
        self.assertEqual(download.body.decode(), payload)
        self.assertEqual(
            download.headers["content-disposition"],
            f'attachment; filename="submission-{submission_id}.json"',
        )

    def test_retrieval_rejects_invalid_id_and_reports_missing_payload(self):
        with self.assertRaises(HTTPException) as invalid:
            asyncio.run(router.lead_submission_payload("lead-123", "invalid"))
        self.assertEqual(invalid.exception.status_code, 400)

        with (
            patch("lens.submissions.loki_query", new=AsyncMock(return_value=[])),
            self.assertRaises(HTTPException) as missing,
        ):
            asyncio.run(router.lead_submission_payload(
                "lead-123", "1791887394971000-" + "0" * 64,
            ))
        self.assertEqual(missing.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
