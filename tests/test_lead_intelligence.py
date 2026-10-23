import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from core import config
from lens import lead_service, parser, router, schemas


class LeadIntelligenceTests(unittest.TestCase):
    @staticmethod
    def entry(second, message, request_id="Req_1234", user="test_user", level="INFO"):
        timestamp = datetime(2026, 10, 23, 12, 0, second, tzinfo=timezone.utc)
        nanoseconds = str(int(timestamp.timestamp() * 1_000_000_000))
        raw = (
            f"2026-10-23 12:00:{second:02d}.000 [worker-1] {level} "
            f"[{request_id},{user}] [123] --- example.Controller : {message}"
        )
        return parser.parse_entry(nanoseconds, raw)

    def test_exact_alias_association_rejects_substrings_and_unrelated_values(self):
        lead = "12345"
        accepted = self.entry(1, '{"leadId":"12345","amount":12345}')
        rejected = [
            self.entry(2, '{"leadId":"123456"}'),
            self.entry(3, '{"applicantId":"912345"}'),
            self.entry(4, '{"message":"leadId=12345"}'),
            self.entry(5, '{"createdAt":"2026-10-23T12:00:00Z","amount":12345}'),
            self.entry(6, '{"notleadId":"12345"}'),
        ]
        self.assertEqual(lead_service.matched_lead_aliases(accepted, lead), ["leadId"])
        for item in rejected:
            self.assertEqual(lead_service.matched_lead_aliases(item, lead), [])
        self.assertEqual(
            lead_service.matched_lead_aliases(self.entry(7, "applicantId=12345"), lead),
            ["applicantId"],
        )
        for index, alias in enumerate(("leadId", "applicantId", "applicationId", "partnerLoanId"), 8):
            self.assertEqual(
                lead_service.matched_lead_aliases(self.entry(index, f'"{alias}":"12345"'), lead),
                [alias],
            )

    def test_request_id_extraction_uses_existing_logback_mdc_shape(self):
        raw = (
            "2026-10-23 12:00:01.000 [worker-1] NOTICE "
            "[Req_1234,test_user] [123] --- example.Controller : event"
        )
        entry = parser.parse_entry("1792761601000000000", raw)
        self.assertIsNone(entry["request_id"])
        self.assertEqual(parser.extract_request_id(entry), "Req_1234")

    def test_identifier_aliases_are_candidates_and_cross_alias_is_ambiguous(self):
        lines = [
            self.entry(1, '{"leadId":"12345","applicationId":"67890"}'),
            self.entry(2, "applicantId=12345"),
        ]
        with patch("lens.lead_service.loki_query", new=AsyncMock(return_value=lines)):
            result = asyncio.run(lead_service.investigate_lead("12345", "uat", 7))
        self.assertEqual(result["retrieval"]["identifierCorrelation"], "ambiguous")
        self.assertEqual(result["retrieval"]["aliasesObserved"], ["leadId", "applicantId"])
        self.assertIn("correlation remains ambiguous", " ".join(result["limitations"]))
        self.assertTrue(all(item["source"] == "lead_match" for item in result["evidence"]))

    def test_request_ids_correlate_through_mdc_parser_and_evidence_is_deduplicated_sorted(self):
        first = self.entry(2, '{"leadId":"L-1"}')
        middle = self.entry(1, "REQ START | method=POST | uri=/lead", request_id="Req_1234")
        last = self.entry(3, "ERROR downstream failed", request_id="Req_1234", level="ERROR")

        async def fake_loki(query, *args, **kwargs):
            if "Req_1234" in query:
                return [last, middle, last]
            return [first, first]

        with patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=fake_loki)):
            result = asyncio.run(lead_service.investigate_lead("L-1", "uat", 7))
        self.assertEqual(result["relatedRequestIds"], ["Req_1234"])
        self.assertEqual([item["timestamp"] for item in result["evidence"]],
                         sorted(item["timestamp"] for item in result["evidence"]))
        self.assertEqual(len(result["evidence"]), 3)
        self.assertEqual(result["requestTimelines"][0]["request"]["requestId"], "Req_1234")
        self.assertEqual(
            {event["requestId"] for event in result["requestTimelines"][0]["events"]},
            {"Req_1234"},
        )
        self.assertTrue(all("evidenceRef" in event for event in result["requestTimelines"][0]["events"]))

    def test_loki_pagination_splits_saturated_ranges_and_observes_limits(self):
        first_page = [self.entry(1, '{"leadId":"L-1"}')]
        with (
            patch.object(config, "LEAD_LOKI_PAGE_SIZE", 1),
            patch.object(config, "LEAD_MAX_LOKI_QUERIES", 10),
            patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=[first_page, [], []])) as loki,
        ):
            start = datetime.now(timezone.utc) - timedelta(days=1)
            end = datetime.now(timezone.utc)
            entries, stats = asyncio.run(
                lead_service._bounded_loki_query("bounded", start, end, 10)
            )
        self.assertEqual(len(entries), 1)
        self.assertEqual(stats["queryCount"], 3)
        self.assertFalse(stats["truncated"])
        self.assertEqual(loki.await_count, 3)

        with (
            patch.object(config, "LEAD_LOKI_PAGE_SIZE", 1),
            patch("lens.lead_service.loki_query", new=AsyncMock(return_value=first_page)),
        ):
            entries, stats = asyncio.run(
                lead_service._bounded_loki_query("bounded", start, end, 1)
            )
        self.assertEqual(len(entries), 1)
        self.assertTrue(stats["truncated"])

    def test_discovered_request_ids_are_capped_and_reported(self):
        matches = [
            self.entry(1, '{"leadId":"L-1"}', request_id="Req_1234"),
            self.entry(2, '{"leadId":"L-1"}', request_id="Req_5678"),
        ]

        async def fake_loki(query, *args, **kwargs):
            return [] if "Req_1234" in query or "Req_5678" in query else matches

        with (
            patch.object(config, "LEAD_MAX_REQUEST_IDS", 1),
            patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=fake_loki)),
        ):
            result = asyncio.run(lead_service.investigate_lead("L-1", "uat", 7))
        self.assertEqual(result["relatedRequestIds"], ["Req_1234"])
        self.assertTrue(result["retrieval"]["requestIdsTruncated"])
        self.assertIn("Related request IDs were capped", " ".join(result["limitations"]))

    def test_environment_isolation_and_configured_range_cap_are_reported(self):
        with (
            patch.object(config, "LEAD_MAX_DAYS", 2),
            patch("lens.lead_service.loki_query", new=AsyncMock(return_value=[])) as loki,
        ):
            result = asyncio.run(lead_service.investigate_lead("L-1", "prod", 7))
        self.assertEqual(result["searchedDays"], 2)
        self.assertIn("Requested range was capped", result["limitations"][0])
        self.assertIn('{env="prod",app="prod"}', loki.await_args.args[0])

    def test_ai_context_redacts_lead_identifiers_and_records_context_truncation(self):
        investigation = {
            "environment": "uat",
            "searchedDays": 7,
            "retrieval": {"identifierCorrelation": "candidate"},
            "limitations": [],
            "evidence": [{
                "evidenceRef": "evidence-1", "timestamp": "2026-10-23T12:00:00+00:00",
                "requestId": "Req_1234", "username": "test_user", "severity": "INFO",
                "source": "lead_match", "matchedAliases": ["leadId"], "raw": "",
                "message": '{"leadId":"private-lead","result":"ok"}',
            }],
        }
        with patch.object(config, "LEAD_AI_MAX_CONTEXT_CHARS", 1000):
            context, refs, truncated = lead_service.build_lead_ai_context(investigation)
        self.assertNotIn("private-lead", context)
        self.assertNotIn("Req_1234", context)
        self.assertNotIn("test_user", context)
        self.assertIn('"hasRequestId":true', context)
        self.assertIn("[LEAD_ID]", context)
        self.assertEqual(refs, {"evidence-1"})
        self.assertFalse(truncated)

    def test_analysis_rejects_unknown_actions_and_requires_evidence_navigation_context(self):
        with self.assertRaises(ValidationError):
            schemas.LeadIntelligenceModel.model_validate({
                "narrative": "Summary",
                "confidence": "low",
                "journeyTimeline": [],
                "findingsAndAnomalies": [],
                "rootCauseAssessment": {"observedFacts": [], "possibleCauses": [], "confidence": "low"},
                "suggestedChecks": [{
                    "action": "INVENTED_DESTINATION",
                    "title": "Go elsewhere",
                    "reason": "Unsupported",
                    "priority": "low",
                    "evidenceRefs": ["evidence-1"],
                }],
                "recommendedNextSteps": [],
                "limitations": [],
                "model": config.GROQ_MODEL,
            })
        investigation = {
            "leadId": "L-1",
            "relatedRequestIds": ["Req_1234"],
            "evidence": [{
                "evidenceRef": "evidence-1", "timestamp": "2026-10-23T12:00:00+00:00",
                "requestId": "Req_1234", "username": "test_user", "severity": "ERROR",
                "source": "lead_match", "matchedAliases": ["leadId"], "message": "failure",
            }],
            "retrieval": {"identifierCorrelation": "candidate"},
            "limitations": [],
        }
        base = {
            "narrative": "Observed failure.",
            "latestObservedActivity": None,
            "currentStage": None,
            "summaryEvidenceRefs": ["evidence-1"],
            "stageEvidenceRefs": [],
            "confidence": "low",
            "journeyTimeline": [],
            "findingsAndAnomalies": [],
            "rootCauseAssessment": {"observedFacts": [], "possibleCauses": [], "confidence": "low"},
            "suggestedChecks": [{
                "action": "REQUEST_INVESTIGATION", "title": "Review request",
                "reason": "Inspect correlated request.", "priority": "medium",
                "evidenceRefs": ["evidence-1"],
            }],
            "recommendedNextSteps": [],
            "limitations": [],
            "model": config.GROQ_MODEL,
        }
        result = lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        self.assertEqual(result["suggestedChecks"][0]["context"], {
            "environment": "uat", "requestId": "Req_1234",
        })
        base["narrative"] = "The lead was successfully submitted."
        with self.assertRaises(HTTPException):
            lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        base["narrative"] = "The lead is stuck because there was no recent activity."
        with self.assertRaises(HTTPException):
            lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        base["narrative"] = "Observed failure."
        base["suggestedChecks"][0] = {
            "action": "USER_ACTIVITY", "title": "Review user activity",
            "reason": "Check the observed user's activity.", "priority": "low",
            "evidenceRefs": ["evidence-1"],
        }
        result = lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        self.assertEqual(result["suggestedChecks"][0]["context"], {
            "environment": "uat", "username": "test_user",
        })

        base["suggestedChecks"][0]["evidenceRefs"] = []
        with self.assertRaises(HTTPException) as raised:
            lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        self.assertEqual(raised.exception.status_code, 502)

    def test_ai_claim_cannot_combine_ambiguous_alias_groups(self):
        investigation = {
            "leadId": "12345", "environment": "uat", "relatedRequestIds": [],
            "evidence": [
                {"evidenceRef": "evidence-1", "timestamp": "2026-10-23T12:00:00+00:00",
                 "requestId": None, "username": None, "matchedAliases": ["leadId"],
                 "message": "lead event"},
                {"evidenceRef": "evidence-2", "timestamp": "2026-10-23T12:00:01+00:00",
                 "requestId": None, "username": None, "matchedAliases": ["applicantId"],
                 "message": "applicant event"},
            ],
            "retrieval": {"identifierCorrelation": "ambiguous"},
            "limitations": [],
        }
        result = {
            "narrative": "Candidate evidence is ambiguous.", "summaryEvidenceRefs": ["evidence-1"],
            "latestObservedActivity": None, "currentStage": None, "stageEvidenceRefs": [],
            "confidence": "low", "journeyTimeline": [{
                "event": "Two candidate observations", "description": "They may be related.",
                "evidenceRefs": ["evidence-1", "evidence-2"],
            }],
            "findingsAndAnomalies": [],
            "rootCauseAssessment": {"observedFacts": [], "possibleCauses": [], "confidence": "low"},
            "suggestedChecks": [], "recommendedNextSteps": [], "limitations": [],
            "model": config.GROQ_MODEL,
        }
        with self.assertRaises(HTTPException) as raised:
            lead_service.validate_lead_analysis(result, investigation, {"evidence-1", "evidence-2"})
        self.assertEqual(raised.exception.status_code, 502)

    def test_new_uat_routes_enforce_existing_investigation_token(self):
        with (
            patch("core.security.REQUEST_INVESTIGATION_TOKEN", "configured-token"),
            patch("lens.router.investigate_lead", new=AsyncMock()) as investigate,
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(router.lead_investigation(
                    "L-1", access_token="wrong-token", environment="uat"
                ))
        self.assertEqual(raised.exception.status_code, 401)
        investigate.assert_not_awaited()

    def test_production_analysis_never_calls_groq_without_server_authorization(self):
        with (
            patch.object(config, "ALLOW_PROD_AI", False),
            patch("core.security.REQUEST_INVESTIGATION_TOKEN", "configured-token"),
            patch.dict("os.environ", {"API_TOKEN": "secret"}),
            patch("lens.router.call_lead_groq", new=AsyncMock()) as groq,
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(router.analyze_lead(
                    "L-1", access_token="configured-token", environment="prod"
                ))
        self.assertEqual(raised.exception.status_code, 403)
        groq.assert_not_awaited()

    def test_production_access_fails_closed_without_server_token_configuration(self):
        with (
            patch("core.security.REQUEST_INVESTIGATION_TOKEN", None),
            patch("lens.router.investigate_lead", new=AsyncMock()) as investigate,
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(router.lead_investigation("L-1", environment="prod"))
        self.assertEqual(raised.exception.status_code, 503)
        investigate.assert_not_awaited()

    def test_existing_production_log_routes_fail_closed(self):
        with (
            patch("core.security.REQUEST_INVESTIGATION_TOKEN", None),
            patch("lens.router.loki_query", new=AsyncMock()) as loki,
        ):
            calls = (
                lambda: router.request_timeline("Req_1234", environment="prod"),
                lambda: router.user_activity("test_user", environment="prod"),
                lambda: router.recent_errors(environment="prod"),
                lambda: router.analyze_request(
                    schemas.AnalyzeRequest(text="sample"), environment="prod"
                ),
            )
            for call in calls:
                with self.subTest(call=call):
                    with self.assertRaises(HTTPException) as raised:
                        asyncio.run(call())
                    self.assertEqual(raised.exception.status_code, 503)
        loki.assert_not_awaited()

    def test_existing_production_analysis_requires_separate_ai_authorization(self):
        with (
            patch("core.security.REQUEST_INVESTIGATION_TOKEN", "configured-token"),
            patch.object(config, "ALLOW_PROD_AI", False),
            patch.dict("os.environ", {"API_TOKEN": "secret"}),
            patch("lens.router.request_timeline", new=AsyncMock()) as timeline,
            patch("lens.router.call_groq", new=AsyncMock()) as groq,
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(router.analyze_request(
                    schemas.AnalyzeRequest(requestId="Req_1234"),
                    access_token="configured-token",
                    environment="prod",
                ))
        self.assertEqual(raised.exception.status_code, 403)
        timeline.assert_not_awaited()
        groq.assert_not_awaited()

    def test_empty_evidence_returns_explicit_unknown_stage_without_ai(self):
        with (
            patch.dict("os.environ", {"API_TOKEN": "secret"}),
            patch("lens.router.investigate_lead", new=AsyncMock(return_value={
                "leadId": "L-1", "environment": "uat", "requestedDays": 7, "searchedDays": 7,
                "candidateCount": 0, "relatedRequestIds": [], "evidence": [], "requestTimelines": [],
                "retrieval": {"identifierCorrelation": "candidate"}, "limitations": ["No logs found"],
            })),
            patch("lens.router.call_lead_groq", new=AsyncMock()) as groq,
        ):
            response = asyncio.run(router.analyze_lead("L-1"))
        self.assertIsNone(response["leadSummary"]["currentStage"])
        self.assertIn("No logs found", response["limitations"])
        self.assertIn("Current stage could not be established", response["limitations"][-1])
        groq.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
