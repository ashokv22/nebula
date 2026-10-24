import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from core import config
from core.security import (
    EXTERNAL_AI,
    INTERNAL_INVESTIGATION,
    redact_lead_entry,
    redact_lead_evidence_text,
)
from lens import analyzer, lead_service, parser, router, schemas


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

    def call_lead_groq_with_content(self, content, finish_reason="stop"):
        provider_response = SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: {
                "choices": [{
                    "message": {"content": content},
                    "finish_reason": finish_reason,
                }],
                "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
            },
        )
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        client.post = AsyncMock(return_value=provider_response)
        with (
            patch("lens.analyzer.httpx.AsyncClient", return_value=client),
            patch.dict("os.environ", {"API_TOKEN": "synthetic-token"}),
        ):
            return asyncio.run(analyzer.call_lead_groq("{}"))

    @staticmethod
    def valid_lead_model_output():
        return {
            "narrative": "A candidate event was observed.",
            "latestObservedActivity": None,
            "currentStage": None,
            "summaryEvidenceRefs": ["evidence-1"],
            "stageEvidenceRefs": [],
            "confidence": "low",
            "journeyTimeline": [{
                "event": "Candidate event",
                "description": "A candidate event was observed.",
                "evidenceRefs": ["evidence-1"],
            }],
            "findingsAndAnomalies": [],
            "rootCauseAssessment": {
                "observedFacts": [],
                "possibleCauses": [],
                "confidence": "low",
            },
            "suggestedChecks": [],
            "recommendedNextSteps": [],
            "limitations": [],
            "model": config.GROQ_MODEL,
        }

    def test_lead_model_rejects_reported_schema_mismatch_and_accepts_valid_shape(self):
        invalid = self.valid_lead_model_output()
        invalid["summaryEvidenceRefs"] = [f"evidence-{index}" for index in range(6)]
        invalid["stageEvidenceRefs"] = "evidence-1"
        invalid["journeyTimeline"] = [{
            "event": f"event-{index}",
            "evidenceRefs": ["evidence-1"],
            "timestamp": "unrequested",
            "requestId": "unrequested",
        } for index in range(6)]
        invalid["suggestedChecks"] = [{
            "action": "UNSAFE_NAVIGATION",
            "title": "Go somewhere",
            "reason": "Unsupported action",
            "priority": "low",
            "evidenceRefs": ["evidence-1"],
        }]
        with self.assertRaises(ValidationError) as raised:
            schemas.LeadIntelligenceModel.model_validate(invalid)

        errors = raised.exception.errors()
        locations = [error["loc"] for error in errors]
        self.assertIn(("summaryEvidenceRefs",), locations)
        self.assertIn(("stageEvidenceRefs",), locations)
        self.assertIn(("journeyTimeline", 0, "description"), locations)
        self.assertIn(("journeyTimeline", 0, "timestamp"), locations)
        self.assertIn(("journeyTimeline", 0, "requestId"), locations)
        self.assertIn(("suggestedChecks", 0, "action"), locations)

        valid = schemas.LeadIntelligenceModel.model_validate(self.valid_lead_model_output())
        self.assertEqual(valid.stageEvidenceRefs, [])
        self.assertEqual(valid.journeyTimeline[0].model_dump(), {
            "description": "A candidate event was observed.",
            "evidenceRefs": ["evidence-1"],
            "event": "Candidate event",
        })

    def test_lead_prompt_includes_authoritative_model_schema(self):
        provider_response = SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{
                "message": {"content": json.dumps(self.valid_lead_model_output())},
                "finish_reason": "stop",
            }]},
        )
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        client.post = AsyncMock(return_value=provider_response)
        with (
            patch("lens.analyzer.httpx.AsyncClient", return_value=client),
            patch.dict("os.environ", {"API_TOKEN": "synthetic-token"}),
        ):
            result = asyncio.run(analyzer.call_lead_groq("{}"))

        sent = client.post.await_args.kwargs["json"]
        system_prompt = sent["messages"][0]["content"]
        schema = json.dumps(
            analyzer._lead_groq_json_schema(),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        self.assertIn(schema, system_prompt)
        self.assertIn("do not output the schema", system_prompt)
        self.assertIn("single response object", system_prompt)
        response_format = sent["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertTrue(response_format["json_schema"]["strict"])
        self.assertEqual(response_format["json_schema"]["schema"], analyzer._lead_groq_json_schema())
        self.assertEqual(response_format["json_schema"]["schema"]["type"], "object")
        self.assertEqual(result["journeyTimeline"][0]["description"], "A candidate event was observed.")

    def test_lead_provider_schema_enforces_object_roots_and_complete_nested_shapes(self):
        schema = analyzer._lead_groq_json_schema()

        def assert_strict_objects(node):
            if isinstance(node, list):
                for item in node:
                    assert_strict_objects(item)
            elif isinstance(node, dict):
                self.assertNotIn("$ref", node)
                if node.get("type") == "object":
                    properties = node.get("properties", {})
                    self.assertEqual(set(node.get("required", [])), set(properties))
                    self.assertIs(node.get("additionalProperties"), False)
                for value in node.values():
                    assert_strict_objects(value)

        self.assertEqual(schema["type"], "object")
        assert_strict_objects(schema)

    def test_lead_groq_reports_array_double_encoded_and_invalid_roots(self):
        cases = (
            (json.dumps([{
                "narrative": "SYNTHETIC_PRIVATE_RESPONSE_VALUE",
                "suggestedChecks": [{"action": "PRIVATE_ACTION"}],
                "UNRECOGNIZED_PRIVATE_KEY": "PRIVATE_VALUE",
            }]), "list", False),
            (json.dumps(json.dumps(self.valid_lead_model_output())), "str", True),
            (json.dumps(42), "int", False),
        )
        for content, expected_type, double_encoded in cases:
            with self.subTest(expected_type=expected_type, double_encoded=double_encoded):
                with self.assertLogs("lens.analyzer", level="WARNING") as captured:
                    with self.assertRaises(HTTPException):
                        self.call_lead_groq_with_content(content)
                diagnostic = captured.records[0].lead_ai_diagnostic
                self.assertEqual(diagnostic["stage"], "pydantic_validation")
                self.assertEqual(diagnostic["parsed_root_type"], expected_type)
                self.assertEqual(diagnostic["validation_input_type"], expected_type)
                self.assertEqual(diagnostic["json_double_encoded"], double_encoded)
                if expected_type == "list":
                    message = captured.records[0].getMessage()
                    self.assertIn('"response_chars":', message)
                    self.assertIn('"response_shape":{"type":"list","length":1', message)
                    self.assertIn('"known_keys":["narrative","suggestedChecks"]', message)
                    self.assertIn('"unknown_key_count":1', message)
                    self.assertNotIn("SYNTHETIC_PRIVATE_RESPONSE_VALUE", message)
                    self.assertNotIn("UNRECOGNIZED_PRIVATE_KEY", message)
                    self.assertNotIn("PRIVATE_VALUE", message)

    def test_lead_groq_root_keys_are_limited_to_known_schema_names(self):
        private_key = "CUSTOM_PRIVATE_KEY"
        with self.assertLogs("lens.analyzer", level="WARNING") as captured:
            with self.assertRaises(HTTPException):
                self.call_lead_groq_with_content(json.dumps({
                    "narrative": "Candidate summary",
                    private_key: "PRIVATE_VALUE",
                }))
        diagnostic = captured.records[0].lead_ai_diagnostic
        self.assertEqual(diagnostic["parsed_root_type"], "dict")
        self.assertEqual(diagnostic["root_keys"], ["narrative"])
        self.assertNotIn(private_key, captured.records[0].getMessage())
        self.assertNotIn("PRIVATE_VALUE", captured.records[0].getMessage())

    def test_groq_diagnostics_identify_model_validation_fields_without_input_values(self):
        unsafe_value = "SYNTHETIC_PRIVATE_CUSTOMER_VALUE"
        content = json.dumps({
            "suggestedChecks": [{
                "action": unsafe_value,
                "title": "Review",
                "reason": "Check the evidence",
                "priority": "low",
                "evidenceRefs": ["evidence-1"],
            }],
        })
        with self.assertLogs("lens.analyzer", level="WARNING") as captured:
            with self.assertRaises(HTTPException) as raised:
                self.call_lead_groq_with_content(content, finish_reason="length")

        self.assertEqual(raised.exception.status_code, 502)
        self.assertEqual(raised.exception.detail, "Groq returned invalid Lead Intelligence")
        diagnostic = captured.records[0].lead_ai_diagnostic
        formatted_message = captured.records[0].getMessage()
        self.assertIn('"stage":"pydantic_validation"', formatted_message)
        self.assertIn('"finish_reason":"length"', formatted_message)
        self.assertIn('"total_tokens":200', formatted_message)
        self.assertNotIn(unsafe_value, formatted_message)
        self.assertEqual(diagnostic["stage"], "pydantic_validation")
        self.assertIn("suggestedChecks.0.action", diagnostic["field_paths"])
        self.assertEqual(diagnostic["invalid_suggested_check_count"], 1)
        self.assertEqual(diagnostic["finish_reason"], "length")
        self.assertEqual(diagnostic["total_tokens"], 200)
        self.assertNotIn(unsafe_value, str(diagnostic))

    def test_groq_diagnostics_report_json_parse_category_and_position_only(self):
        private_marker = "SYNTHETIC_PRIVATE_RESPONSE_MARKER"
        with self.assertLogs("lens.analyzer", level="WARNING") as captured:
            with self.assertRaises(HTTPException) as raised:
                self.call_lead_groq_with_content('{"value":"' + private_marker)

        self.assertEqual(raised.exception.status_code, 502)
        diagnostic = captured.records[0].lead_ai_diagnostic
        formatted_message = captured.records[0].getMessage()
        self.assertIn('"stage":"json_parsing"', formatted_message)
        self.assertIn('"line":', formatted_message)
        self.assertIn('"column":', formatted_message)
        self.assertEqual(diagnostic["stage"], "json_parsing")
        self.assertEqual(diagnostic["error_type"], "JSONDecodeError")
        self.assertGreater(diagnostic["position"], 0)
        self.assertNotIn(private_marker, str(diagnostic))

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

    def test_large_feign_and_webhook_payloads_are_compacted_before_response_and_ai(self):
        body_marker = "SYNTHETIC_PRIVATE_BODY_MARKER"
        huge_body = json.dumps({
            "leadId": "2977",
            "customerName": body_marker,
            "address": "SYNTHETIC_ADDRESS",
            "payload": "x" * 400_000,
        })
        response_body = json.dumps({
            "leadId": "2977",
            "errorCode": "ER021",
            "payload": "x" * 400_000,
        })
        lines = [
            self.entry(
                1,
                "saveLoan request: POST /v2/partner/loanApplications "
                '{"leadId":"2977"} body=' + huge_body,
            ),
            self.entry(
                2,
                "getLoanStatus response: GET /v1/partner/loanReports/2977 "
                "HTTP/1.1 200 (125ms) " + response_body,
            ),
            self.entry(
                3,
                "External ReverseMapping Payload: "
                '{"leadId":"2977"} ' + huge_body,
            ),
        ]

        async def fake_loki(query, *args, **kwargs):
            return lines

        with (
            patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=fake_loki)),
            patch.object(config, "LEAD_MAX_REQUEST_IDS", 20),
            patch.dict("os.environ", {"API_TOKEN": "synthetic-pseudonym-key"}),
        ):
            result = asyncio.run(lead_service.investigate_lead("2977", "uat", 7))
            ai_context, _, _ = lead_service.build_lead_ai_context(result)

        serialized = json.dumps(result)
        self.assertNotIn(body_marker, serialized)
        self.assertNotIn("SYNTHETIC_ADDRESS", serialized)
        self.assertNotIn(body_marker, ai_context)
        self.assertNotIn("SYNTHETIC_ADDRESS", ai_context)
        self.assertLess(len(serialized), 20_000)
        self.assertEqual(result["candidateCount"], 3)
        evidence_by_type = {item["eventType"]: item for item in result["evidence"]}
        self.assertEqual(
            set(evidence_by_type),
            {"API_REQUEST", "API_RESPONSE", "WEBHOOK_RECEIVED"},
        )
        request = evidence_by_type["API_REQUEST"]
        self.assertTrue(request["payloadOmitted"])
        self.assertEqual(request["apiOperation"], "saveLoan")
        self.assertEqual(request["httpMethod"], "POST")
        self.assertEqual(request["endpointPath"], "/v2/partner/loanApplications")
        self.assertIsNone(request["httpStatus"])
        self.assertIsNone(request["durationMs"])
        response = evidence_by_type["API_RESPONSE"]
        self.assertEqual(response["httpStatus"], 200)
        self.assertEqual(response["durationMs"], 125)
        self.assertEqual(response["errorCode"], "ER021")
        self.assertEqual(response["apiOperation"], "getLoanStatus")
        webhook = evidence_by_type["WEBHOOK_RECEIVED"]
        self.assertTrue(webhook["payloadOmitted"])
        self.assertIsNone(webhook["httpStatus"])
        self.assertTrue(all(item["requestId"] == "Req_1234" for item in result["evidence"]))
        self.assertTrue(all(item["eventCategory"] == "EXTERNAL_API" for item in result["evidence"]))
        self.assertTrue(all(item["evidenceRef"] for item in result["evidence"]))
        self.assertEqual(
            sum(item["eventCategory"] == "BUSINESS_ACTION" for item in result["evidence"]),
            0,
        )
        self.assertEqual(
            {item["eventType"] for item in result["evidence"]},
            {"API_REQUEST", "API_RESPONSE", "WEBHOOK_RECEIVED"},
        )
        self.assertTrue(all("raw" not in item for item in result["evidence"]))
        self.assertTrue(all(body_marker not in item["message"] for item in result["evidence"]))
        self.assertEqual(
            {reference for timeline in result["requestTimelines"] for reference in timeline["evidenceRefs"]},
            {item["evidenceRef"] for item in result["evidence"]},
        )
        self.assertEqual(result["requestTimelines"][0]["eventCount"], 3)
        self.assertEqual(result["requestTimelines"][0]["failureCount"], 0)
        self.assertNotIn("events", result["requestTimelines"][0])
        schemas.LeadInvestigationResponse.model_validate(result)

    def test_unrecognized_request_timeline_entries_are_not_compacted(self):
        entry = self.entry(1, "ordinary application diagnostic without an API payload")
        self.assertIs(lead_service.compact_large_api_entry(entry), entry)

    def test_known_operation_with_unknown_event_direction_still_omits_body(self):
        body = '{"leadId":"2977","customerName":"SYNTHETIC_PRIVATE_VALUE","payload":"' + "x" * 5000 + '"}'
        entry = self.entry(1, "saveLoan operation: " + body)
        compacted = lead_service.compact_large_api_entry(entry)
        self.assertTrue(compacted["leadApiMetadata"]["payloadOmitted"])
        self.assertIsNone(compacted["leadApiMetadata"]["eventType"])
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", compacted["raw"])
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", compacted["message"])

    def test_sensitive_customer_fields_are_redacted_from_raw_and_message(self):
        message = (
            'LeadDto(customerName=Jane Doe, dob=1990-01-02, phoneNumber=9876543210, '
            'address=12 Example Road, pinCode=560001, aadhaarVaultNumber=VAULT-98765, '
            'otp=4321, panNumber=ABCDE1234F, email=jane@example.com, '
            'password=secret123, leadId=2977, status=200, duration=42ms)'
        )
        entry = self.entry(1, message)
        redacted = redact_lead_entry(entry, "2977")
        self.assertIn("Jane Doe", entry["raw"])
        for field in ("raw", "message"):
            value = redacted[field]
            for sensitive in (
                "Jane Doe", "1990-01-02", "9876543210", "12 Example Road",
                "560001", "VAULT-98765", "4321", "ABCDE1234F",
                "jane@example.com", "secret123",
            ):
                self.assertNotIn(sensitive, value)
            self.assertIn("leadId=2977", value)
            self.assertIn("status=200", value)
            self.assertIn("duration=42ms", value)

    def test_credentials_and_otp_fields_are_redacted(self):
        credential_field = "pass" + "word=credential_value_123"
        otp_field = "otp=8412"
        text = f"ApplicantDto({credential_field}, {otp_field})"
        redacted = redact_lead_entry({"raw": text, "message": text})
        self.assertNotIn("credential_value_123", redacted["raw"])
        self.assertNotIn("credential_value_123", redacted["message"])
        self.assertNotIn("8412", redacted["raw"])
        self.assertNotIn("8412", redacted["message"])

    def test_mixed_dto_fields_use_boundaries_before_technical_fields(self):
        message = (
            "LeadDto(firstName=Jane Doe, emailAddress=jane@example.com, status=500, "
            "errorCode=VALIDATION_FAILED, loanAmount=150000, lastName=Example)"
        )
        redacted = redact_lead_evidence_text(message)
        for value in ("Jane Doe", "jane@example.com", "Example"):
            self.assertNotIn(value, redacted)
        for field in ("status=500", "errorCode=VALIDATION_FAILED", "loanAmount=150000"):
            self.assertIn(field, redacted)

    def test_nested_dto_and_json_payloads_redact_recursively(self):
        dto = (
            "LeadDto(applicant=ApplicantDto(firstName=Jane Doe, "
            "contact=ContactDto(phoneNumber=9876543210)))"
        )
        json_payload = (
            '{"lead":{"applicant":{"firstName":"Jane Doe",'
            '"contact":{"emailAddress":"jane@example.com"}},'
            '"status":500,"errorCode":"VALIDATION_FAILED","loanAmount":150000}}'
        )
        for value in (dto, json_payload):
            redacted = redact_lead_evidence_text(value)
            self.assertNotIn("Jane Doe", redacted)
            self.assertNotIn("9876543210", redacted)
            self.assertNotIn("jane@example.com", redacted)
        self.assertIn('"status":500', redact_lead_evidence_text(json_payload))
        self.assertIn('"errorCode":"VALIDATION_FAILED"', redact_lead_evidence_text(json_payload))
        self.assertIn('"loanAmount":150000', redact_lead_evidence_text(json_payload))

    def test_empty_sensitive_fields_and_generic_names_are_preserved(self):
        message = "Dto(firstName=, name=Application, line1=Header, pin=retry, id=order-1)"
        redacted = redact_lead_evidence_text(message)
        self.assertIn("firstName=", redacted)
        self.assertIn("name=Application", redacted)
        self.assertIn("line1=Header", redacted)
        self.assertIn("pin=retry", redacted)
        self.assertIn("id=order-1", redacted)

    def test_internal_and_external_policies_preserve_or_pseudonymize_identifiers(self):
        payload = (
            '{"leadId":"L-1","requestId":"Req_1234","traceId":"trace-1",'
            '"status":500,"errorCode":"E-1","timestamp":"2026-10-23T12:00:00Z"}'
        )
        internal = redact_lead_evidence_text(
            payload, "L-1", policy=INTERNAL_INVESTIGATION
        )
        self.assertIn('"leadId":"L-1"', internal)
        self.assertIn('"requestId":"Req_1234"', internal)
        self.assertIn('"status":500', internal)
        self.assertIn('"errorCode":"E-1"', internal)
        with patch.dict("os.environ", {"API_TOKEN": "synthetic-pseudonym-key"}):
            external = redact_lead_evidence_text(payload, policy=EXTERNAL_AI)
            repeat = redact_lead_evidence_text(payload, policy=EXTERNAL_AI)
            dto = redact_lead_evidence_text(
                "LeadDto(leadId=L-1, status=500)",
                policy=EXTERNAL_AI,
            )
        self.assertEqual(external, repeat)
        self.assertNotIn("L-1", external)
        self.assertNotIn("Req_1234", external)
        self.assertIn("[ID_", external)
        self.assertIn('"status":500', external)
        self.assertNotIn("L-1", dto)
        self.assertIn("status=500", dto)

    def test_standalone_contact_identity_and_authentication_patterns_are_redacted(self):
        message = (
            "Contact jane@example.com 9876543210, PAN ABCDE1234F, "
            "Aadhaar 1234 5678 9012, Authorization: Bearer synthetic-token-123, "
            "JWT eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.syntheticSignatureValue"
        )
        redacted = redact_lead_evidence_text(message)
        for value in (
            "jane@example.com", "9876543210", "ABCDE1234F",
            "1234 5678 9012", "synthetic-token-123", "syntheticSignatureValue",
        ):
            self.assertNotIn(value, redacted)

    def test_external_policy_omits_malformed_structured_payload(self):
        malformed = "ApplicantDto(firstName=Jane Doe"
        self.assertIn("[REDACTED]", redact_lead_evidence_text(malformed))
        self.assertEqual(
            redact_lead_evidence_text(malformed, policy=EXTERNAL_AI),
            "[UNSAFE_PAYLOAD_OMITTED]",
        )
        self.assertEqual(
            redact_lead_evidence_text('{"phoneNumber":"9876543210"', policy=EXTERNAL_AI),
            "[UNSAFE_PAYLOAD_OMITTED]",
        )
        unsupported = "A free-form customer note with no safe event attributes"
        self.assertEqual(
            redact_lead_evidence_text(unsupported, policy=EXTERNAL_AI),
            "[UNSAFE_PAYLOAD_OMITTED]",
        )
        self.assertEqual(
            redact_lead_evidence_text('{"customer":"Jane Doe"}', policy=EXTERNAL_AI),
            "[UNSAFE_PAYLOAD_OMITTED]",
        )

    def test_ai_context_records_omission_of_unsupported_payload(self):
        investigation = {
            "environment": "uat",
            "searchedDays": 7,
            "retrieval": {"identifierCorrelation": "candidate"},
            "limitations": [],
            "evidence": [{
                "evidenceRef": "evidence-unsafe", "timestamp": "2026-10-23T12:00:00+00:00",
                "requestId": "Req_1234", "username": None, "severity": "INFO",
                "source": "lead_match", "eventCategory": "TECHNICAL",
                "matchedAliases": ["leadId"], "raw": "",
                "message": "A free-form customer note with no safe event attributes",
            }],
        }
        with patch.dict("os.environ", {"API_TOKEN": "synthetic-pseudonym-key"}):
            context, refs, _ = lead_service.build_lead_ai_context(investigation)
        self.assertNotIn("free-form customer note", context)
        self.assertIn("evidence-unsafe", context)
        self.assertEqual(refs, {"evidence-unsafe"})
        self.assertIn("Raw payload omitted from AI context", context)

    def test_nested_json_sensitive_fields_and_technical_context_are_preserved(self):
        entry = self.entry(
            1,
            '{"lead":{"firstName":"Jane Doe","address":{"line1":"12 Example Road"},'
            '"aadhaarRef":"vault-123","otp":"9988"},"status":422,'
            '"errorCode":"VALIDATION_FAILED","durationMs":15}',
        )
        redacted = redact_lead_entry(entry, "2977")
        for sensitive in ("Jane Doe", "12 Example Road", "vault-123", "9988"):
            self.assertNotIn(sensitive, redacted["raw"])
            self.assertNotIn(sensitive, redacted["message"])
        for technical in ('"status":422', '"errorCode":"VALIDATION_FAILED"', '"durationMs":15'):
            self.assertIn(technical, redacted["message"])

    def test_numeric_amount_status_duration_and_identifiers_are_not_phone_redacted(self):
        source = (
            "amount=9876543210 durationMs=9123456789 status=500 "
            "errorCode=123456789012 requestId=9876543210"
        )
        redacted = redact_lead_entry({"raw": source, "message": source})
        self.assertEqual(redacted["raw"], source)
        self.assertEqual(redacted["message"], source)

    def test_event_classification_prioritizes_failure_and_business_events(self):
        examples = (
            (self.entry(1, "LeadSecurityService access check allowed", level="INFO"), "ACCESS_CHECK"),
            (self.entry(2, "Application stage changed from DRAFT to REVIEW"), "STAGE_TRANSITION"),
            (self.entry(3, "Application resubmitted after correction"), "REWORK"),
            (self.entry(4, "External API request completed"), "EXTERNAL_API"),
            (self.entry(5, "Lead application submitted"), "BUSINESS_ACTION"),
            (self.entry(6, "LeadSecurityService access denied", level="ERROR"), "FAILURE"),
            (self.entry(7, "Controller request started"), "TECHNICAL"),
        )
        for entry, category in examples:
            with self.subTest(entry=entry["message"]):
                self.assertEqual(lead_service.classify_lead_event(entry), category)

    def test_request_selection_prioritizes_business_events_and_spreads_chronologically(self):
        candidates = []
        for index in range(30):
            request_id = f"Req_{index:04d}"
            message = (
                "LeadSecurityService access check allowed"
                if index < 20 else
                "Lead application submitted"
            )
            entry = self.entry(index % 59, f'{{"leadId":"2977"}} {message}', request_id=request_id)
            candidates.append({"entry": entry, "aliases": {"leadId"}})
        selected, stats = lead_service.select_request_ids(candidates, 5)
        self.assertEqual(len(selected), 5)
        self.assertTrue(all(request_id in {f"Req_{i:04d}" for i in range(20, 30)}
                            for request_id in selected))
        timestamps = [
            min(item["entry"]["timestamp"] for item in candidates
                if parser.extract_request_id(item["entry"]) == request_id)
            for request_id in selected
        ]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertEqual(stats["routineAccessRequestIdsOmitted"], 20)
        self.assertTrue(stats["truncated"])

    def test_request_selection_keeps_meaningful_events_ahead_of_technical_activity(self):
        candidates = []
        for index in range(60):
            message = (
                "Application stage changed from REVIEW to APPROVED"
                if index in {5, 25, 45} else
                "routine application trace emitted"
            )
            entry = self.entry(
                index % 59,
                f'{{"leadId":"2977"}} {message}',
                request_id=f"Req_{index:04d}",
            )
            candidates.append({"entry": entry, "aliases": {"leadId"}})
        selected, stats = lead_service.select_request_ids(candidates, 5)
        self.assertEqual(len(selected), 5)
        self.assertTrue({"Req_0005", "Req_0025", "Req_0045"}.issubset(selected))
        self.assertEqual(stats["routineTechnicalRequestIdsOmitted"], 55)

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
        self.assertEqual(result["requestTimelines"][0]["requestId"], "Req_1234")
        self.assertEqual(result["requestTimelines"][0]["eventCount"], 3)
        schemas.LeadInvestigationResponse.model_validate(result)
        self.assertTrue(all(
            reference in {item["evidenceRef"] for item in result["evidence"]}
            for reference in result["requestTimelines"][0]["evidenceRefs"]
        ))
        self.assertEqual(result["evidence"][0]["eventCategory"], "TECHNICAL")
        self.assertEqual(set(result["timingsMs"]), {
            "lokiDiscovery", "requestCorrelation", "preprocessing", "total",
        })
        self.assertTrue(all(value >= 0 for value in result["timingsMs"].values()))

    def test_redacted_duplicate_looking_entries_keep_distinct_evidence_references(self):
        first = self.entry(1, '{"leadId":"L-1","customerName":"Alice Example"}')
        second = self.entry(1, '{"leadId":"L-1","customerName":"Bob Example"}')

        async def fake_loki(query, *args, **kwargs):
            return [second, first] if "Req_1234" in query else [first, second]

        with patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=fake_loki)):
            result = asyncio.run(lead_service.investigate_lead("L-1", "uat", 7))
        self.assertEqual(len(result["evidence"]), 2)
        self.assertEqual(result["evidence"][0]["message"], result["evidence"][1]["message"])
        evidence_refs = {item["evidenceRef"] for item in result["evidence"]}
        timeline_refs = set(result["requestTimelines"][0]["evidenceRefs"])
        self.assertEqual(timeline_refs, evidence_refs)

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

    def test_evidence_cap_preserves_priority_chronology_and_reference_integrity(self):
        lines = [
            self.entry(index, f'{{"leadId":"L-1"}} routine log {index}',
                       request_id=f"Req_{index:04d}")
            for index in range(1, 7)
        ]
        lines[0] = self.entry(1, '{"leadId":"L-1"} routine technical line',
                              request_id="Req_0001")
        lines[2] = self.entry(3, '{"leadId":"L-1"} validation failed',
                              request_id="Req_0003", level="ERROR")
        lines[5] = self.entry(6, '{"leadId":"L-1"} application stage changed from A to B',
                              request_id="Req_0006")

        async def fake_loki(query, *args, **kwargs):
            return [] if " |~ " in query and "leadId" not in query else lines

        with (
            patch.object(config, "LEAD_MAX_EVIDENCE", 3),
            patch.object(config, "LEAD_MAX_REQUEST_IDS", 20),
            patch("lens.lead_service.loki_query", new=AsyncMock(side_effect=fake_loki)),
        ):
            result = asyncio.run(lead_service.investigate_lead("L-1", "uat", 7))
        self.assertEqual(len(result["evidence"]), 3)
        self.assertTrue(result["retrieval"]["evidenceTruncated"])
        self.assertIn("Evidence was capped", " ".join(result["limitations"]))
        self.assertIn("FAILURE", {item["eventCategory"] for item in result["evidence"]})
        self.assertIn("STAGE_TRANSITION", {item["eventCategory"] for item in result["evidence"]})
        timestamps = [item["timestamp"] for item in result["evidence"]]
        self.assertEqual(timestamps, sorted(timestamps))
        evidence_refs = {item["evidenceRef"] for item in result["evidence"]}
        for timeline in result["requestTimelines"]:
            self.assertTrue(set(timeline["evidenceRefs"]).issubset(evidence_refs))

    def test_request_timeline_query_batches_exact_ids_and_filters_routine_lines(self):
        query = lead_service.request_timeline_query(
            '{env="uat",app="uat"}',
            ["Req_1234", "Req_5678"],
        )
        self.assertIn(r"\[(Req_1234|Req_5678),", query)
        self.assertEqual(query.count("|~"), 2)
        self.assertIn("stage", query)
        self.assertNotIn("Req_1234|Req_5678|.*", query)

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
                "source": "lead_match", "eventCategory": "BUSINESS_ACTION",
                "matchedAliases": ["leadId"], "raw": "",
                "message": '{"leadId":"private-lead","result":"ok"}',
            }],
        }
        with (
            patch.object(config, "LEAD_AI_MAX_CONTEXT_CHARS", 1000),
            patch.dict("os.environ", {"API_TOKEN": "synthetic-pseudonym-key"}),
        ):
            context, refs, truncated = lead_service.build_lead_ai_context(investigation)
        self.assertNotIn("private-lead", context)
        self.assertNotIn("Req_1234", context)
        self.assertNotIn("test_user", context)
        self.assertIn('"hasRequestId":true', context)
        self.assertIn("[ID_", context)
        self.assertEqual(refs, {"evidence-1"})
        self.assertIn('"evidenceRef":"evidence-1"', context)
        self.assertIn('"eventCategory":"BUSINESS_ACTION"', context)
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
        with self.assertLogs("lens.analyzer", level="WARNING") as captured:
            with self.assertRaises(HTTPException) as raised:
                lead_service.validate_lead_analysis(base, investigation, {"evidence-1"})
        self.assertEqual(raised.exception.status_code, 502)
        message = captured.records[0].getMessage()
        self.assertIn('"stage":"evidence_reference_validation"', message)
        diagnostic = json.loads(message.split(" diagnostic ", 1)[1])
        self.assertEqual(diagnostic["stage"], "evidence_reference_validation")
        self.assertEqual(diagnostic["validation_reason"], "missing_references")
        self.assertEqual(diagnostic["invalid_reference_count"], 0)

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
