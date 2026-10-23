import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException

from core import config
from core.config import selector_for_environment
from core.security import redact_analysis_text, redact_request_entry
from lens.loki import loki_query
from lens.parser import extract_request_id, request_entry_matches
from lens.schemas import LeadIntelligenceModel
from lens.service import build_request_investigation

LEAD_ALIASES = ("leadId", "applicantId", "applicationId", "partnerLoanId")
LEAD_FIELD = re.compile(
    r"""(?i)(?:^|[,{|;\s])["']?(leadId|applicantId|applicationId|partnerLoanId)["']?"""
    r"""\s*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^,\s;}\]]+))"""
)
LEAD_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
AI_CORRELATION_FIELD = re.compile(
    r"""(?i)(["']?(?:request[_-]?id|trace[_-]?id|correlation[_-]?id)["']?\s*[:=]\s*)"""
    r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^,\s;}]+)"""
)
REQUEST_SUPPORTED_CLAIM = re.compile(
    r"\b(?:fail(?:ed|ure)?s?|errors?|retry|retries|rework|attempt|repeated|submission|submissions|"
    r"submitted|stage|transition|transitions|timeout|timeouts|timed out|validation|"
    r"reject(?:ed|ion)?s?|delay(?:ed)?s?|"
    r"external api)\b",
    re.IGNORECASE,
)
CLAIM_SUCCESS = re.compile(
    r"\b(?:success(?:ful(?:ly)?)?|successful submission|approved|accepted)\b",
    re.IGNORECASE,
)
BUSINESS_SUCCESS_EVIDENCE = re.compile(
    r"\b(?:success|successful|successfully|approved|accepted|submitted)\b",
    re.IGNORECASE,
)
UNSUPPORTED_ABSENCE_CLAIM = re.compile(
    r"\b(?:stuck|stalled|no recent activity|no logs?|not progressed|no progress)\b",
    re.IGNORECASE,
)
ACTION_CONTEXT = {
    "REQUEST_INVESTIGATION": "request",
    "LEAD_HISTORY": "lead",
    "USER_ACTIVITY": "user",
    "EXTERNAL_API_INSPECTION": "request",
    "COMPARE_ATTEMPTS": "lead",
}


def _entry_key(entry: dict) -> tuple[str, str]:
    return entry["timestamp"], entry.get("raw", entry.get("message", ""))


def matched_lead_aliases(entry: dict, lead_id: str) -> list[str]:
    text = "\n".join(
        value for value in (entry.get("raw"), entry.get("message")) if isinstance(value, str)
    )
    matched = set()
    for match in LEAD_FIELD.finditer(text):
        value = next((group for group in match.groups()[1:] if group is not None), None)
        if value == lead_id:
            alias = match.group(1).casefold()
            matched.add(next(name for name in LEAD_ALIASES if name.casefold() == alias))
    return [alias for alias in LEAD_ALIASES if alias in matched]


def _query_pattern(lead_id: str) -> str:
    return (
        r"""(?i)(^|[,{|;[:space:]])["']?"""
        r"""(leadId|applicantId|applicationId|partnerLoanId)["']?[[:space:]]*[:=]"""
        r"""[[:space:]]*["']?"""
        + re.escape(lead_id)
        + r"""([^A-Za-z0-9_-]|$)"""
    )


async def _bounded_loki_query(
    query: str,
    start: datetime,
    end: datetime,
    total_limit: int,
    max_queries: int | None = None,
) -> tuple[list[dict], dict]:
    page_size = max(1, min(config.LEAD_LOKI_PAGE_SIZE, total_limit, 5000))
    query_limit = max(0, config.LEAD_MAX_LOKI_QUERIES if max_queries is None else max_queries)
    found: list[dict] = []
    query_count = 0
    truncated = False

    async def read_range(range_start: datetime, range_end: datetime) -> None:
        nonlocal query_count, truncated
        if len(found) >= total_limit or query_count >= query_limit:
            truncated = True
            return
        remaining = total_limit - len(found)
        requested_limit = min(page_size, remaining)
        query_count += 1
        duration_minutes = max(1, math.ceil((range_end - range_start).total_seconds() / 60))
        entries = await loki_query(
            query,
            duration_minutes,
            requested_limit,
            window_start=range_start,
            window_end=range_end,
        )
        found.extend(entries[:remaining])
        saturated = len(entries) >= requested_limit
        if not saturated:
            return
        span = (range_end - range_start).total_seconds()
        if span <= 1 or len(found) >= total_limit or query_count >= query_limit:
            truncated = True
            return
        midpoint = range_start + (range_end - range_start) / 2
        if midpoint <= range_start or midpoint >= range_end:
            truncated = True
            return
        await read_range(range_start, midpoint)
        await read_range(midpoint, range_end)

    await read_range(start, end)
    return found, {
        "queryCount": query_count,
        "returnedLines": len(found),
        "truncated": truncated,
        "lineLimit": total_limit,
        "pageSize": page_size,
    }


async def investigate_lead(
    lead_id: str,
    environment: Literal["uat", "prod"],
    days: int,
) -> dict:
    if not LEAD_ID_PATTERN.fullmatch(lead_id):
        raise HTTPException(status_code=400, detail="Invalid lead ID")
    maximum_days = max(1, config.LEAD_MAX_DAYS)
    searched_days = min(days, maximum_days)
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(days=searched_days)
    limitations = []
    if searched_days < days:
        limitations.append(
            f"Requested range was capped at {searched_days} days by server configuration."
        )

    selector = selector_for_environment(environment)
    candidate_query = selector + " |~ " + json.dumps(_query_pattern(lead_id))
    candidate_lines, candidate_stats = await _bounded_loki_query(
        candidate_query,
        window_start,
        window_end,
        max(1, config.LEAD_MAX_RETRIEVED_LINES),
    )
    candidate_by_key = {}
    for entry in candidate_lines:
        aliases = matched_lead_aliases(entry, lead_id)
        if not aliases:
            continue
        key = _entry_key(entry)
        candidate_by_key.setdefault(key, {"entry": entry, "aliases": set()})["aliases"].update(aliases)

    candidate_events = sorted(
        candidate_by_key.values(),
        key=lambda item: item["entry"]["timestamp"],
    )
    discovered_ids = list(dict.fromkeys(
        extract_request_id(item["entry"])
        for item in candidate_events
        if extract_request_id(item["entry"])
        and REQUEST_ID_PATTERN.fullmatch(extract_request_id(item["entry"]))
    ))
    aliases_by_request_id = {}
    for item in candidate_events:
        request_id = extract_request_id(item["entry"])
        if request_id in discovered_ids:
            aliases_by_request_id.setdefault(request_id, set()).update(item["aliases"])
    maximum_request_ids = max(0, config.LEAD_MAX_REQUEST_IDS)
    request_id_truncated = len(discovered_ids) > maximum_request_ids
    request_ids = discovered_ids[:maximum_request_ids]
    if request_id_truncated:
        limitations.append("Related request IDs were capped by server configuration.")

    timeline_lines: list[dict] = []
    timeline_stats = {
        "queryCount": 0,
        "returnedLines": 0,
        "truncated": False,
        "lineLimit": 0,
        "pageSize": 0,
    }
    if request_ids:
        request_pattern = r"\[(" + "|".join(re.escape(item) for item in request_ids) + r"),"
        timeline_query = selector + " |~ " + json.dumps(request_pattern)
        remaining_line_budget = max(
            0, config.LEAD_MAX_RETRIEVED_LINES - candidate_stats["returnedLines"]
        )
        if remaining_line_budget:
            timeline_lines, timeline_stats = await _bounded_loki_query(
                timeline_query,
                window_start,
                window_end,
                remaining_line_budget,
                max_queries=max(0, config.LEAD_MAX_LOKI_QUERIES - candidate_stats["queryCount"]),
            )
            timeline_lines = [
                entry for entry in timeline_lines
                if any(request_entry_matches(entry, request_id) for request_id in request_ids)
            ]
            timeline_lines = list({
                _entry_key(entry): entry for entry in timeline_lines
            }.values())
            timeline_lines.sort(key=lambda entry: entry["timestamp"])
        else:
            timeline_stats.update({"truncated": True, "lineLimit": 0})
            limitations.append("The total retrieved-line limit left no room for request timelines.")
    if candidate_stats["truncated"]:
        limitations.append("Candidate Loki retrieval was truncated by pagination or configured limits.")
    if timeline_stats["truncated"]:
        limitations.append("Related request timelines were truncated by pagination or configured limits.")
    if not candidate_events:
        limitations.append("No exact lead-identifier field matches were found in the searched logs.")
    if candidate_events and len({
        alias for item in candidate_events for alias in item["aliases"]
    }) > 1:
        limitations.append(
            "The same value appeared under multiple identifier aliases; correlation remains ambiguous."
        )
    if candidate_events and not request_ids:
        limitations.append("Matched logs did not contain usable request IDs for timeline correlation.")

    evidence_rows = {}
    for item in candidate_events:
        entry = redact_request_entry(item["entry"])
        key = _entry_key(item["entry"])
        evidence_rows[key] = {
            "entry": entry,
            "source": "lead_match",
            "matchedAliases": sorted(item["aliases"]),
        }
    for entry in timeline_lines:
        key = _entry_key(entry)
        if key not in evidence_rows:
            evidence_rows[key] = {
                "entry": redact_request_entry(entry),
                "source": "request_timeline",
                "matchedAliases": sorted(
                    aliases_by_request_id.get(extract_request_id(entry), set())
                ),
            }
    ordered_rows = sorted(evidence_rows.values(), key=lambda item: item["entry"]["timestamp"])
    evidence = []
    evidence_ref_by_key = {}
    for index, row in enumerate(ordered_rows, 1):
        entry = row["entry"]
        evidence_ref = f"evidence-{index}"
        evidence_ref_by_key[_entry_key(entry)] = evidence_ref
        evidence.append({
            "evidenceRef": evidence_ref,
            "timestamp": entry["timestamp"],
            "requestId": extract_request_id(entry),
            "username": entry.get("user"),
            "severity": entry.get("level"),
            "source": row["source"],
            "matchedAliases": row["matchedAliases"],
            "raw": entry.get("raw", ""),
            "message": entry.get("message", ""),
        })

    request_timelines = []
    for request_id in request_ids:
        entries = []
        for entry in timeline_lines:
            if request_entry_matches(entry, request_id):
                redacted_entry = redact_request_entry(entry)
                redacted_entry["request_id"] = extract_request_id(entry)
                entries.append(redacted_entry)
        entries.sort(key=lambda entry: entry["timestamp"])
        timeline = build_request_investigation(
            request_id,
            entries,
            searched_days * 1440,
            max(1, config.LEAD_MAX_RETRIEVED_LINES),
            window_start,
            window_end,
            timeline_stats["returnedLines"],
        )
        for event in timeline["events"]:
            for entry in entries:
                if event.get("raw") == entry.get("raw") and event.get("timestamp") == entry.get("timestamp"):
                    event["evidenceRef"] = evidence_ref_by_key.get(_entry_key(entry))
                    event["correlationAliases"] = sorted(
                        aliases_by_request_id.get(extract_request_id(entry), set())
                    )
                    break
        request_timelines.append(timeline)

    aliases_observed = sorted({
        alias for item in candidate_events for alias in item["aliases"]
    })
    return {
        "leadId": lead_id,
        "environment": environment,
        "requestedDays": days,
        "searchedDays": searched_days,
        "candidateCount": len(candidate_events),
        "relatedRequestIds": request_ids,
        "evidence": evidence,
        "requestTimelines": request_timelines,
        "retrieval": {
            "candidate": candidate_stats,
            "requestTimelines": timeline_stats,
            "discoveredRequestIds": len(discovered_ids),
            "returnedRequestIds": len(request_ids),
            "requestIdsTruncated": request_id_truncated,
            "aliasesObserved": aliases_observed,
            "requestAliases": {
                request_id: sorted(aliases_by_request_id.get(request_id, set()))
                for request_id in request_ids
            },
            "identifierCorrelation": (
                "ambiguous" if len(aliases_observed) > 1 else "candidate"
            ),
            "windowStart": window_start.isoformat(),
            "windowEnd": window_end.isoformat(),
            "totalReturnedLines": candidate_stats["returnedLines"] + timeline_stats["returnedLines"],
        },
        "limitations": list(dict.fromkeys(limitations)),
    }


def build_lead_ai_context(investigation: dict) -> tuple[str, set[str], bool]:
    evidence = []
    allowed_refs = set()
    lead_id_pattern = re.compile(
        r"(?<![A-Za-z0-9_])" + re.escape(investigation["leadId"]) + r"(?![A-Za-z0-9_])"
    )
    for item in investigation["evidence"]:
        allowed_refs.add(item["evidenceRef"])
        message = LEAD_FIELD.sub(
            lambda match: f"{match.group(1)}=[LEAD_ID]",
            item["message"],
        )
        message = AI_CORRELATION_FIELD.sub(r"\1[REQUEST_ID]", message)
        message = lead_id_pattern.sub("[LEAD_ID]", message)
        evidence.append({
            "evidenceRef": item["evidenceRef"],
            "timestamp": item["timestamp"],
            "hasRequestId": bool(item["requestId"]),
            "hasUsername": bool(item["username"]),
            "severity": item["severity"],
            "source": item["source"],
            "matchedAliases": item["matchedAliases"],
            "message": message,
        })
    safe_context = {
        "environment": investigation["environment"],
        "searchedDays": investigation["searchedDays"],
        "identifierCorrelation": investigation["retrieval"]["identifierCorrelation"],
        "evidence": evidence,
        "limitations": investigation["limitations"],
    }
    context = redact_analysis_text(json.dumps(safe_context, ensure_ascii=True, separators=(",", ":")))
    maximum_chars = max(1, config.LEAD_AI_MAX_CONTEXT_CHARS)
    truncated = len(context) > maximum_chars
    if len(context) > maximum_chars:
        for item in evidence:
            if len(item["message"]) > 200:
                item["message"] = item["message"][:200] + "...[TRUNCATED]"
        safe_context["evidence"] = evidence
        context = redact_analysis_text(json.dumps(safe_context, ensure_ascii=True, separators=(",", ":")))
    while len(context) > maximum_chars and evidence:
        evidence.pop()
        truncated = True
        safe_context["evidence"] = evidence
        context = redact_analysis_text(json.dumps(safe_context, ensure_ascii=True, separators=(",", ":")))
    if len(context) > maximum_chars:
        raise HTTPException(status_code=422, detail="Lead evidence exceeds the safe AI context budget")
    if investigation["evidence"] and not evidence:
        raise HTTPException(status_code=422, detail="No evidence fits the safe AI context budget")
    retained_refs = {item["evidenceRef"] for item in evidence}
    return context, allowed_refs & retained_refs, truncated


def validate_lead_analysis(
    result: dict,
    investigation: dict,
    valid_refs: set[str],
    context_truncated: bool = False,
) -> dict:
    evidence_by_ref = {
        item["evidenceRef"]: item for item in investigation["evidence"]
        if item["evidenceRef"] in valid_refs
    }

    def validate_claim_refs(claim: dict) -> None:
        refs = claim.get("evidenceRefs", [])
        if not refs:
            raise HTTPException(status_code=502, detail="Groq returned an unsupported evidence claim")
        if any(reference not in evidence_by_ref for reference in refs):
            raise HTTPException(status_code=502, detail="Groq cited evidence not present in the retrieved context")
        if investigation["retrieval"]["identifierCorrelation"] == "ambiguous":
            alias_groups = [
                set(evidence_by_ref[reference].get("matchedAliases", []))
                for reference in refs
            ]
            if any(len(aliases) > 1 for aliases in alias_groups) or len(
                set.union(*alias_groups) if alias_groups else set()
            ) > 1:
                raise HTTPException(
                    status_code=502,
                    detail="Groq combined evidence from ambiguous identifier aliases",
                )
        claim_text = " ".join(
            str(claim.get(key, "")) for key in ("description", "event")
        )
        supporting_items = [evidence_by_ref[reference] for reference in refs]
        if (REQUEST_SUPPORTED_CLAIM.search(claim_text)
                or re.search(r"\b[45]\d{2}\b", claim_text)) and not any(
            evidence_by_ref[reference].get("requestId") for reference in refs
        ):
            raise HTTPException(
                status_code=502,
                detail="Groq made a request-dependent claim without a supporting request ID",
            )
        if CLAIM_SUCCESS.search(claim_text) and not any(
            BUSINESS_SUCCESS_EVIDENCE.search(item["message"]) for item in supporting_items
        ):
            raise HTTPException(
                status_code=502,
                detail="Groq inferred business success without explicit supporting evidence",
            )
        if UNSUPPORTED_ABSENCE_CLAIM.search(claim_text) and not any(
            UNSUPPORTED_ABSENCE_CLAIM.search(item["message"]) for item in supporting_items
        ):
            raise HTTPException(
                status_code=502,
                detail="Groq inferred inactivity without direct supporting evidence",
            )

    for claim in result["journeyTimeline"] + result["findingsAndAnomalies"]:
        validate_claim_refs(claim)
    root_cause = result["rootCauseAssessment"]
    for claim in root_cause["observedFacts"] + root_cause["possibleCauses"]:
        validate_claim_refs(claim)
    for reference in result["summaryEvidenceRefs"] + result["stageEvidenceRefs"]:
        if reference not in evidence_by_ref:
            raise HTTPException(status_code=502, detail="Groq cited evidence not present in the retrieved context")
    if result["currentStage"] and not result["stageEvidenceRefs"]:
        raise HTTPException(status_code=502, detail="Groq returned a stage without supporting evidence")
    if result["currentStage"] and not any(
        evidence_by_ref[reference].get("requestId") for reference in result["stageEvidenceRefs"]
    ):
        raise HTTPException(status_code=502, detail="Groq returned a stage without a supporting request ID")
    if result["currentStage"]:
        normalized_stage = re.sub(r"[^a-z0-9]+", " ", result["currentStage"].casefold()).strip()
        stage_evidence = " ".join(
            evidence_by_ref[reference]["message"].casefold()
            for reference in result["stageEvidenceRefs"]
        )
        normalized_evidence = re.sub(r"[^a-z0-9]+", " ", stage_evidence)
        if not normalized_stage or normalized_stage not in normalized_evidence:
            raise HTTPException(
                status_code=502,
                detail="Groq returned a stage not stated in its supporting evidence",
            )
    if result["latestObservedActivity"] and not result["summaryEvidenceRefs"]:
        raise HTTPException(status_code=502, detail="Groq returned activity without supporting evidence")
    if result["latestObservedActivity"]:
        validate_claim_refs({
            "description": result["latestObservedActivity"],
            "evidenceRefs": result["summaryEvidenceRefs"],
        })
    if result["narrative"] and not result["summaryEvidenceRefs"]:
        raise HTTPException(status_code=502, detail="Groq returned a summary without supporting evidence")
    if result["narrative"]:
        validate_claim_refs({
            "description": result["narrative"],
            "evidenceRefs": result["summaryEvidenceRefs"],
        })

    suggested_checks = []
    request_ids = set(investigation["relatedRequestIds"])
    usernames = {
        item["username"] for item in investigation["evidence"] if item["username"]
    }
    lead_id = investigation["leadId"]
    for proposal in result["suggestedChecks"]:
        action = proposal["action"]
        refs = proposal["evidenceRefs"]
        validate_claim_refs({
            "description": proposal["title"] + " " + proposal["reason"],
            "evidenceRefs": refs,
        })
        if any(reference not in evidence_by_ref for reference in refs):
            raise HTTPException(status_code=502, detail="Groq proposed a check using unknown evidence")
        evidenced = [evidence_by_ref[reference] for reference in refs]
        context_type = ACTION_CONTEXT[action]
        navigation = {}
        if context_type == "lead":
            navigation["leadId"] = lead_id
        elif context_type == "request":
            candidates = list(dict.fromkeys(
                item["requestId"] for item in evidenced
                if item.get("requestId") in request_ids
            ))
            if not candidates:
                raise HTTPException(status_code=502, detail="Groq proposed a request check without a supported request ID")
            navigation["requestId"] = candidates[0]
        elif context_type == "user":
            candidates = list(dict.fromkeys(
                item["username"] for item in evidenced
                if item.get("username") in usernames
            ))
            if not candidates:
                raise HTTPException(status_code=502, detail="Groq proposed a user check without a supported username")
            navigation["username"] = candidates[0]
        suggested_checks.append({
            "action": action,
            "title": proposal["title"],
            "reason": proposal["reason"],
            "priority": proposal["priority"],
            "context": {"environment": investigation["environment"], **navigation},
        })
    for next_step in result["recommendedNextSteps"]:
        validate_claim_refs(next_step)

    def enrich_claim(claim: dict) -> dict:
        claim = dict(claim)
        claim["supportingEvidence"] = [
            {
                "evidenceRef": reference,
                "timestamp": evidence_by_ref[reference]["timestamp"],
                "requestId": evidence_by_ref[reference]["requestId"],
            }
            for reference in claim.pop("evidenceRefs")
        ]
        return claim

    timeline = [enrich_claim(claim) for claim in result["journeyTimeline"]]
    findings = [enrich_claim(item) for item in result["findingsAndAnomalies"]]
    facts = [enrich_claim(item) for item in root_cause["observedFacts"]]
    causes = [enrich_claim(item) for item in root_cause["possibleCauses"]]
    next_steps = [enrich_claim(item) for item in result["recommendedNextSteps"]]
    root_cause["observedFacts"] = facts
    root_cause["possibleCauses"] = causes
    summary_support = [evidence_by_ref[ref] for ref in result["summaryEvidenceRefs"]]
    stage_support = [evidence_by_ref[ref] for ref in result["stageEvidenceRefs"]]
    limitations = list(dict.fromkeys(investigation["limitations"] + result["limitations"]))
    if not result["currentStage"]:
        limitations.append("Current stage could not be established from retrieved evidence.")
    if context_truncated:
        limitations.append("AI input was truncated to the configured context budget.")
    if investigation["retrieval"]["identifierCorrelation"] == "ambiguous":
        limitations.append("Identifier correlation is ambiguous and all matches are candidates.")
    return {
        "leadSummary": {
            "narrative": result["narrative"],
            "latestObservedActivity": result["latestObservedActivity"],
            "latestActivityEvidence": [
                {"evidenceRef": item["evidenceRef"], "timestamp": item["timestamp"],
                 "requestId": item["requestId"]}
                for item in summary_support
            ],
            "currentStage": result["currentStage"],
            "stageEvidence": [
                {"evidenceRef": item["evidenceRef"], "timestamp": item["timestamp"],
                 "requestId": item["requestId"]}
                for item in stage_support
            ],
            "confidence": result["confidence"],
        },
        "journeyTimeline": timeline,
        "findingsAndAnomalies": findings,
        "rootCauseAssessment": {
            "observedFacts": facts,
            "possibleCauses": causes,
            "confidence": root_cause["confidence"],
        },
        "suggestedChecks": suggested_checks,
        "recommendedNextSteps": next_steps,
        "limitations": list(dict.fromkeys(limitations)),
        "model": result["model"],
    }
