import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException

from core import config
from core.config import selector_for_environment
from core.security import (
    EXTERNAL_AI,
    redact_lead_entry,
    redact_lead_evidence_text,
)
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
EVENT_CATEGORY_PRIORITY = {
    "FAILURE": 100,
    "STAGE_TRANSITION": 80,
    "REWORK": 70,
    "EXTERNAL_API": 60,
    "BUSINESS_ACTION": 50,
    "TECHNICAL": 10,
    "ACCESS_CHECK": 0,
}
FAILURE_EVENT = re.compile(
    r"\b(?:error|exception|failed|failure|invalid|rejected|denied|unauthorized|forbidden|"
    r"timed?\s*out|timeout|4\d\d|5\d\d)\b",
    re.IGNORECASE,
)
STAGE_EVENT = re.compile(
    r"\b(?:stage|status)\s*(?:changed|transition(?:ed)?|updated|from|to)\b|"
    r"\b(?:stage|status)\s*[:=]\s*[\w-]+\s*(?:->|=>)\s*[\w-]+|"
    r"\b(?:transitioned|moved)\s+to\s+\w+",
    re.IGNORECASE,
)
REWORK_EVENT = re.compile(
    r"\b(?:rework|resubmi(?:t|ssion)|retry|retried|re-?attempt|correction|returned\s+for)\b",
    re.IGNORECASE,
)
EXTERNAL_API_EVENT = re.compile(
    r"\b(?:external\s+api|third.party|downstream|feign|integration)\b",
    re.IGNORECASE,
)
BUSINESS_ACTION_EVENT = re.compile(
    r"\b(?:lead|application|loan|applicant)\b.{0,60}\b(?:created|submitted|updated|"
    r"approved|rejected|validated|saved|processed|initiated)\b|"
    r"\b(?:submission|validation|approval|disbursement)\b",
    re.IGNORECASE,
)
ACCESS_CHECK_EVENT = re.compile(
    r"\b(?:access\s+check|checking\s+access|permission\s+check|authorization\s+check|"
    r"access\s+(?:allowed|granted|permitted))\b",
    re.IGNORECASE,
)
LARGE_API_OPERATION = re.compile(r"\b(saveLoan|getLoanStatus)\b", re.IGNORECASE)
LARGE_API_ENDPOINTS = {
    "/v2/partner/loanApplications": "saveLoan",
    "/v1/partner/loanReports/": "getLoanStatus",
}
API_ENDPOINT_PATTERN = re.compile(
    r"(?i)(?:https?://[^/\s]+)?(?P<path>/v[12]/partner/"
    r"(?:loanApplications|loanReports/?[^\s\"',)}]*))"
)
API_METHOD_PATTERN = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\b", re.IGNORECASE)
API_STATUS_PATTERN = re.compile(
    r"(?i)(?:HTTP/\d(?:\.\d)?\s+|(?:httpstatus(?:code)?|statuscode|status)\s*[:=]\s*)(\d{3})\b"
)
API_DURATION_PATTERN = re.compile(
    r"(?i)(?:duration(?:ms)?|elapsed(?:ms)?|time)\s*[:=]\s*(\d+(?:\.\d+)?)\s*ms?"
    r"|\((\d+(?:\.\d+)?)\s*ms\)"
)
API_ERROR_PATTERN = re.compile(
    r'''(?i:\berrorCode\s*[:=]\s*["']?)([A-Z][A-Z0-9_-]{1,63})'''
)
API_BODY_ERROR_PATTERN = re.compile(
    r'''(?i:"errorCode"\s*:\s*")([A-Z][A-Z0-9_-]{1,63})'''
)
WEBHOOK_PAYLOAD_MARKER = re.compile(r"(?i)\bExternal ReverseMapping Payload\s*:")
MAX_API_METADATA_PREFIX = 4096


def classify_lead_event(entry: dict) -> str:
    api_metadata = entry.get("leadApiMetadata")
    if api_metadata:
        status = api_metadata.get("httpStatus")
        if status is not None and status >= 400:
            return "FAILURE"
        return "EXTERNAL_API"
    message = entry.get("message") or ""
    logger = entry.get("logger") or ""
    combined = f"{logger} {message}"
    if FAILURE_EVENT.search(combined) or entry.get("level") == "ERROR" or entry.get("exception"):
        return "FAILURE"
    if STAGE_EVENT.search(message):
        return "STAGE_TRANSITION"
    if REWORK_EVENT.search(message):
        return "REWORK"
    if EXTERNAL_API_EVENT.search(message):
        return "EXTERNAL_API"
    if BUSINESS_ACTION_EVENT.search(message):
        return "BUSINESS_ACTION"
    security_logger = config.LEAD_SECURITY_ACCESS_LOGGER.strip()
    if (security_logger and security_logger.casefold() in logger.casefold()) or ACCESS_CHECK_EVENT.search(message):
        return "ACCESS_CHECK"
    return "TECHNICAL"


def select_request_ids(candidate_events: list[dict], maximum: int) -> tuple[list[str], dict]:
    grouped = {}
    for item in candidate_events:
        request_id = extract_request_id(item["entry"])
        if not request_id or not REQUEST_ID_PATTERN.fullmatch(request_id):
            continue
        category = classify_lead_event(item["entry"])
        group = grouped.setdefault(request_id, {
            "timestamp": item["entry"]["timestamp"],
            "categories": [],
            "aliases": set(),
            "events": 0,
        })
        group["timestamp"] = min(group["timestamp"], item["entry"]["timestamp"])
        group["categories"].append(category)
        group["aliases"].update(item["aliases"])
        group["events"] += 1

    ranked = []
    for request_id, group in grouped.items():
        highest_priority = max(
            (EVENT_CATEGORY_PRIORITY[category] for category in group["categories"]),
            default=0,
        )
        if highest_priority == EVENT_CATEGORY_PRIORITY["ACCESS_CHECK"]:
            continue
        group["score"] = highest_priority + min(group["events"], 5)
        ranked.append((request_id, group))

    ranked.sort(key=lambda candidate: candidate[1]["timestamp"])
    selected = []
    if maximum > 0 and len(ranked) > maximum:
        first = datetime.fromisoformat(ranked[0][1]["timestamp"].replace("Z", "+00:00"))
        last = datetime.fromisoformat(ranked[-1][1]["timestamp"].replace("Z", "+00:00"))
        span_seconds = max(1.0, (last - first).total_seconds())
        buckets = [[] for _ in range(maximum)]
        for candidate in ranked:
            at = datetime.fromisoformat(candidate[1]["timestamp"].replace("Z", "+00:00"))
            index = min(maximum - 1, int((at - first).total_seconds() / span_seconds * maximum))
            buckets[index].append(candidate)
        for bucket in buckets:
            if bucket:
                selected.append(max(
                    bucket,
                    key=lambda candidate: (
                        candidate[1]["score"],
                        candidate[1]["timestamp"],
                        candidate[0],
                    ),
                ))
        selected_ids = {item[0] for item in selected}
        remaining = [
            candidate for candidate in ranked if candidate[0] not in selected_ids
        ]
        remaining.sort(
            key=lambda candidate: (
                candidate[1]["score"],
                candidate[1]["timestamp"],
                candidate[0],
            ),
            reverse=True,
        )
        selected.extend(remaining[:maximum - len(selected)])
    else:
        selected = ranked

    selected = sorted(selected[:maximum], key=lambda candidate: candidate[1]["timestamp"])
    return [request_id for request_id, _ in selected], {
        "discoveredRequestIds": len(grouped),
        "eligibleRequestIds": len(ranked),
        "routineAccessRequestIdsOmitted": len(grouped) - len(ranked),
        "selectedRequestIds": len(selected),
        "truncated": len(ranked) > maximum,
    }


def _entry_key(entry: dict) -> tuple[str, str]:
    return entry["timestamp"], entry.get("raw", entry.get("message", ""))


def matched_lead_aliases(entry: dict, lead_id: str) -> list[str]:
    text = entry.get("message") or entry.get("raw") or ""
    matched = set()
    for match in LEAD_FIELD.finditer(text):
        value = next((group for group in match.groups()[1:] if group is not None), None)
        if value == lead_id:
            alias = match.group(1).casefold()
            matched.add(next(name for name in LEAD_ALIASES if name.casefold() == alias))
    return [alias for alias in LEAD_ALIASES if alias in matched]


def compact_large_api_entry(entry: dict) -> dict:
    message = entry.get("message") or ""
    prefix = message[:MAX_API_METADATA_PREFIX]
    logger = entry.get("logger") or ""
    webhook_match = WEBHOOK_PAYLOAD_MARKER.search(prefix)
    metadata_prefix = prefix.splitlines()[0]
    body_positions = [position for position in (metadata_prefix.find("{"),) if position >= 0]
    body_start = body_positions[0] if body_positions else None
    if webhook_match:
        marker_end = webhook_match.end()
        array_start = metadata_prefix.find("[", marker_end)
        if array_start >= 0:
            body_positions.append(array_start)
    if body_positions:
        metadata_prefix = metadata_prefix[:min(body_positions)]
    endpoint_match = API_ENDPOINT_PATTERN.search(metadata_prefix)
    operation_match = (
        LARGE_API_OPERATION.search(metadata_prefix)
        or LARGE_API_OPERATION.search(logger)
    )
    operation = operation_match.group(1) if operation_match else None
    endpoint = endpoint_match.group("path") if endpoint_match else None
    if endpoint:
        known_match = next(
            ((known_endpoint, name) for known_endpoint, name in LARGE_API_ENDPOINTS.items()
             if endpoint.startswith(known_endpoint)),
            None,
        )
        if known_match:
            endpoint, operation = known_match
    if not webhook_match and not operation and not endpoint:
        return entry

    method_match = API_METHOD_PATTERN.search(metadata_prefix)
    if webhook_match:
        event_type = "WEBHOOK_RECEIVED"
    else:
        lowered = metadata_prefix.casefold()
        is_response = (
            "<---" in metadata_prefix
            or re.search(r"\bresponse\b", lowered)
            or API_STATUS_PATTERN.search(metadata_prefix)
            or re.search(r"\(\d+(?:\.\d+)?\s*ms\)", metadata_prefix)
        )
        is_request = (
            "--->" in metadata_prefix
            or re.search(r"\brequest\b", lowered)
            or (method_match and (endpoint_match or operation))
        )
        if is_response:
            event_type = "API_RESPONSE"
        elif is_request:
            event_type = "API_REQUEST"
        else:
            event_type = None

    status_match = API_STATUS_PATTERN.search(metadata_prefix)
    duration_match = API_DURATION_PATTERN.search(metadata_prefix)
    error_match = API_ERROR_PATTERN.search(metadata_prefix)
    if not error_match and body_start is not None:
        error_match = API_BODY_ERROR_PATTERN.search(prefix[body_start:body_start + 512])
    duration_value = None
    if duration_match:
        value = duration_match.group(1) or duration_match.group(2)
        numeric_duration = float(value)
        duration_value = int(numeric_duration) if numeric_duration.is_integer() else numeric_duration
    metadata = {
        "eventType": event_type,
        "operation": operation,
        "httpMethod": method_match.group(1).upper() if method_match else None,
        "endpointPath": endpoint,
        "httpStatus": int(status_match.group(1)) if status_match else None,
        "durationMs": duration_value,
        "errorCode": error_match.group(1) if error_match else None,
        "payloadOmitted": True,
    }
    safe_message = (
        f"Large API payload omitted: {event_type or 'API_EVENT_TYPE_UNKNOWN'}"
        + (f" operation={operation}" if operation else "")
        + (f" method={metadata['httpMethod']}" if metadata["httpMethod"] else "")
        + (f" endpoint={endpoint}" if endpoint else "")
        + (f" status={metadata['httpStatus']}" if metadata["httpStatus"] is not None else "")
        + (f" durationMs={duration_value}" if duration_value is not None else "")
        + (f" errorCode={metadata['errorCode']}" if metadata["errorCode"] else "")
    )
    compacted = dict(entry)
    compacted["message"] = safe_message
    request_id = extract_request_id(entry) or ""
    compacted["raw"] = (
        f"{entry.get('applicationTimestamp') or entry.get('timestamp')} "
        f"[{entry.get('thread') or 'unknown'}] {entry.get('level') or 'INFO'} "
        f"[{request_id},[REDACTED]] [{entry.get('pid') or 'unknown'}] --- "
        f"{logger or 'unknown'} : {safe_message}"
    )
    compacted["exception"] = None
    compacted["leadApiMetadata"] = metadata
    return compacted


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
    entry_processor=None,
) -> tuple[list[dict], dict]:
    page_size = max(1, min(config.LEAD_LOKI_PAGE_SIZE, total_limit, 5000))
    query_limit = max(0, config.LEAD_MAX_LOKI_QUERIES if max_queries is None else max_queries)
    found: list[dict] = []
    retrieved_count = 0
    query_count = 0
    truncated = False

    async def read_range(range_start: datetime, range_end: datetime) -> None:
        nonlocal query_count, retrieved_count, truncated
        if retrieved_count >= total_limit or query_count >= query_limit:
            truncated = True
            return
        remaining = total_limit - retrieved_count
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
        for entry in entries[:remaining]:
            retrieved_count += 1
            processed = entry_processor(entry) if entry_processor else entry
            if processed is not None:
                found.append(processed)
        saturated = len(entries) >= requested_limit
        if not saturated:
            return
        span = (range_end - range_start).total_seconds()
        if span <= 1 or retrieved_count >= total_limit or query_count >= query_limit:
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
        "returnedLines": retrieved_count,
        "truncated": truncated,
        "lineLimit": total_limit,
        "pageSize": page_size,
    }


async def investigate_lead(
    lead_id: str,
    environment: Literal["uat", "prod"],
    days: int,
) -> dict:
    total_started = time.perf_counter()
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

    def prepare_candidate(entry: dict) -> dict | None:
        aliases = matched_lead_aliases(entry, lead_id)
        if not aliases:
            return None
        compacted = compact_large_api_entry(entry)
        compacted["_matchedLeadAliases"] = aliases
        return compacted

    candidate_lines, candidate_stats = await _bounded_loki_query(
        candidate_query,
        window_start,
        window_end,
        max(1, config.LEAD_MAX_RETRIEVED_LINES),
        entry_processor=prepare_candidate,
    )
    discovery_finished = time.perf_counter()
    candidate_by_key = {}
    for entry in candidate_lines:
        aliases = entry.pop("_matchedLeadAliases")
        key = _entry_key(entry)
        candidate_by_key.setdefault(key, {"entry": entry, "aliases": set()})["aliases"].update(aliases)

    candidate_events = sorted(
        candidate_by_key.values(),
        key=lambda item: item["entry"]["timestamp"],
    )
    request_ids, selection_stats = select_request_ids(
        candidate_events,
        max(0, config.LEAD_MAX_REQUEST_IDS),
    )
    aliases_by_request_id = {}
    for item in candidate_events:
        request_id = extract_request_id(item["entry"])
        if request_id in request_ids:
            aliases_by_request_id.setdefault(request_id, set()).update(item["aliases"])
    request_id_truncated = selection_stats["truncated"]
    if request_id_truncated:
        limitations.append("Related request IDs were capped by server configuration.")
    if selection_stats["routineAccessRequestIdsOmitted"]:
        limitations.append(
            "Routine access-check-only requests were omitted from request timeline retrieval."
        )

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
                entry_processor=compact_large_api_entry,
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
    correlation_finished = time.perf_counter()
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
    if candidate_events and not selection_stats["discoveredRequestIds"]:
        limitations.append("Matched logs did not contain usable request IDs for timeline correlation.")

    evidence_rows = {}
    for item in candidate_events:
        entry = redact_lead_entry(item["entry"], lead_id)
        key = _entry_key(item["entry"])
        evidence_rows[key] = {
            "entry": entry,
            "originalKey": key,
            "source": "lead_match",
            "matchedAliases": sorted(item["aliases"]),
            "eventCategory": classify_lead_event(item["entry"]),
        }
    for entry in timeline_lines:
        key = _entry_key(entry)
        if key not in evidence_rows:
            evidence_rows[key] = {
                "entry": redact_lead_entry(entry, lead_id),
                "originalKey": key,
                "source": "request_timeline",
                "matchedAliases": sorted(
                    aliases_by_request_id.get(extract_request_id(entry), set())
                ),
                "eventCategory": classify_lead_event(entry),
            }
    ordered_rows = sorted(evidence_rows.values(), key=lambda item: item["entry"]["timestamp"])
    evidence = []
    evidence_ref_by_key = {}
    for index, row in enumerate(ordered_rows, 1):
        entry = row["entry"]
        evidence_ref = f"evidence-{index}"
        evidence_ref_by_key[row["originalKey"]] = evidence_ref
        evidence.append({
            "evidenceRef": evidence_ref,
            "timestamp": entry["timestamp"],
            "requestId": extract_request_id(entry),
            "username": entry.get("user"),
            "severity": entry.get("level"),
            "source": row["source"],
            "eventCategory": row["eventCategory"],
            "matchedAliases": row["matchedAliases"],
            "raw": entry.get("raw", ""),
            "message": entry.get("message", ""),
            "eventType": (entry.get("leadApiMetadata") or {}).get("eventType"),
            "payloadOmitted": bool((entry.get("leadApiMetadata") or {}).get("payloadOmitted")),
            "apiOperation": (entry.get("leadApiMetadata") or {}).get("operation"),
            "httpMethod": (entry.get("leadApiMetadata") or {}).get("httpMethod"),
            "endpointPath": (entry.get("leadApiMetadata") or {}).get("endpointPath"),
            "httpStatus": (entry.get("leadApiMetadata") or {}).get("httpStatus"),
            "durationMs": (entry.get("leadApiMetadata") or {}).get("durationMs"),
            "errorCode": (entry.get("leadApiMetadata") or {}).get("errorCode"),
        })

    request_timelines = []
    for request_id in request_ids:
        entries = []
        original_keys = []
        for entry in timeline_lines:
            if request_entry_matches(entry, request_id):
                original_keys.append(_entry_key(entry))
                redacted_entry = redact_lead_entry(entry, lead_id)
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
        if timeline["request"].get("uri"):
            timeline["request"]["uri"] = redact_lead_evidence_text(
                timeline["request"]["uri"],
                lead_id,
            )
        for event, entry, original_key in zip(timeline["events"], entries, original_keys):
            event["evidenceRef"] = evidence_ref_by_key.get(original_key)
            event["correlationAliases"] = sorted(
                aliases_by_request_id.get(extract_request_id(entry), set())
            )
            event["eventCategory"] = classify_lead_event(entry)
            api_metadata = entry.get("leadApiMetadata")
            if api_metadata:
                event["eventType"] = api_metadata["eventType"]
                event.update(api_metadata)
        request_timelines.append(timeline)

    aliases_observed = sorted({
        alias for item in candidate_events for alias in item["aliases"]
    })
    result = {
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
            "discoveredRequestIds": selection_stats["discoveredRequestIds"],
            "eligibleRequestIds": selection_stats["eligibleRequestIds"],
            "routineAccessRequestIdsOmitted": selection_stats["routineAccessRequestIdsOmitted"],
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
    finished = time.perf_counter()
    result["timingsMs"] = {
        "lokiDiscovery": round((discovery_finished - total_started) * 1000, 2),
        "requestCorrelation": round((correlation_finished - discovery_finished) * 1000, 2),
        "preprocessing": round((finished - correlation_finished) * 1000, 2),
        "total": round((finished - total_started) * 1000, 2),
    }
    return result


def build_lead_ai_context(investigation: dict) -> tuple[str, set[str], bool]:
    evidence = []
    allowed_refs = set()
    omitted_refs = []
    for item in investigation["evidence"]:
        allowed_refs.add(item["evidenceRef"])
        if item.get("payloadOmitted"):
            message = json.dumps({
                key: item.get(key)
                for key in (
                    "eventType", "apiOperation", "httpMethod", "endpointPath",
                    "httpStatus", "durationMs", "errorCode", "payloadOmitted",
                )
                if item.get(key) is not None
            }, ensure_ascii=True, separators=(",", ":"))
        else:
            message = redact_lead_evidence_text(
                item["message"],
                policy=EXTERNAL_AI,
            )
        if message == "[UNSAFE_PAYLOAD_OMITTED]":
            message = ""
            omitted_refs.append(item["evidenceRef"])
        evidence.append({
            "evidenceRef": item["evidenceRef"],
            "timestamp": item["timestamp"],
            "hasRequestId": bool(item["requestId"]),
            "hasUsername": bool(item["username"]),
            "severity": item["severity"],
            "source": item["source"],
            "eventCategory": item["eventCategory"],
            "matchedAliases": item["matchedAliases"],
            "message": message,
        })
    safe_context = {
        "environment": investigation["environment"],
        "searchedDays": investigation["searchedDays"],
        "identifierCorrelation": investigation["retrieval"]["identifierCorrelation"],
        "evidence": evidence,
        "limitations": investigation["limitations"] + (
            ["Raw payload omitted from AI context because it could not be safely sanitized: "
             + ", ".join(omitted_refs)]
            if omitted_refs else []
        ),
    }
    context = json.dumps(safe_context, ensure_ascii=True, separators=(",", ":"))
    maximum_chars = max(1, config.LEAD_AI_MAX_CONTEXT_CHARS)
    truncated = len(context) > maximum_chars
    if len(context) > maximum_chars:
        for item in evidence:
            if len(item["message"]) > 200:
                item["message"] = item["message"][:200] + "...[TRUNCATED]"
        safe_context["evidence"] = evidence
        context = json.dumps(safe_context, ensure_ascii=True, separators=(",", ":"))
    while len(context) > maximum_chars and evidence:
        evidence.pop()
        truncated = True
        safe_context["evidence"] = evidence
        context = json.dumps(safe_context, ensure_ascii=True, separators=(",", ":"))
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
