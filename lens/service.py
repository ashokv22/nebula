import re
from collections import Counter
from datetime import datetime
from typing import Literal
from urllib.parse import quote

from core.security import EMAIL_DOMAIN, redact_sensitive_text
from lens.parser import (
    parse_request_fields,
    request_event,
    request_marker_metadata,
    _timestamp_key,
)


def normalize_username(username: str) -> str:
    normalized = username.strip().casefold()
    if normalized.endswith(EMAIL_DOMAIN):
        normalized = normalized[:-len(EMAIL_DOMAIN)]
    return normalized


def is_anonymous_username(username: str | None) -> bool:
    return not username or normalize_username(username) in {
        "anonymous", "anonymoususer", "anonymous_user", "anonymous-user", "unknown", "n/a"
    }


def classify_error(entry: dict, request_url: str | None) -> str:
    logger = (entry.get("logger") or "").casefold()
    exception = (entry.get("exception") or "").casefold()
    endpoint = (request_url or "").casefold()
    auth_logger = re.search(r"auth|security|identity|credential", logger)
    auth_exception = re.search(
        r"authentication|authorization|accessdenied|badcredentials|credential|"
        r"invalidtoken|jwt|oauth|tokenexpired|usernamenotfound|accountlocked|accountdisabled",
        exception,
    )
    auth_endpoint = re.search(
        r"/(?:auth|login|logout|oauth|token|session|sso|signin|signout)(?:/|\?|$)", endpoint
    )
    return "authentication" if auth_logger or auth_exception or auth_endpoint else "application"


def enrich_recent_errors(errors: list[dict], related_entries: list[dict], minutes: int) -> list[dict]:
    related_by_id = {}
    for entry in related_entries:
        if entry["request_id"]:
            related_by_id.setdefault(entry["request_id"], []).append(entry)
    enriched = []
    for error in errors:
        request_id = error["request_id"]
        related = related_by_id.get(request_id, [])
        user = None if is_anonymous_username(error["user"]) else normalize_username(error["user"])
        if user is None:
            correlated_users = {normalize_username(entry["user"]) for entry in related
                                if not is_anonymous_username(entry["user"])}
            if len(correlated_users) == 1:
                user = correlated_users.pop()
        request_url = None
        request_events = sorted(related, key=lambda entry: entry["timestamp"])
        for marker in ("START", "END"):
            for event in request_events:
                fields = parse_request_fields(event, marker)
                if fields and fields["uri"]:
                    request_url = fields["uri"]
                    break
            if request_url:
                break
        if user:
            activity_url = f"/users/{quote(user, safe='')}/activity?minutes={minutes}"
        elif request_id:
            activity_url = f"/requests/{quote(request_id, safe='')}"
        else:
            activity_url = None
        item = dict(error)
        item.update({"user": user, "requestId": request_id,
                     "category": classify_error(error, request_url),
                     "requestUrl": request_url, "activityUrl": activity_url})
        enriched.append(item)
    return enriched


def build_user_activity(entries: list[dict], username: str, limit: int,
                        environment: Literal["uat", "prod"] = "uat") -> dict:
    normalized_username = normalize_username(username)
    matching = [entry for entry in entries
                if entry["user"] and normalize_username(entry["user"]) == normalized_username]
    matching.sort(key=lambda entry: _timestamp_key(entry["timestamp"]))
    grouped = {}
    for entry in matching:
        request_id = entry["request_id"]
        if request_id:
            grouped.setdefault(request_id, []).append(entry)
    requests = []
    endpoint_counts = Counter()
    durations = []
    failed_requests = 0
    completed_requests = 0
    for request_id, request_entries in grouped.items():
        starts = [(entry, parse_request_fields(entry, "START")) for entry in request_entries]
        starts = [(entry, fields) for entry, fields in starts if fields is not None]
        ends = [(entry, parse_request_fields(entry, "END")) for entry in request_entries]
        ends = [(entry, fields) for entry, fields in ends if fields is not None]
        start_entry, start_fields = starts[0] if starts else (None, {})
        end_entry, end_fields = ends[-1] if ends else (None, {})
        errors = [entry for entry in request_entries
                  if entry["level"] == "ERROR" or entry["exception"]]
        timestamp = (start_entry or end_entry or request_entries[0])["timestamp"]
        method = start_fields.get("method") or end_fields.get("method")
        uri = start_fields.get("uri") or end_fields.get("uri")
        status = end_fields.get("status")
        duration = end_fields.get("durationMs")
        completed = end_entry is not None
        failed = bool(errors) or (status is not None and status >= 400)
        requests.append({"requestId": request_id, "timestamp": timestamp, "method": method,
                         "uri": uri, "status": status, "durationMs": duration,
                         "hasError": bool(errors), "errorCount": len(errors)})
        if completed:
            completed_requests += 1
        if failed:
            failed_requests += 1
        if duration is not None:
            durations.append(duration)
        if uri:
            endpoint_counts[(method, uri)] += 1
    requests.sort(key=lambda request: _timestamp_key(request["timestamp"]))
    top_endpoints = [{"method": method, "uri": uri, "count": count}
                     for (method, uri), count in sorted(
                         endpoint_counts.items(),
                         key=lambda item: (-item[1], item[0][1], item[0][0] or ""),
                     )[:10]]
    return {
        "username": normalized_username,
        "environment": environment,
        "truncated_possible": len(entries) >= limit,
        "summary_is_exact": len(entries) < limit,
        "requests": requests,
        "summary": {
            "totalRequests": len(requests),
            "completedRequests": completed_requests,
            "failedRequests": failed_requests,
            "averageDurationMs": round(sum(durations) / len(durations), 2) if durations else None,
            "topEndpoints": top_endpoints,
        },
    }


def build_request_investigation(request_id: str, entries: list[dict], minutes: int,
                                limit: int, window_start: datetime,
                                window_end: datetime, loki_entry_count: int) -> dict:
    starts = [(entry, request_marker_metadata(entry, "START")) for entry in entries
              if parse_request_fields(entry, "START") is not None]
    ends = [(entry, request_marker_metadata(entry, "END")) for entry in entries
            if parse_request_fields(entry, "END") is not None]
    start_entry, start_fields = starts[0] if starts else (None, {})
    end_entry, end_fields = ends[-1] if ends else (None, {})
    users = [entry["user"].strip() for entry in entries
             if entry["user"] and not is_anonymous_username(entry["user"])]
    user = None
    if start_entry and start_entry["user"] and not is_anonymous_username(start_entry["user"]):
        user = start_entry["user"].strip()
    elif len(set(users)) == 1:
        user = users[0]
    events = []
    exceptions = []
    for index, entry in enumerate(entries, 1):
        event, exception = request_event(entry, request_id, index)
        events.append(event)
        if exception:
            exceptions.append(exception)
    request = {
        "requestId": request_id,
        "user": user,
        "method": start_fields.get("method") or end_fields.get("method"),
        "uri": redact_sensitive_text(start_fields.get("uri") or end_fields.get("uri")) if (start_fields.get("uri") or end_fields.get("uri")) else None,
        "startedAt": start_entry["timestamp"] if start_entry else None,
        "endedAt": end_entry["timestamp"] if end_entry else None,
        "status": end_fields.get("status"),
        "durationMs": end_fields.get("durationMs"),
        "platform": start_fields.get("platform") or end_fields.get("platform"),
        "appVersion": start_fields.get("appVersion") or end_fields.get("appVersion"),
        "clientOs": start_fields.get("clientOs") or end_fields.get("clientOs"),
    }
    truncated = loki_entry_count >= limit
    return {
        "request": request,
        "events": events,
        "exceptions": exceptions,
        "query": {
            "windowStart": window_start.isoformat(),
            "windowEnd": window_end.isoformat(),
            "minutes": minutes,
            "returnedEntries": len(entries),
            "truncatedPossible": truncated,
        },
    }