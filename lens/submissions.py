import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from core.config import selector_for_environment
from lens.loki import loki_query

SAVE_LOAN_MARKER = "[FeignKeilodofinClient#saveLoan]"
LOKI_RESULT_LIMIT = 5000
SUBMISSION_ID = re.compile(r"(?P<timestamp>\d{1,20})-(?P<hash>[a-f0-9]{64})")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _timestamp_microseconds(timestamp: str) -> int:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = parsed.astimezone(timezone.utc) - EPOCH
    return ((delta.days * 86400 + delta.seconds) * 1_000_000) + delta.microseconds


def _contains_lead_id(value: object, lead_id: str) -> bool:
    if isinstance(value, dict):
        return any(
            (key == "partnerLoanId" and str(item) == lead_id)
            or _contains_lead_id(item, lead_id)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_lead_id(item, lead_id) for item in value)
    return False


def _matching_payload(message: str, lead_id: str) -> str | None:
    marker_offset = message.find(SAVE_LOAN_MARKER)
    if marker_offset < 0:
        return None

    content = message[marker_offset + len(SAVE_LOAN_MARKER):]
    decoder = json.JSONDecoder()
    for index, character in enumerate(content):
        if character != "{":
            continue
        try:
            payload, end = decoder.raw_decode(content, index)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and _contains_lead_id(payload, lead_id):
            return content[index:end]
    return None


def _submission(entry: dict, lead_id: str) -> dict | None:
    payload = _matching_payload(entry.get("message", ""), lead_id)
    if payload is None:
        return None
    payload_bytes = payload.encode("utf-8")
    timestamp = entry["timestamp"]
    timestamp_us = _timestamp_microseconds(timestamp)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    return {
        "submission_id": f"{timestamp_us}-{payload_hash}",
        "timestamp": timestamp,
        "payload_size": len(payload_bytes),
        "payload": payload,
    }


def _loki_query(lead_id: str, environment: str) -> str:
    return (
        selector_for_environment(environment)
        + " |= "
        + json.dumps(SAVE_LOAN_MARKER)
        + " |= "
        + json.dumps(lead_id)
    )


async def list_submissions(lead_id: str, days: int, environment: str) -> dict:
    window_end = datetime.now(timezone.utc)
    entries = await loki_query(
        _loki_query(lead_id, environment),
        days * 24 * 60,
        LOKI_RESULT_LIMIT,
        window_end=window_end,
    )
    submissions = {}
    for entry in entries:
        submission = _submission(entry, lead_id)
        if submission is not None:
            submissions[submission["submission_id"]] = submission

    ordered = sorted(
        submissions.values(),
        key=lambda item: (_timestamp_microseconds(item["timestamp"]), item["submission_id"]),
        reverse=True,
    )
    return {
        "lead_id": lead_id,
        "environment": environment,
        "count": len(ordered),
        "truncated_possible": len(entries) >= LOKI_RESULT_LIMIT,
        "submissions": [
            {
                "submission_id": item["submission_id"],
                "timestamp": item["timestamp"],
                "payload_size": item["payload_size"],
            }
            for item in ordered
        ],
    }


async def get_submission(lead_id: str, submission_id: str, environment: str) -> dict:
    match = SUBMISSION_ID.fullmatch(submission_id)
    if match is None:
        raise HTTPException(status_code=400, detail="Invalid submission ID")

    timestamp_us = int(match.group("timestamp"))
    try:
        timestamp = EPOCH + timedelta(microseconds=timestamp_us)
    except OverflowError as exc:
        raise HTTPException(status_code=400, detail="Invalid submission ID") from exc
    window_start = timestamp - timedelta(seconds=2)
    window_end = timestamp + timedelta(seconds=2)

    entries = await loki_query(
        _loki_query(lead_id, environment),
        1,
        LOKI_RESULT_LIMIT,
        window_start=window_start,
        window_end=window_end,
    )
    if len(entries) >= LOKI_RESULT_LIMIT:
        raise HTTPException(
            status_code=502,
            detail="Loki result limit reached while retrieving submission",
        )
    for entry in entries:
        submission = _submission(entry, lead_id)
        if submission is not None and submission["submission_id"] == submission_id:
            return submission
    raise HTTPException(status_code=404, detail="Submission not found")
