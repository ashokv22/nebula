import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Header, HTTPException, Query

from core.config import (
    ANALYSIS_CACHE,
    LOKI_URL,
    selector_for_environment,
)
from core.security import EMAIL_DOMAIN, authorize_request_investigation, redact_request_entry
from lens.analyzer import build_analysis_context, call_groq
from lens.loki import loki_query
from lens.parser import request_entry_matches
from lens.schemas import AnalysisResponse, AnalyzeRequest
from lens.service import (
    build_request_investigation,
    build_user_activity,
    enrich_recent_errors,
    normalize_username,
)

router = APIRouter()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_request(
    body: AnalyzeRequest,
    access_token: Annotated[str | None, Header(alias="X-Request-Investigation-Token")] = None,
    environment: Annotated[Literal["uat", "prod"], Query(alias="env")] = "uat",
):
    if body.request_id is not None and body.text is not None:
        raise HTTPException(status_code=400, detail="Provide either requestId or text, not both")
    if body.request_id is None and (body.text is None or not body.text.strip()):
        raise HTTPException(status_code=400, detail="Provide a non-empty requestId or text")
    if not os.getenv("API_TOKEN"):
        raise HTTPException(status_code=503, detail="AI analysis is unavailable: API_TOKEN is not configured")

    investigation = None
    request_id = body.request_id
    if request_id is not None:
        investigation = await request_timeline(
            request_id, body.minutes, 1000,
            access_token=access_token, environment=environment,
        )
        if not investigation.get("count"):
            raise HTTPException(status_code=404, detail=f"No logs found for requestId {request_id}")
    context, valid_indices = build_analysis_context(body.text, investigation)
    fingerprint = hashlib.sha256(context.encode("utf-8")).hexdigest()
    cache_key = (request_id, fingerprint) if request_id is not None else None
    if cache_key is not None and not body.force_refresh and cache_key in ANALYSIS_CACHE:
        return ANALYSIS_CACHE[cache_key]
    result = await call_groq(context, valid_indices, body.text is not None)
    if cache_key is not None:
        if cache_key not in ANALYSIS_CACHE and len(ANALYSIS_CACHE) >= 256:
            ANALYSIS_CACHE.pop(next(iter(ANALYSIS_CACHE)))
        ANALYSIS_CACHE[cache_key] = result
    return result


@router.get("/health")
async def health(environment: Annotated[Literal["uat", "prod"], Query(alias="env")] = "uat"):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{LOKI_URL}/ready")
            response.raise_for_status()
        return {"status": "ok", "loki": "ready", "environment": environment}
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Loki unavailable; check SSH tunnel")


@router.get("/requests/{request_id}")
async def request_timeline(
    request_id: str,
    minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    access_token: Annotated[str | None, Header(alias="X-Request-Investigation-Token")] = None,
    environment: Annotated[Literal["uat", "prod"], Query(alias="env")] = "uat",
):
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,64}", request_id):
        raise HTTPException(status_code=400, detail="Invalid request ID")
    authorize_request_investigation(access_token)
    # Match MDC field rather than arbitrary message occurrences.
    query = selector_for_environment(environment) + f' |= "[{request_id},"'
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=minutes)
    loki_entries = await loki_query(query, minutes, limit, window_end=window_end)
    entries = [redact_request_entry(e) for e in loki_entries
               if request_entry_matches(e, request_id)]
    starts = [e for e in entries if "REQ START |" in e["message"]]
    ends = [e for e in entries if "REQ END |" in e["message"]]
    structured = build_request_investigation(
        request_id, entries, minutes, limit, window_start, window_end, len(loki_entries)
    )
    return {"request_id": request_id, "environment": environment, "count": len(entries),
            "truncated_possible": len(loki_entries) >= limit,
            "start": starts[0] if starts else None,
            "end": ends[-1] if ends else None,
            "errors": [e for e in entries if e["level"] == "ERROR"],
            "timeline": entries, **structured}


@router.get("/users/{user}/activity")
async def user_activity(
    user: str,
    minutes: Annotated[int, Query(ge=1, le=1440)] = 15,
    limit: Annotated[int, Query(ge=1, le=5000)] = 100,
    environment: Annotated[Literal["uat", "prod"], Query(alias="env")] = "uat",
):
    normalized_username = normalize_username(user)
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username must not be empty")
    mdc_pattern = (rf"(?i)\[[^,\]]+,\s*{re.escape(normalized_username)}"
                   rf"({re.escape(EMAIL_DOMAIN)})?\s*\]")
    query = selector_for_environment(environment) + " |~ " + json.dumps(mdc_pattern)
    entries = await loki_query(query, minutes, limit)
    return build_user_activity(entries, normalized_username, limit, environment)


@router.get("/errors/recent")
async def recent_errors(
    minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    exclude_anonymous: Annotated[bool, Query(alias="excludeAnonymous")] = False,
    exclude_auth: Annotated[bool, Query(alias="excludeAuth")] = False,
    user: str | None = None,
    exception: str | None = None,
    environment: Annotated[Literal["uat", "prod"], Query(alias="env")] = "uat",
):
    selector = selector_for_environment(environment)
    entries = await loki_query(selector + ' |= "ERROR"', minutes, limit)
    errors = [e for e in entries if e["level"] == "ERROR"]
    request_ids = list(dict.fromkeys(e["request_id"] for e in errors if e["request_id"]))
    related_entries = []
    if request_ids:
        request_pattern = r"\[(" + "|".join(re.escape(request_id) for request_id in request_ids) + r"),"
        related_entries = await loki_query(
            selector + " |~ " + json.dumps(request_pattern), minutes, limit
        )
    enriched = enrich_recent_errors(errors, related_entries, minutes)
    normalized_filter_user = normalize_username(user) if user else None
    normalized_filter_exception = exception.strip().casefold() if exception else None
    if normalized_filter_user:
        enriched = [error for error in enriched if error["user"] == normalized_filter_user]
    if normalized_filter_exception:
        enriched = [error for error in enriched if error["exception"] and
                    (error["exception"].casefold() == normalized_filter_exception or
                     error["exception"].rsplit(".", 1)[-1].casefold() == normalized_filter_exception)]
    if exclude_anonymous:
        enriched = [error for error in enriched if error["user"] is not None]
    if exclude_auth:
        enriched = [error for error in enriched if error["category"] != "authentication"]
    truncated_possible = len(entries) >= limit or len(related_entries) >= limit
    enriched.reverse()
    return {"environment": environment, "count": len(enriched),
            "truncated_possible": truncated_possible,
            "count_is_exact": not truncated_possible, "errors": enriched}